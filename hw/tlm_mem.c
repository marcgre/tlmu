/*
 * QEMU device to interface with external SystemC simulators.
 *
 * Copyright (c) 2011 Edgar E. Iglesias.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysbus.h"
#include "qemu-char.h"
#include "qemu-timer.h"
#include "qemu-log.h"
#include "qdev-addr.h"
#include "ptimer.h"

#include "tlm.h"

#define D(x)

/* just quick hack to compile this file. FIXME */
uint64_t qemu_icount;


/* There is one of these instantiated per memory/IO area. The first one
   is the only one with valid IRQ connections, the rest are only meant to
   be used for RAM maps.  */
struct TLMMemory {
    SysBusDevice busdev;
    void *cpu_env; //actually its type is CPUArchState *;

    QEMUBH *sync_bh;
    QEMUBH *irq_bh;
    ptimer_state *sync_ptimer;
    qemu_irq *cpu_irq;

    MemoryRegion iomem;
    int is_ram;
    uint64_t base_addr;
    uint64_t size;
    uint64_t sync_period_ns;
    uint32_t pending_irq[16]; /* max 512 irqs.  */
    uint32_t nr_irq;

    struct tlmu_dmi dmi;

    void *irq_vector;
};

struct TLMRegisterRamEntry {
    const char *name;
    uint64_t base;
    uint64_t size;
    int rw;

    struct TLMMemory *mem;
    struct TLMRegisterRamEntry *next;
};

static struct TLMRegisterRamEntry *tlm_register_ram_entries = NULL;
struct TLMMemory *main_tlmdev = NULL;

void notdirty_mem_wr(hwaddr ram_addr, int len);

static void tlm_write_irq(struct tlmu_irq *qirq)
{
    assert(main_tlmdev);

    if ((qirq->addr / 4) > main_tlmdev->nr_irq) {
       /* This is a write to the vector.  */
       if (main_tlmdev->irq_vector) {
           * (uint32_t *) main_tlmdev->irq_vector = qirq->data;
       }
    }

    main_tlmdev->pending_irq[qirq->addr / 4] = qirq->data;
    qemu_bh_schedule(main_tlmdev->irq_bh);
}

int tlm_bus_access(int rw, uint64_t addr, void *data, int len)
{
    const int r = cpu_physical_memory_rw(addr, data, len, rw);
    return r;
}

void tlm_bus_access_dbg(int rw, uint64_t addr, void *data, int len)
{
    cpu_physical_memory_rw_debug(addr, data, len, rw);
}

int tlm_get_dmi_ptr(struct tlmu_dmi *dmi)
{
    hwaddr addr;
    int len;

    assert(dmi);
    addr = dmi->base;
    dmi->ptr = qemu_map_paddr_to_host(&addr, &len);
    dmi->base = addr;
    dmi->size = len;
    dmi->prot = TLMU_DMI_PROT_READ | TLMU_DMI_PROT_WRITE;
    dmi->read_latency = 0;
    dmi->write_latency = 0;
    return dmi->ptr != NULL;
}

static inline
int dmi_check_flags(struct TLMMemory *s, int flags) {
	return (s->dmi.prot & flags) == flags;
}

/*
 * Check if this particular TLMMemory needs to get it's dmi mappings
 * invalidated. If so, invalidate them.
 */
static void tlm_check_invalidate_dmi(struct TLMMemory *s,
                                     uint64_t start, uint64_t end)
{
    if (start > s->base_addr && start < (s->base_addr + s->size)) {
        s->dmi.ptr = NULL;
        s->dmi.prot = 0;
    }
}

/*
 * Walk the list of TLMMemory areas and if needed, invalidate their dmi
 * mappings.
 */
static void tlm_invalidate_dmi(struct tlmu_dmi *dmi)
{
    struct TLMRegisterRamEntry *ram;
    struct TLMMemory *s;
    uint64_t start, end;

    start = dmi->base;
    end = dmi->base + dmi->size;

    ram = tlm_register_ram_entries;
    while (ram) {
	s = ram->mem;
        tlm_check_invalidate_dmi(s, start, end);
        ram = ram->next;
    }

    /* Also check the main dev.  */
    tlm_check_invalidate_dmi(main_tlmdev, start, end);
}

static void tlm_try_dmi(struct TLMMemory *s, uint64_t addr, int len)
{
    if (tlm_get_dmi_ptr_cb) {
        tlm_get_dmi_ptr_cb(tlm_opaque, addr, &s->dmi);
        /* If we got a readable aligned ptr, make it a fast one!  */
        if (s->dmi.ptr && (s->dmi.prot & TLMU_DMI_PROT_READ)) {
            intptr_t p = (intptr_t) s->dmi.ptr;
            if (s->dmi.base == s->base_addr
                && s->dmi.size == s->size
                && (p & 0x3) == 0) {
                s->dmi.prot |= TLMU_DMI_PROT_FAST;
            }
        }
    }
}

static
int dmi_is_allowed(struct TLMMemory *s, int flags, uint64_t addr, int len)
{
    if (s->dmi.ptr && s->dmi.prot & flags) {
        if (addr >= s->dmi.base
            && (addr + len - 1) <= (s->dmi.base + s->dmi.size)) {
            return 1;
        }
    }
    return 0;
}

static inline uint64_t tlm_dbg_read(void *opaque, hwaddr addr, unsigned int len){
    struct TLMMemory *const s = opaque;
    const uint64_t eaddr = s->base_addr + addr;
    uint64_t r = 0;
    const int64_t clk = qemu_get_clock_ns(vm_clock);
    D(printf("tlm_dbg_read(%p, %08llX, %d)\n", opaque, (long long)eaddr, len));
    tlm_bus_access_dbg_cb(tlm_opaque, clk, 0, eaddr, &r, len);
    return r;
}

static inline void tlm_dbg_write(void *opaque, hwaddr addr, uint64_t value, unsigned int len){
    struct TLMMemory *const s = opaque;
    const uint64_t eaddr = s->base_addr + addr;
    const int64_t clk = qemu_get_clock_ns(vm_clock);
    D(printf("tlm_dbg_write(%p, %08llX, %08llX, %d)\n", opaque, (long long)eaddr, (long long)value, len));
    tlm_bus_access_dbg_cb(tlm_opaque, clk, 1, eaddr, &value, len);
}

static inline
uint64_t tlm_read(void *opaque, hwaddr addr, unsigned int len)
{
    struct TLMMemory *const s = opaque;
    uint64_t r = 0;
    const uint64_t eaddr = s->base_addr + addr;
    int64_t clk;
    int dmi_supported;

//    qemu_log("%s: addr=%lx,%lx.%lx len=%d\n", __func__, s->base_addr, eaddr, (unsigned long) addr, len);

    D(printf("tlm_read(%p, %08llX, %d)\n", opaque, (long long)eaddr, len));
    if (dmi_is_allowed(s, TLMU_DMI_PROT_READ, eaddr, len)) {
        int offset;
        char *p = s->dmi.ptr;

        offset = eaddr - s->dmi.base;
        p += offset;
        memcpy(&r, p, len);
        qemu_icount += s->dmi.read_latency;
        if (!s->is_ram) {
            clk = qemu_get_clock_ns(vm_clock);
            tlm_sync(tlm_opaque, clk);
        }
        return r;
    }

    clk = qemu_get_clock_ns(vm_clock);
    dmi_supported = tlm_bus_access_cb(tlm_opaque, clk, 0, eaddr, &r, len);
    if (dmi_supported && !s->dmi.prot) {
        tlm_try_dmi(s, eaddr, len);
    }

    D(qemu_log("%s: addr=%lx r=%x len=%d)\n", __func__, eaddr, r, len));
    return r;
}

static inline void
tlm_write(void *opaque, hwaddr addr, uint64_t value, unsigned int len)
{
    struct TLMMemory *const s = opaque;
    uint64_t eaddr = s->base_addr + addr;
    int64_t clk;
    int dmi_supported;

    D(printf("tlm_write(%p, %08llX, %08llX, %d)\n", opaque, (long long)eaddr, (long long)value, len));

    if (s->is_ram) {
        //notdirty_mem_wr(eaddr, len); //FIXME just to compile
    }
//    qemu_log("%s: addr=%lx.%lx value=%x len=%d\n", __func__, eaddr, (unsigned long) addr, value, len);

    if (dmi_is_allowed(s, TLMU_DMI_PROT_WRITE, eaddr, len)) {
        int offset;
        char *p = s->dmi.ptr;

        offset = eaddr - s->dmi.base;
        p += offset;
        memcpy(p, &value, len);
        qemu_icount += s->dmi.write_latency;
        if (!s->is_ram) {
            clk = qemu_get_clock_ns(vm_clock);
            tlm_sync(tlm_opaque, clk);
        }
        return;
    }

    clk = qemu_get_clock_ns(vm_clock);
    dmi_supported = tlm_bus_access_cb(tlm_opaque, clk, 1, eaddr, &value, len);
    if (dmi_supported && !s->dmi.prot) {
        tlm_try_dmi(s, eaddr, len);
    }
}
static const MemoryRegionOps tlm_mem_ops[2] = {
    {
        .read = tlm_read,
        .write = tlm_write,
        .endianness = DEVICE_NATIVE_ENDIAN
    },
    {
        .read = tlm_dbg_read,
        .write = tlm_dbg_write,
        .endianness = DEVICE_NATIVE_ENDIAN
    }
};


static inline uint64_t tlm_read_via_entry(void *opaque, hwaddr addr, unsigned int len)
{
    struct TLMRegisterRamEntry *const ram = opaque;
    const uint64_t rd = tlm_read(ram->mem, addr, len);;
    D(printf("tlm_read_via_entry(%p, %08llX, %d) = %llX\n", opaque, (long long)addr, len, (long long)rd));
    return rd;
}
static inline void tlm_write_via_entry(void *opaque, hwaddr addr, uint64_t value, unsigned int len)
{
    struct TLMRegisterRamEntry *const ram = opaque;
    D(printf("tlm_write_via_entry(%p, %08llX, %08llX, %d)\n", opaque, (long long)addr, (long long)value, len));
    tlm_write(ram->mem, addr, value, len);
}


static inline uint64_t tlm_dbg_read_via_entry(void *opaque, hwaddr addr, unsigned int len)
{
    struct TLMRegisterRamEntry *const ram = opaque;
    const uint64_t rd = tlm_dbg_read(ram->mem, addr, len);;
    D(printf("tlm_dbg_read_via_entry(%p, %08llX, %d) = %llX\n", opaque, (long long)addr, len, (long long)rd));
    return rd;
}
static inline void tlm_dbg_write_via_entry(void *opaque, hwaddr addr, uint64_t value, unsigned int len)
{
    struct TLMRegisterRamEntry *const ram = opaque;
    D(printf("tlm_dbg_write_via_entry(%p, %08llX, %08llX, %d)\n", opaque, (long long)addr, (long long)value, len));
    tlm_dbg_write(ram->mem, addr, value, len);
}



static const MemoryRegionOps tlm_mem_entry_ops[2] = {
    {
        .read = tlm_read_via_entry,
        .write = tlm_write_via_entry,
        .endianness = DEVICE_NATIVE_ENDIAN
    },
    {
        .read = tlm_dbg_read_via_entry,
        .write = tlm_dbg_write_via_entry,
        .endianness = DEVICE_NATIVE_ENDIAN
    }
};




static void update_irq(void *opaque)
{
    struct TLMMemory *s = opaque;
    int i;

    for (i = 0; i < s->nr_irq; i++) {
        int regnr = i / 32;
        int bitnr = i & 0x1f;
        uint32_t data;
        int level;

        data = s->pending_irq[regnr];
        level = !!(data & (1 << bitnr));
        qemu_set_irq(s->cpu_irq[i], level);
    }
}

static void timer_hit(void *opaque)
{
    struct TLMMemory *s = opaque;
    cpu_interrupt(s->cpu_env, CPU_INTERRUPT_EXITTB);
}

void tlm_notify_event(enum tlmu_event ev, void *d)
{
    CPUArchState *env;

    assert(main_tlmdev);
    env = main_tlmdev->cpu_env;

    switch (ev) {
        case TLMU_TLM_EVENT_SYNC:
            qemu_notify_event();
            break;
        case TLMU_TLM_EVENT_WAKE:
            env->halted = 0;
            cpu_reset_interrupt(env, CPU_INTERRUPT_HALT);
            break;
        case TLMU_TLM_EVENT_SLEEP:
            cpu_interrupt(env, CPU_INTERRUPT_HALT);
            break;
        case TLMU_TLM_EVENT_IRQ:
            tlm_write_irq(d);
            break;
        case TLMU_TLM_EVENT_INVALIDATE_DMI:
            tlm_invalidate_dmi(d);
            break;
        default:
            break;
    }
}

static int tlm_memory_init(SysBusDevice *dev)
{
    struct TLMMemory *const s = FROM_SYSBUS(typeof(*s), dev);
    int i;

    if (s->nr_irq) {
        if (s->nr_irq > (sizeof (s->pending_irq) * 8)) {
            printf("%s: Failed: to many irqs %d!\n", __func__, s->nr_irq);
            return 1;
        }
        s->cpu_irq = g_malloc0(s->nr_irq * sizeof (*s->cpu_irq));
        for (i = 0; i < s->nr_irq; i++) {
            sysbus_init_irq(dev, &s->cpu_irq[i]);
        }
    }

    s->irq_bh = qemu_bh_new(update_irq, s);
    s->sync_bh = qemu_bh_new(timer_hit, s);
    s->sync_ptimer = ptimer_init(s->sync_bh);
    if (s->sync_period_ns) {
        ptimer_set_period(s->sync_ptimer, s->sync_period_ns / 10);
        ptimer_set_limit(s->sync_ptimer, 10, 1);
        ptimer_run(s->sync_ptimer, 0);
    }

    memory_region_init_io(&s->iomem, tlm_mem_ops, s, "tlm_memory", s->size);
    sysbus_init_mmio(dev, &s->iomem);

    /* Register the main tlm dev.  Used for interrupts.  */
    main_tlmdev = s;
    printf("tlm_memory_init() called %p\n", main_tlmdev);
    return 0;
}

static Property tlm_mem_props[] = {
    DEFINE_PROP_UINT64("base_addr", struct TLMMemory, base_addr, 0),
    DEFINE_PROP_UINT64("size", struct TLMMemory, size, 0),
    DEFINE_PROP_PTR("cpu_env", struct TLMMemory, cpu_env),
    DEFINE_PROP_UINT64("sync_period_ns", struct TLMMemory, sync_period_ns, 0),
    DEFINE_PROP_UINT32("nr_irq", struct TLMMemory, nr_irq, 0),
    DEFINE_PROP_PTR("irq_vector", struct TLMMemory, irq_vector),
    DEFINE_PROP_END_OF_LIST(),
};

static void tlm_memory_class_init(ObjectClass *klass, void *data){
    DeviceClass *const dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *const k = SYS_BUS_DEVICE_CLASS(klass);
    k->init = tlm_memory_init;
    dc->props = tlm_mem_props;
}


static void tlm_memory_register_type(void){
    static const TypeInfo tlm_memory_type_info = {
        .name = "tlm,memory",
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(struct TLMMemory),
        .class_init = tlm_memory_class_init,
    };
    type_register_static(&tlm_memory_type_info);
}

type_init(tlm_memory_register_type)


static void map_ram(struct TLMRegisterRamEntry *ram)
{
    printf("map_ram(%p:%s) base:0x%08X size:0x%08X called\n", ram, ram->name, (unsigned)ram->base, (unsigned)ram->size);
    tlm_try_dmi(ram->mem, ram->base, ram->size);
    if(ram->mem->dmi.ptr){
        printf("DMI is OK\n");
        memory_region_init_ram_ptr(&ram->mem->iomem, ram->name, ram->size, ram->mem->dmi.ptr);
        vmstate_register_ram_global(&ram->mem->iomem);
        memory_region_add_subregion(&main_tlmdev->iomem, ram->base, &ram->mem->iomem);
        memory_region_set_readonly(&ram->mem->iomem, ram->rw ? false : true);
    }
    else{
        memory_region_init_ram(&ram->mem->iomem, ram->name, ram->size);
        ram->mem->iomem.ops = tlm_mem_entry_ops;
        ram->mem->iomem.opaque = ram;
        vmstate_register_ram_global(&ram->mem->iomem);
        memory_region_add_subregion(&main_tlmdev->iomem, ram->base, &ram->mem->iomem);
        memory_region_set_readonly(&ram->mem->iomem, ram->rw ? false : true);
    }
}

void tlm_map_ram(const char *name, uint64_t addr, uint64_t size, int rw)
{
    struct TLMRegisterRamEntry *ram;

    ram = g_malloc0(sizeof *ram);
    ram->name = g_strdup(name);
    ram->base = addr;
    ram->size = size;
    ram->rw = rw;

    ram->mem = g_malloc0(sizeof *ram->mem);
    ram->mem->is_ram = rw;
    ram->mem->base_addr = addr;
    ram->mem->size = size;

    /* Insert.  */
    ram->next = tlm_register_ram_entries;
    tlm_register_ram_entries = ram;
}

void tlm_register_rams(void)
{
    struct TLMRegisterRamEntry *ram;

    ram = tlm_register_ram_entries;
    while (ram) {
        map_ram(ram);
        ram = ram->next;
    }
}
