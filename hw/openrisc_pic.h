#ifndef OPENRISC_PIC_H
#define OPENRISC_PIC_H
#include "hw/irq.h"
qemu_irq * cpu_openrisc_pic_init(OpenRISCCPU *);
#endif
