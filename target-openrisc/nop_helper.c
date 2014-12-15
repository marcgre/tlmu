
/*
 * OpenRISC l.nop helper define to support or1ksim like behaviour
 *
 * Copyright (c) 2014 Marc Greim <marc.greim@mytum.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 *
 *
 */



#include "sysemu/sysemu.h"
#include "cpu.h"
#include "helper.h"

// @see or1k-support.h of newlib for possible changes
#define NOP_NOP 0x0000 /* Normal nop instruction */
#define NOP_EXIT 0x0001 /* End of simulation */
#define NOP_REPORT 0x0002 /* Simple report */
/*#define NOP_PRINTF 0x0003 Simprintf instruction (obsolete)*/
#define NOP_PUTC 0x0004 /* JPB: Simputc instruction */
#define NOP_CNT_RESET 0x0005 /* Reset statistics counters */
#define NOP_GET_TICKS 0x0006 /* JPB: Get # ticks running */
#define NOP_GET_PS 0x0007 /* JPB: Get picosecs/cycle */
#define NOP_REPORT_FIRST 0x0400 /* Report with number */
#define NOP_REPORT_LAST 0x03ff /* Report with number */

void HELPER(l_nop)(CPUOpenRISCState *env, uint32_t code)
{

	// OpenRISCCPU * cpu = openrisc_env_get_cpu(env); // get cpu state

	switch (code) {
	case 1:
		qemu_system_shutdown_request(); // maybe there is a better function to exit the current cpu
		cpu_loop_exit(env);
		break;
	///TODO handle other cases
	default:
		break;
	}

}
