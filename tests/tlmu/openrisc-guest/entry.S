# ----------------------------------------------------------------------------

# Example Programs for "Building a Loosely Timed SoC Model with OSCI TLM 2.0"

# Copyright (C) 2008  Embecosm Limited

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# ----------------------------------------------------------------------------

# This is a general purpose bootloader routine. It defines the _start address
# (required by the standard linker to be the reset vector, sets up the stack
# register and frame, and jumps to the _main program location. It should be
# linked at the start of all programs.

# $Id: start.s 81 2008-06-27 07:43:26Z jeremy $

#*****************************************************************************
#                                                                            *
# This program is modifyed by HdLab,inc.(http://www.hdlab.co.jp)             *
#                                                                            *
# 1. Set Address for External interrupt                                      *
#                                                                            *
#*****************************************************************************


	.file   "start.s"

	.text
.org	0x100		# The reset routine goes at 0x100
#	.org	0x18010100		# The reset routine goes at 0x100

	.global _start
_start:
    l.movhi r1,0x1901
    l.ori   r1,r1,0x7f00
#	l.addi	r1,r0,0x7f00	# Set SP to value 0x7f00
	l.addi	r2,r1,0x0	# FP and SP are the same
	l.mfspr	r3,r0,17	# Get SR value
	l.ori	r3,r3,0x10	# Set exception enable bit
	l.jal   run 		# Jump to main routine
	l.mtspr	r0,r3,17	# Enable exceptions (DELAY SLOT)

	.org	0x00000800
#	l.jal   _extIntHandler		# Jump to Interrupt Handler
	l.nop
	l.rfe
	l.nop

	.org	0x00000FFC
	l.nop			# Guarantee the exception vector space
				# does not have general purpose code

# C code starts at 0x1000
