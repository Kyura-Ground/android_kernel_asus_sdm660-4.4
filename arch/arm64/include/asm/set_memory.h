/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 */

#ifndef _ASM_ARM64_SET_MEMORY_H
#define _ASM_ARM64_SET_MEMORY_H

#ifdef __KERNEL__

#include <linux/mm.h>

int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);
int set_memory_x(unsigned long addr, int numpages);

#endif /* __KERNEL__ */
#endif /* _ASM_ARM64_SET_MEMORY_H */
