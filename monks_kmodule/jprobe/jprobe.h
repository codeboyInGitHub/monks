#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#include "../utils.h"
#include "../netlink.h"
#include "../../common/mem_ops.h"

int jprobe_init(void);
void jprobe_exit(void);
