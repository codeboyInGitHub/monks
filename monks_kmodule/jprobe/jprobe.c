#include "jprobe.h"

static long jdo_execve(const char *filename, const char __user *const __user *argv, 
		const char __user *const __user *envp, struct pt_regs *regs)
{
	syscall_intercept_info *i;
	i = new(sizeof(struct syscall_intercept_info));
	if(i){
			i->pname = current->comm;
			i->pid = current->pid;
			i->operation = "execve";
			i->path = kasprintf(GFP_KERNEL, "%s", filename);
			i->result = "Ok";
			i->details = kasprintf(GFP_KERNEL, "%s", argv[1] == NULL?NULL:argv[1]);

			nl_send(i);
			printk("step in jprobe\n");

			del(i->path);
			del(i->details);
			del(i);
		}else{
			//something bad happened, can't show results
		}

	jprobe_return();
	return 0;
}


static struct jprobe execve_jprobe = {
	.entry			= jdo_execve,
	.kp = {
		.symbol_name	= "do_execve",
	},
};

int jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&execve_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	return 0;
}

void jprobe_exit(void)
{
	unregister_jprobe(&execve_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", execve_jprobe.kp.addr);
}
