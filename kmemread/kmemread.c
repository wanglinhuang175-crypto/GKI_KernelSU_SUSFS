// kmemread —— 内核态跨进程读内存 PoC（反 ACE 隐蔽方向）
//
// 目的：把 dfmread 的读取原语从用户态 process_vm_readv / pread(/proc/pid/mem)
// 移到内核态。消除两个游戏可感知的暴露面：
//   ① 不再 open("/proc/<游戏>/mem")  —— ACE 可枚举谁打开了它的 mem
//   ② 不再对游戏发 process_vm_readv  —— 读取不经过任何游戏可感知的用户态 syscall
//
// 机制：注册一个 misc 字符设备，用户态对它 ioctl(KMR_READ,{pid,addr,len,ubuf})，
// 内核态用 access_process_vm(task, addr, buf, len, FOLL_FORCE) 读目标进程，
// FOLL_FORCE 天然能读壳把 .bss 映射成 -w-p(只写) 的页，等价现在的 pread 回落。
//
// GKI 特有的两个坎本文件都处理了：
//   • access_process_vm / find_get_task_by_vpid 在 GKI 不 EXPORT_SYMBOL：
//     用 kprobe 落在 "kallsyms_lookup_name" 上拿它的地址，再查这两个符号。
//   • 只读小心 len 上界 + copy_to_user 失败处理，避免把一个内核 bug 变成 panic。
//
// ⚠ PoC 阶段用的是普通可见的设备名 /dev/kmemread；隐蔽化（改名/SUSFS 隐藏/
//    去掉 printk）留到可行性验证通过之后。

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#define KMR_DEV_NAME "kmemread"
#define KMR_MAX_LEN  (256 * 1024)   // 单次读上界，防止用户态传巨值把内核拖垮

// 和用户态 ktest.c / dfmread.c 共用的 ioctl 协议
struct kmr_req {
	__u32 pid;      // 目标进程 pid（vpid，调用者所在 pid namespace）
	__u32 len;      // 要读的字节数，<= KMR_MAX_LEN
	__u64 addr;     // 目标进程虚拟地址
	__u64 ubuf;     // 用户态接收缓冲区指针
};
#define KMR_READ _IOWR('k', 1, struct kmr_req)

// ---- 未导出符号：用 kprobe 拿 kallsyms_lookup_name 再查其余 ----
static unsigned long (*kln)(const char *name);

static int (*p_access_process_vm)(struct task_struct *tsk, unsigned long addr,
				  void *buf, int len, unsigned int gup_flags);
static struct task_struct *(*p_find_get_task_by_vpid)(pid_t nr);

static int resolve_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	kln = (void *)kp.addr;
	unregister_kprobe(&kp);
	return kln ? 0 : -ENOENT;
}

static int resolve_syms(void)
{
	int ret = resolve_kln();
	if (ret)
		return ret;
	p_access_process_vm =
		(void *)kln("access_process_vm");
	p_find_get_task_by_vpid =
		(void *)kln("find_get_task_by_vpid");
	if (!p_access_process_vm || !p_find_get_task_by_vpid) {
		pr_err("kmemread: symbol miss apv=%px fgt=%px\n",
		       p_access_process_vm, p_find_get_task_by_vpid);
		return -ENOENT;
	}
	return 0;
}

// ---- 读取核心 ----
static long do_read(struct kmr_req *req)
{
	struct task_struct *task;
	void *kbuf;
	long got;

	if (req->len == 0 || req->len > KMR_MAX_LEN)
		return -EINVAL;

	task = p_find_get_task_by_vpid((pid_t)req->pid);
	if (!task)
		return -ESRCH;

	kbuf = kvmalloc(req->len, GFP_KERNEL);
	if (!kbuf) {
		put_task_struct(task);
		return -ENOMEM;
	}

	// FOLL_FORCE：读壳映射成 -w-p 的只写页，等价 /proc/pid/mem 的 pread。
	got = p_access_process_vm(task, (unsigned long)req->addr,
				  kbuf, (int)req->len, FOLL_FORCE);
	put_task_struct(task);

	if (got <= 0) {
		kvfree(kbuf);
		return got < 0 ? got : -EFAULT;
	}
	if (copy_to_user((void __user *)(uintptr_t)req->ubuf, kbuf, got))
		got = -EFAULT;

	kvfree(kbuf);
	return got;   // 返回实际读取字节数
}

static long kmr_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct kmr_req req;

	if (cmd != KMR_READ)
		return -ENOTTY;
	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;
	return do_read(&req);
}

static const struct file_operations kmr_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kmr_ioctl,
	.compat_ioctl = kmr_ioctl,
};

static struct miscdevice kmr_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KMR_DEV_NAME,
	.fops = &kmr_fops,
	.mode = 0600,
};

static int __init kmr_init(void)
{
	int ret = resolve_syms();
	if (ret) {
		pr_err("kmemread: resolve_syms failed %d\n", ret);
		return ret;
	}
	ret = misc_register(&kmr_dev);
	if (ret) {
		pr_err("kmemread: misc_register failed %d\n", ret);
		return ret;
	}
	pr_info("kmemread: ready at /dev/%s (apv=%px)\n",
		KMR_DEV_NAME, p_access_process_vm);
	return 0;
}

static void __exit kmr_exit(void)
{
	misc_deregister(&kmr_dev);
	pr_info("kmemread: unloaded\n");
}

module_init(kmr_init);
module_exit(kmr_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cross-process memory read via ioctl (PoC)");
