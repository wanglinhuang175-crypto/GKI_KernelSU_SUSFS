// kmemread —— 内核态跨进程读/写内存 PoC（反 ACE 隐蔽方向）
//
// 目的：把 dfmread 的读取原语从用户态 process_vm_readv / pread(/proc/pid/mem)
// 移到内核态。消除两个游戏可感知的暴露面：
//   ① 不再 open("/proc/<游戏>/mem")  —— ACE 可枚举谁打开了它的 mem
//   ② 不再对游戏发 process_vm_readv  —— 读取不经过任何游戏可感知的用户态 syscall
//
// 2026-10-17 增加写入原语（KMR_WRITE / KMR_WRITE_FORCE / KMR_VMA），
// 用途是【检测面实验】：测 ACE 对内核态写内存是否有校验/回滚/报警，不是竞争优势。
// 阶梯：level0 写无语义堆页 → level1 写本机 mesh CTW(可写页) → level2 FOLL_FORCE 穿只读页。
//   • 非 force 写入【先查 VMA 权限】，只读段直接 -EACCES 拒绝，绝不静默硬写——
//     否则"目标只读"会被误读成"ACE 拦截"。这是单变量实验的前提。
//   • force 写入才加 FOLL_FORCE 穿 COW 页（level2），预期会被 .text 自校验发现。
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
#include <linux/mmap_lock.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/task_work.h>
#include <linux/completion.h>
#include <linux/mman.h>

#define KMR_DEV_NAME "kmemread"
#define KMR_MAX_LEN  (256 * 1024)   // 单次读/写上界，防止用户态传巨值把内核拖垮

// 和用户态 ktest.c / dfmread.c 共用的 ioctl 协议
struct kmr_req {
	__u32 pid;      // 目标进程 pid（vpid，调用者所在 pid namespace）
	__u32 len;      // 读/写字节数，<= KMR_MAX_LEN；KMR_VMA 时须 >=8
	__u64 addr;     // 目标进程虚拟地址
	__u64 ubuf;     // READ=接收缓冲区; WRITE/FORCE=源缓冲区; VMA=回写 vm_flags(u64)
};
#define KMR_READ       _IOWR('k', 1, struct kmr_req)  // 读
#define KMR_WRITE      _IOWR('k', 2, struct kmr_req)  // 写(仅限可写页, 不可写则拒绝不硬写)
#define KMR_WRITE_FORCE _IOWR('k', 3, struct kmr_req) // 写(FOLL_FORCE, 穿只读/COW页—— level2 实验用)
#define KMR_VMA        _IOWR('k', 4, struct kmr_req)  // 查 addr 所在 VMA 的 vm_flags
#define KMR_MMAP       _IOWR('k', 5, struct kmr_req)  // 在目标进程建 RWX 页(len=大小, ubuf 回写映射地址 u64)

// ---- 未导出符号：用 kprobe 拿 kallsyms_lookup_name 再查其余 ----
static unsigned long (*kln)(const char *name);

static int (*p_access_process_vm)(struct task_struct *tsk, unsigned long addr,
				  void *buf, int len, unsigned int gup_flags);
static struct task_struct *(*p_find_get_task_by_vpid)(pid_t nr);
// VMA 预检用：GKI 对这几个符号同样不 EXPORT，统一 kprobe+kln 拿地址。
static struct mm_struct *(*p_get_task_mm)(struct task_struct *task);
static void (*p_mmput)(struct mm_struct *mm);
static struct vm_area_struct *(*p_find_vma)(struct mm_struct *mm, unsigned long addr);
// KMR_MMAP 用：在目标进程上下文 vm_mmap 建 RWX 页。两个符号 GKI 同样不 EXPORT，kprobe+kln 拿。
static unsigned long (*p_vm_mmap)(struct file *file, unsigned long addr,
				  unsigned long len, unsigned long prot,
				  unsigned long flag, unsigned long offset);
static int (*p_task_work_add)(struct task_struct *task,
			      struct callback_head *work,
			      enum task_work_notify_mode notify);

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
	// VMA 预检符号：缺了不致命(退化成不预检)，但记一条日志便于排查。
	p_get_task_mm = (void *)kln("get_task_mm");
	p_mmput       = (void *)kln("mmput");
	p_find_vma    = (void *)kln("find_vma");
	if (!p_get_task_mm || !p_mmput || !p_find_vma)
		pr_warn("kmemread: vma-precheck syms miss gtm=%px mmput=%px fv=%px"
			" (写入将无法预检权限)\n",
			p_get_task_mm, p_mmput, p_find_vma);
	p_vm_mmap       = (void *)kln("vm_mmap");
	p_task_work_add = (void *)kln("task_work_add");
	if (!p_vm_mmap || !p_task_work_add)
		pr_warn("kmemread: mmap syms miss vm_mmap=%px twa=%px (KMR_MMAP 不可用)\n",
			p_vm_mmap, p_task_work_add);
	return 0;
}

// 查 addr 所在 VMA 的 vm_flags。返回 0 并把 flags 写进 *out；
// <0 = 出错；-ENODATA = 符号缺失无法预检（调用方自行决定是否继续）。
static long vma_flags(struct task_struct *task, unsigned long addr,
		      unsigned long *out)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	long ret = 0;

	if (!p_get_task_mm || !p_mmput || !p_find_vma)
		return -ENODATA;

	mm = p_get_task_mm(task);
	if (!mm)
		return -ESRCH;              // 内核线程 / 已退出，无用户地址空间

	mmap_read_lock(mm);
	vma = p_find_vma(mm, addr);
	if (!vma || addr < vma->vm_start)
		ret = -ENOMEM;              // addr 不落在任何已映射区间
	else
		*out = vma->vm_flags;
	mmap_read_unlock(mm);

	p_mmput(mm);
	return ret;
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

// ---- 写入核心 ----
// force=0：只写可写页。VMA 不带 VM_WRITE 时【直接拒绝(-EACCES)，绝不硬写】——
//          这样"目标是只读段"和"ACE 拦了写"两种情况能从 errno 区分，不会被误读。
// force=1：加 FOLL_FORCE，穿只读/COW 页（level2 实验：预期触发 COW 分裂，大概率被检测）。
static long do_write(struct kmr_req *req, int force)
{
	struct task_struct *task;
	void *kbuf;
	long wrote;
	unsigned int flags = FOLL_WRITE | (force ? FOLL_FORCE : 0);

	if (req->len == 0 || req->len > KMR_MAX_LEN)
		return -EINVAL;

	task = p_find_get_task_by_vpid((pid_t)req->pid);
	if (!task)
		return -ESRCH;

	// --- VMA 预检（仅非 force 路径）---
	if (!force) {
		unsigned long vf = 0;
		long vr = vma_flags(task, (unsigned long)req->addr, &vf);
		if (vr == -ENODATA) {
			// 预检符号缺失：保守起见直接拒绝，避免"以为在测写入其实啥也没写"。
			put_task_struct(task);
			pr_warn("kmemread: write 拒绝—无法预检 VMA 权限\n");
			return -EOPNOTSUPP;
		}
		if (vr < 0) {
			put_task_struct(task);
			return vr;              // 地址没映射 / 进程没地址空间
		}
		if (!(vf & VM_WRITE)) {
			put_task_struct(task);
			return -EACCES;         // 只读段：明确拒绝，交给调用方决定走不走 force
		}
	}

	kbuf = kvmalloc(req->len, GFP_KERNEL);
	if (!kbuf) {
		put_task_struct(task);
		return -ENOMEM;
	}
	if (copy_from_user(kbuf, (void __user *)(uintptr_t)req->ubuf, req->len)) {
		kvfree(kbuf);
		put_task_struct(task);
		return -EFAULT;
	}

	wrote = p_access_process_vm(task, (unsigned long)req->addr,
				    kbuf, (int)req->len, flags);
	put_task_struct(task);
	kvfree(kbuf);

	if (wrote <= 0)
		return wrote < 0 ? wrote : -EFAULT;
	return wrote;   // 返回实际写入字节数
}

// ---- VMA 查询：把 vm_flags(u64) 回写到用户 ubuf ----
static long do_vma(struct kmr_req *req)
{
	struct task_struct *task;
	unsigned long vf = 0;
	__u64 out;
	long vr;

	if (req->len < sizeof(__u64))
		return -EINVAL;

	task = p_find_get_task_by_vpid((pid_t)req->pid);
	if (!task)
		return -ESRCH;
	vr = vma_flags(task, (unsigned long)req->addr, &vf);
	put_task_struct(task);
	if (vr < 0)
		return vr;

	out = (__u64)vf;
	if (copy_to_user((void __user *)(uintptr_t)req->ubuf, &out, sizeof(out)))
		return -EFAULT;
	return sizeof(out);
}

// ---- 在目标进程建 RWX 页（inline-hook 的 code cave）----
// 难点：ioctl 跑在调用者(dfmread_pov)上下文, current->mm 是【调用者】的, 直接 vm_mmap
// 会建在调用者进程里, 对目标没用。用 task_work_add 把 vm_mmap 排到【目标进程】返回用户态
// 的边界执行 —— 那一刻 current==目标进程, vm_mmap 自然落在目标 mm。
struct kmr_mmap_work {
	struct callback_head cb;
	unsigned long len;
	unsigned long result;      // 成功=映射地址; 失败=IS_ERR_VALUE(-errno)
	struct completion done;
};

static void kmr_mmap_cb(struct callback_head *cb)
{
	struct kmr_mmap_work *w = container_of(cb, struct kmr_mmap_work, cb);
	// 此刻 current == 目标进程; vm_mmap 用 current->mm = 目标 mm
	w->result = p_vm_mmap(NULL, 0, w->len,
			      PROT_READ | PROT_WRITE | PROT_EXEC,
			      MAP_PRIVATE | MAP_ANONYMOUS, 0);
	complete(&w->done);
}

static long do_mmap_target(struct kmr_req *req)
{
	struct task_struct *task;
	struct kmr_mmap_work *w;
	unsigned long a;
	long ret;

	if (!p_vm_mmap || !p_task_work_add)
		return -EOPNOTSUPP;
	if (req->len == 0 || req->len > 16 * 1024 * 1024)
		return -EINVAL;

	task = p_find_get_task_by_vpid((pid_t)req->pid);
	if (!task)
		return -ESRCH;

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w) {
		put_task_struct(task);
		return -ENOMEM;
	}
	init_task_work(&w->cb, kmr_mmap_cb);
	init_completion(&w->done);
	w->len = req->len;

	ret = p_task_work_add(task, &w->cb, TWA_RESUME);
	put_task_struct(task);
	if (ret) {
		kfree(w);
		return ret;                 // 目标正在退出等, task_work 加不进去
	}

	// 等目标进程跑到用户态边界执行回调。活跃进程通常几毫秒内。
	if (!wait_for_completion_timeout(&w->done, msecs_to_jiffies(5000))) {
		// 超时: 回调可能仍会触发并访问 w, 【绝不 free】(否则 UAF→panic)。
		// PoC 阶段选择泄漏这一个 w, 换取绝对不 panic。
		pr_warn("kmemread: mmap task_work 超时(目标未返回用户态?)\n");
		return -ETIMEDOUT;
	}

	a = w->result;
	if (IS_ERR_VALUE(a)) {
		ret = (long)a;              // vm_mmap 失败(如 W^X 被 LSM 拒 -EPERM)
	} else if (copy_to_user((void __user *)(uintptr_t)req->ubuf,
				&a, sizeof(a))) {
		ret = -EFAULT;
	} else {
		ret = sizeof(a);
	}
	kfree(w);
	return ret;
}

static long kmr_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct kmr_req req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	switch (cmd) {
	case KMR_READ:        return do_read(&req);
	case KMR_WRITE:       return do_write(&req, 0);
	case KMR_WRITE_FORCE: return do_write(&req, 1);
	case KMR_VMA:         return do_vma(&req);
	case KMR_MMAP:        return do_mmap_target(&req);
	default:              return -ENOTTY;
	}
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
	pr_info("kmemread: ready at /dev/%s (apv=%px, rw+vma)\n",
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
