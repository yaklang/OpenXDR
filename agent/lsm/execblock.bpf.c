// SPDX-License-Identifier: GPL-2.0-only
// 执行前按内容拒绝；与采集程序分开加载，缺少 IMA/LSM 不影响采集。
// 只声明访问的字段，Clang 生成 CO-RE relocation，加载时按目标内核 BTF 修正。
typedef unsigned int u32;
typedef unsigned long long u64;
struct file;
struct linux_binprm {
    struct file *file;
} __attribute__((preserve_access_index));

#define SEC(name) __attribute__((section(name), used))
#define UINT(name, value) int (*name)[value]
#define TYPE(name, value) value *name

// hash_algo 来自内核，digest 按最长 SHA-512 留空间，未使用的字节必须清零。
struct digest {
    u32 algorithm;
    unsigned char bytes[64];
};

struct {
    UINT(type, 1); // BPF_MAP_TYPE_HASH
    UINT(max_entries, 4096);
    TYPE(key, struct digest);
    TYPE(value, u32);
} DENIED SEC(".maps");

// [0]：启用开关。用户态先装入全部规则，再启用；没有规则时不计算哈希。
struct {
    UINT(type, 2); // BPF_MAP_TYPE_ARRAY
    UINT(max_entries, 1);
    TYPE(key, u32);
    TYPE(value, u32);
} ENABLED SEC(".maps");

// 探测完整打开后的只读 ioctl，在安装规则前确认内核实际采用的哈希及计算能力。
struct probe_result {
    struct digest digest;
    int error;
};
struct {
    UINT(type, 1);
    UINT(max_entries, 1);
    TYPE(key, u64);
    TYPE(value, struct probe_result);
} PROBE SEC(".maps");

static void *(*lookup)(void *, const void *) = (void *)1;
static u64 (*pid_tgid)(void) = (void *)14;
static long (*file_hash)(struct file *, void *, u32) = (void *)193;

SEC("lsm.s/file_ioctl")
int probe_hash(u64 *ctx)
{
    int previous = (int)ctx[3];
    if (previous)
        return previous;
    u64 tid = pid_tgid();
    struct probe_result *result = lookup(&PROBE, &tid);
    if (!result)
        return 0;
    struct digest digest = {};
    long algorithm = file_hash((struct file *)ctx[0], digest.bytes, sizeof(digest.bytes));
    result->error = algorithm < 0 ? algorithm : 0;
    digest.algorithm = algorithm < 0 ? 0 : algorithm;
    result->digest = digest;
    return 0;
}

SEC("lsm.s/bprm_check_security")
int deny_execution(u64 *ctx)
{
    int previous = (int)ctx[1];
    if (previous)
        return previous;
    u32 zero = 0;
    u32 *enabled = lookup(&ENABLED, &zero);
    if (!enabled || !*enabled)
        return 0;
    struct linux_binprm *bprm = (void *)ctx[0];
    struct digest digest = {};
    long algorithm = file_hash(bprm->file, digest.bytes, sizeof(digest.bytes));
    // 已启用时无法计算哈希不得当成未命中。用户态必须先探测并确认可解除。
    if (algorithm < 0)
        return -13; // EACCES
    digest.algorithm = algorithm;
    return lookup(&DENIED, &digest) ? -13 : 0;
}

char LICENSE[] SEC("license") = "GPL";
