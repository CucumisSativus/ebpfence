// file: deny_new_reads.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* -------- policy state --------
 * mode_map: key=tgid (process id), value=mode
 *   0 = off
 *   1 = learn (record allowed files)
 *   2 = enforce (deny new files)
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);
  __type(value, __u8);
} mode_map SEC(".maps");

/* allow_map: key=(tgid, dev, inode) => value=1 */
struct file_key {
  __u32 tgid;
  __u32 dev;     // simplified: minor+major packed (see note below)
  __u64 inode;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 262144);
  __type(key, struct file_key);
  __type(value, __u8);
} allow_map SEC(".maps");

/* Helper: detect read intent from f_mode (covers read opens).
 * NOTE: f_mode is a bitmask of FMODE_*.
 */
static __always_inline bool is_read_open(struct file *file)
{
  __u32 f_mode = BPF_CORE_READ(file, f_mode);
  return (f_mode & FMODE_READ) != 0;
}

/* Pack dev_t into 32 bits (good enough for an allowlist key; adjust if needed) */
static __always_inline __u32 pack_dev(dev_t dev)
{
  // Linux dev_t layout is kernel-specific; this is a pragmatic packing.
  // If you need perfect stability, consider storing major/minor separately.
  __u32 d = (__u32)dev;
  return d;
}

SEC("lsm/file_open")
int BPF_PROG(block_new_reads, struct file *file, int mask)
{
  if (!is_read_open(file))
    return 0; // only care about reads

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = pid_tgid >> 32;

  __u8 *modep = bpf_map_lookup_elem(&mode_map, &tgid);
  if (!modep || *modep == 0)
    return 0; // off by default unless configured

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  if (!inode)
    return 0;

  struct file_key k = {};
  k.tgid  = tgid;
  k.inode = BPF_CORE_READ(inode, i_ino);
  k.dev   = pack_dev(BPF_CORE_READ(inode, i_sb, s_dev));

  __u8 one = 1;

  if (*modep == 1) {
    // learn: record file identity
    bpf_map_update_elem(&allow_map, &k, &one, BPF_ANY);
    return 0;
  }

  if (*modep == 2) {
    // enforce: allow only if previously recorded
    __u8 *ok = bpf_map_lookup_elem(&allow_map, &k);
    if (!ok)
      return -EPERM;
  }

  return 0;
}
