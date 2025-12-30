bash -c "$(cat << 'EOF'
set -euo pipefail

echo '=== CIBE SHIELD XDP CORE INSTALL (FIXED & VERIFIER SAFE) ==='

# =========================
# ROOT CHECK
# =========================
[ "$EUID" -ne 0 ] && echo '[FATAL] Run as root' && exit 1

IFACE=$(ip route get 1 2>/dev/null | awk '{print $5;exit}')
[ -z "$IFACE" ] && echo '[FATAL] Interface not found' && exit 1
echo "[INFO] Interface: $IFACE"

BASE=/opt/cibe-xdp
mkdir -p $BASE
cd $BASE

# =========================
# DEPENDENCIES
# =========================
apt update -y
apt install -y \
 clang llvm gcc make \
 libelf-dev linux-headers-$(uname -r) \
 iproute2 jq curl linux-tools-common linux-tools-generic

command -v bpftool >/dev/null || { echo '[FATAL] bpftool missing'; exit 1; }

# =========================
# MINIMAL BPF HEADERS
# =========================
cat > vmlinux.h << 'V'
#define SEC(NAME) __attribute__((section(NAME), used))
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#define __be16 __u16
#define __be32 __u32

struct xdp_md { __u32 data, data_end; };

struct ethhdr { __u8 d[6], s[6]; __be16 h_proto; };

struct iphdr {
  __u8 ihl:4, version:4;
  __u8 tos; __be16 tot_len; __be16 id;
  __be16 frag_off; __u8 ttl; __u8 protocol;
  __be16 check; __be32 saddr, daddr;
};

struct udphdr { __be16 source, dest, len, check; };

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

#define XDP_PASS 2
#define XDP_DROP 1

#define __constant_htons(x) ((__be16)__builtin_bswap16(x))
V

cat > bpf_helpers.h << 'H'
#define SEC(NAME) __attribute__((section(NAME), used))
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, unsigned long long) = (void *)2;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)5;
H

# =========================
# XDP PROGRAM (VERIFIER SAFE)
# =========================
cat > samp_xdp.c << 'C'
#include "vmlinux.h"
#include "bpf_helpers.h"

#define S0 0x53
#define S1 0x41
#define S2 0x4D
#define S3 0x50

#define MAX_PPS 3000
#define WINDOW_NS 1000000000ULL

struct key {
    __u32 ip;
};

struct val {
    __u64 ts;
    __u32 pps;
};

struct {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
} ip_rate SEC("maps") = {
    .type = 9, /* BPF_MAP_TYPE_HASH */
    .key_size = sizeof(struct key),
    .value_size = sizeof(struct val),
    .max_entries = 131072,
};

SEC("xdp")
int xdp_samp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > end)
        return XDP_PASS;

    __u8 *p = (void *)(udp + 1);
    if (p + 4 > (unsigned char *)end)
        return XDP_PASS;

    if (p[0] != S0 || p[1] != S1 || p[2] != S2 || p[3] != S3)
        return XDP_PASS;

    struct key k = {};
    k.ip = ip->saddr;

    __u64 now = bpf_ktime_get_ns();
    struct val *v = bpf_map_lookup_elem(&ip_rate, &k);

    if (!v) {
        struct val nv = {};
        nv.ts = now;
        nv.pps = 1;
        bpf_map_update_elem(&ip_rate, &k, &nv, 0);
        return XDP_PASS;
    }

    if (now - v->ts > WINDOW_NS) {
        v->ts = now;
        v->pps = 1;
        return XDP_PASS;
    }

    v->pps++;
    if (v->pps > MAX_PPS)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
C

# =========================
# COMPILE
# =========================
echo '[INFO] Compiling XDP program'
clang -O2 -target bpf -Wall -Werror -c samp_xdp.c -o samp_xdp.o

# =========================
# LOAD SCRIPT
# =========================
cat > load.sh << 'L'
#!/bin/bash
set -e
IFACE=$(ip route get 1 | awk '{print $5;exit}')
ip link set dev $IFACE xdp off 2>/dev/null || true
sleep 1
ip link set dev $IFACE xdp obj /opt/cibe-xdp/samp_xdp.o sec xdp || \
ip link set dev $IFACE xdpgeneric obj /opt/cibe-xdp/samp_xdp.o sec xdp
L
chmod +x load.sh

# =========================
# SYSTEMD SERVICE
# =========================
cat > /etc/systemd/system/cibe-xdp.service << 'S'
[Unit]
Description=CIBE SHIELD XDP CORE
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/cibe-xdp/load.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
S

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now cibe-xdp.service

echo ''
echo '=== ✅ CIBE SHIELD XDP ACTIVE ==='
echo "Interface : $IFACE"
echo "Verify    : ip link show $IFACE | grep xdp"
echo "Logs      : journalctl -u cibe-xdp.service -n 30 --no-pager"
EOF
)"
