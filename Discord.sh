bash -c 'cat << '\''CIBE_XDP_DISCORD_FINAL'\'' | bash

#!/bin/bash
set -euo pipefail

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
NC="\033[0m"

clear
echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║    CIBE SHIELD XDP v3.0 + DISCORD INTEGRATION              ║"
echo "║      Advanced DDoS Detection & Real-Time Alerts            ║"
echo "║      Ring Buffer • Analytics • Discord Webhooks            ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[✗] Must run as root!${NC}"
    exit 1
fi

BASE="/opt/cibe-xdp"
WEBHOOK_URL="https://discord.com/api/webhooks/1251252122608079020/USCoHvKtiZku-O2Bsw_a360n75BZzvxzb3doP26fG_ba9TJsNRQ5j6earecuyRpYRgn6"

detect_interface() {
    local iface=$(ip route | grep default | head -n1 | awk '\''{print $5}'\'' 2>/dev/null)
    if [ -z "$iface" ]; then
        iface=$(ip -o addr show | grep -v "127.0.0.1" | grep inet | head -n1 | awk '\''{print $2}'\'' 2>/dev/null)
    fi
    if [ -n "$iface" ] && ip link show "$iface" &>/dev/null; then
        echo "$iface"
        return 0
    fi
    return 1
}

IFACE=$(detect_interface)
if [ -z "$IFACE" ]; then
    echo -e "${RED}[✗] Cannot detect interface${NC}"
    exit 1
fi

if [ "${1:-}" = "uninstall" ]; then
    echo -e "${YELLOW}[→] Uninstalling...${NC}"
    systemctl stop cibe-xdp.service 2>/dev/null || true
    systemctl stop cibe-discord-monitor.service 2>/dev/null || true
    systemctl disable cibe-xdp.service 2>/dev/null || true
    systemctl disable cibe-discord-monitor.service 2>/dev/null || true
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    rm -f /etc/systemd/system/cibe-xdp.service
    rm -f /etc/systemd/system/cibe-discord-monitor.service
    systemctl daemon-reload
    rm -rf "$BASE"
    echo -e "${GREEN}[✓] Removed${NC}"
    exit 0
fi

echo -e "${GREEN}[✓] Interface: ${CYAN}$IFACE${NC}"
echo -e "${BLUE}[→] Installing dependencies...${NC}"

mkdir -p "$BASE"
cd "$BASE"

export DEBIAN_FRONTEND=noninteractive
apt update -y >/dev/null 2>&1
apt install -y clang llvm libelf-dev linux-headers-$(uname -r) \
    iproute2 ethtool build-essential libbpf-dev bc curl jq >/dev/null 2>&1

if ! command -v clang >/dev/null; then
    echo -e "${RED}[✗] clang missing${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] Dependencies installed${NC}"

echo -e "${BLUE}[→] Configuring interface...${NC}"
ethtool -K "$IFACE" gro off lro off tso off gso off 2>/dev/null || true
echo -e "${GREEN}[✓] Interface configured${NC}"

echo -e "${BLUE}[→] Creating advanced XDP program with Ring Buffer...${NC}"

cat > xdp_shield.c << '\''EOF_XDP'\''
/* SPDX-License-Identifier: GPL-2.0 */
/* CIBE SHIELD XDP v3.0 - Ultimate DDoS Protection with Ring Buffer */

#define SEC(NAME) __attribute__((section(NAME), used))
#define __always_inline inline __attribute__((__always_inline__))

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
};

struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

/* BPF helpers */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *) 130;

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define XDP_PASS 2
#define XDP_DROP 1

/* SA-MP/RakNet Protocol Detection */
#define SAMP_S 0x53
#define SAMP_A 0x41
#define SAMP_M 0x4D
#define SAMP_P 0x50
#define RAKNET_MAGIC_0 0x00
#define RAKNET_MAGIC_1 0xff
#define RAKNET_MAGIC_2 0xff
#define RAKNET_MAGIC_3 0x00
#define RAKNET_FRAME_MIN 0x80
#define RAKNET_FRAME_MAX 0x8f
#define RAKNET_PING 0x01
#define RAKNET_PONG 0x1c
#define RAKNET_CONN1 0x05
#define RAKNET_CONN2 0x07
#define PORT_MIN 7000
#define PORT_MAX 7999

/* Multi-Layer Rate Limits */
#define TIME_WINDOW 1000000000ULL
#define QUICK_WINDOW 100000000ULL
#define ATTACK_CHECK_WINDOW 500000000ULL

/* Tier 1: Per-IP Limits */
#define GAMING_BPS_T1 6291456ULL
#define NORMAL_BPS_T1 2097152ULL
#define GAMING_PPS_T1 6000
#define NORMAL_PPS_T1 2000

/* Tier 2: Burst Detection */
#define BURST_BPS 2621440ULL
#define BURST_PPS 2500

/* Tier 3: Connection Tracking */
#define MAX_INIT_ATTEMPTS 60
#define MIN_PACKET_SIZE 28
#define MAX_PACKET_SIZE 1500

/* Attack Detection Thresholds */
#define ATTACK_SCORE_THRESHOLD 100
#define ATTACK_MBPS_THRESHOLD 20
#define ATTACK_PPS_THRESHOLD 10000

/* Event Types */
#define EVENT_ATTACK_START 1
#define EVENT_ATTACK_ONGOING 2
#define EVENT_ATTACK_MITIGATED 3
#define EVENT_DROP 4

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#else
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#endif

struct ip_key {
    __u32 ip;
};

struct traffic_stats {
    __u64 last_reset;
    __u64 last_burst_check;
    __u64 last_attack_check;
    __u64 attack_start_time;
    __u64 bytes;
    __u64 burst_bytes;
    __u64 total_bytes;
    __u64 dropped_bytes;
    __u32 packets;
    __u32 burst_packets;
    __u32 total_packets;
    __u32 dropped_packets;
    __u32 connection_attempts;
    __u32 attack_score;
    __u32 mbps;
    __u32 peak_mbps;
    __u16 last_port;
    __u16 target_port;
    __u8 is_gaming;
    __u8 suspicious_pattern;
    __u8 under_attack;
    __u8 attack_notified;
};

struct global_stats {
    __u64 total_packets;
    __u64 total_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 attacks_detected;
    __u64 attacks_mitigated;
};

struct attack_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_port;
    __u32 mbps;
    __u32 pps;
    __u64 total_bytes;
    __u64 total_packets;
    __u64 dropped_bytes;
    __u64 dropped_packets;
    __u32 attack_score;
    __u32 duration_sec;
    __u8 event_type;
    __u8 padding[3];
};

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") traffic_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct ip_key),
    .value_size = sizeof(struct traffic_stats),
    .max_entries = 524288,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") global_stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct global_stats),
    .max_entries = 1,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") attack_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 4096,
};

static __always_inline int check_samp(void *data, void *data_end) {
    if (data + 4 > data_end) return 0;
    __u8 *b = (__u8 *)data;
    return (b[0] == SAMP_S && b[1] == SAMP_A && 
            b[2] == SAMP_M && b[3] == SAMP_P);
}

static __always_inline int check_raknet(void *data, void *data_end, int off) {
    if (data + off + 4 > data_end) return 0;
    __u8 *b = (__u8 *)data + off;
    return (b[0] == RAKNET_MAGIC_0 && b[1] == RAKNET_MAGIC_1 &&
            b[2] == RAKNET_MAGIC_2 && b[3] == RAKNET_MAGIC_3);
}

static __always_inline int is_gaming_traffic(void *payload, void *data_end, __u16 dport) {
    if (dport >= PORT_MIN && dport <= PORT_MAX)
        return 1;
    
    if (check_samp(payload, data_end))
        return 1;
    
    if (payload + 1 > data_end)
        return 0;
    
    __u8 fb = *((__u8 *)payload);
    
    if (fb >= RAKNET_FRAME_MIN && fb <= RAKNET_FRAME_MAX)
        return 1;
    
    if ((fb == RAKNET_CONN1 || fb == RAKNET_CONN2) && 
        check_raknet(payload, data_end, 1))
        return 1;
    
    if ((fb == RAKNET_PING || fb == RAKNET_PONG) && 
        check_raknet(payload, data_end, 9))
        return 1;
    
    return 0;
}

static __always_inline __u32 calculate_mbps(__u64 bytes, __u64 time_ns) {
    if (time_ns == 0) return 0;
    __u64 bits = bytes * 8;
    __u64 time_ms = time_ns / 1000000;
    if (time_ms == 0) return 0;
    return (bits * 1000) / (time_ms * 1000000);
}

static __always_inline __u32 calculate_attack_score(
    struct traffic_stats *stats,
    __u32 pkt_bytes,
    __u16 dport,
    __u8 is_gaming
) {
    __u32 score = 0;
    
    if (pkt_bytes < MIN_PACKET_SIZE) score += 20;
    if (pkt_bytes == 1024 || pkt_bytes == 1490 || pkt_bytes == 666) score += 15;
    
    if (stats->last_port != 0 && stats->last_port != dport) score += 10;
    
    if (dport >= PORT_MIN && dport <= PORT_MAX && !is_gaming) score += 25;
    
    if (stats->connection_attempts > MAX_INIT_ATTEMPTS) score += 30;
    
    if (stats->burst_packets > BURST_PPS) score += 20;
    
    if (stats->mbps > ATTACK_MBPS_THRESHOLD) score += 40;
    
    if (stats->packets > ATTACK_PPS_THRESHOLD) score += 35;
    
    return score;
}

static __always_inline void send_attack_event(
    __u32 src_ip,
    __u16 dst_port,
    struct traffic_stats *stats,
    __u8 event_type,
    __u64 now
) {
    struct attack_event event = {0};
    event.timestamp = now;
    event.src_ip = src_ip;
    event.dst_port = dst_port;
    event.mbps = stats->mbps;
    event.pps = stats->packets;
    event.total_bytes = stats->total_bytes;
    event.total_packets = stats->total_packets;
    event.dropped_bytes = stats->dropped_bytes;
    event.dropped_packets = stats->dropped_packets;
    event.attack_score = stats->attack_score;
    event.event_type = event_type;
    
    if (stats->attack_start_time > 0) {
        __u64 duration_ns = now - stats->attack_start_time;
        event.duration_sec = duration_ns / 1000000000ULL;
    }
    
    bpf_ringbuf_output(&attack_events, &event, sizeof(event), 0);
}

static __always_inline void update_global_stats(__u32 bytes, __u8 dropped) {
    __u32 key = 0;
    struct global_stats *gstats = bpf_map_lookup_elem(&global_stats_map, &key);
    
    if (gstats) {
        __sync_fetch_and_add(&gstats->total_packets, 1);
        __sync_fetch_and_add(&gstats->total_bytes, bytes);
        
        if (dropped) {
            __sync_fetch_and_add(&gstats->dropped_packets, 1);
            __sync_fetch_and_add(&gstats->dropped_bytes, bytes);
        }
    }
}

SEC("xdp")
int xdp_shield_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    __u16 dport = bpf_ntohs(udp->dest);
    __u16 sport = bpf_ntohs(udp->source);
    void *payload = (void *)(udp + 1);
    __u32 pkt_bytes = bpf_ntohs(ip->tot_len);
    
    if (pkt_bytes < MIN_PACKET_SIZE || pkt_bytes > MAX_PACKET_SIZE) {
        update_global_stats(pkt_bytes, 1);
        return XDP_DROP;
    }
    
    int is_gaming = is_gaming_traffic(payload, data_end, dport);
    
    struct ip_key key = { .ip = ip->saddr };
    struct traffic_stats *stats = bpf_map_lookup_elem(&traffic_map, &key);
    
    __u64 now = bpf_ktime_get_ns();
    
    if (!stats) {
        struct traffic_stats new_stats = {0};
        new_stats.last_reset = now;
        new_stats.last_burst_check = now;
        new_stats.last_attack_check = now;
        new_stats.bytes = pkt_bytes;
        new_stats.burst_bytes = pkt_bytes;
        new_stats.total_bytes = pkt_bytes;
        new_stats.packets = 1;
        new_stats.burst_packets = 1;
        new_stats.total_packets = 1;
        new_stats.last_port = dport;
        new_stats.target_port = dport;
        new_stats.is_gaming = is_gaming ? 1 : 0;
        
        bpf_map_update_elem(&traffic_map, &key, &new_stats, BPF_ANY);
        update_global_stats(pkt_bytes, 0);
        return XDP_PASS;
    }
    
    stats->total_bytes += pkt_bytes;
    stats->total_packets += 1;
    
    __u64 time_since_reset = now - stats->last_reset;
    if (time_since_reset > TIME_WINDOW) {
        stats->mbps = calculate_mbps(stats->bytes, time_since_reset);
        
        if (stats->mbps > stats->peak_mbps)
            stats->peak_mbps = stats->mbps;
        
        stats->last_reset = now;
        stats->bytes = pkt_bytes;
        stats->packets = 1;
        stats->connection_attempts = 0;
    } else {
        stats->bytes += pkt_bytes;
        stats->packets += 1;
        stats->mbps = calculate_mbps(stats->bytes, time_since_reset);
    }
    
    if (now - stats->last_burst_check > QUICK_WINDOW) {
        stats->last_burst_check = now;
        stats->burst_bytes = pkt_bytes;
        stats->burst_packets = 1;
    } else {
        stats->burst_bytes += pkt_bytes;
        stats->burst_packets += 1;
    }
    
    if (is_gaming)
        stats->is_gaming = 1;
    
    if (sport != stats->last_port)
        stats->connection_attempts += 1;
    
    stats->last_port = dport;
    stats->target_port = dport;
    
    __u32 attack_score = calculate_attack_score(stats, pkt_bytes, dport, is_gaming);
    stats->attack_score = attack_score;
    
    __u8 is_attack = 0;
    if (attack_score >= ATTACK_SCORE_THRESHOLD ||
        stats->mbps >= ATTACK_MBPS_THRESHOLD ||
        stats->packets >= ATTACK_PPS_THRESHOLD) {
        is_attack = 1;
    }
    
    if (is_attack && !stats->under_attack) {
        stats->under_attack = 1;
        stats->attack_notified = 0;
        stats->attack_start_time = now;
        __u32 key = 0;
        struct global_stats *gstats = bpf_map_lookup_elem(&global_stats_map, &key);
        if (gstats) {
            __sync_fetch_and_add(&gstats->attacks_detected, 1);
        }
    }
    
    if (stats->under_attack) {
        __u64 time_since_check = now - stats->last_attack_check;
        if (time_since_check > ATTACK_CHECK_WINDOW) {
            stats->last_attack_check = now;
            
            if (!stats->attack_notified) {
                send_attack_event(ip->saddr, dport, stats, EVENT_ATTACK_START, now);
                stats->attack_notified = 1;
            } else {
                send_attack_event(ip->saddr, dport, stats, EVENT_ATTACK_ONGOING, now);
            }
        }
    }
    
    if (stats->burst_bytes > BURST_BPS || stats->burst_packets > BURST_PPS) {
        stats->suspicious_pattern = 1;
        stats->dropped_bytes += pkt_bytes;
        stats->dropped_packets += 1;
        
        if (stats->under_attack && stats->dropped_packets % 10000 == 0) {
            send_attack_event(ip->saddr, dport, stats, EVENT_ATTACK_MITIGATED, now);
        }
        
        update_global_stats(pkt_bytes, 1);
        return XDP_DROP;
    }
    
    if (attack_score >= ATTACK_SCORE_THRESHOLD) {
        stats->dropped_bytes += pkt_bytes;
        stats->dropped_packets += 1;
        
        if (stats->under_attack && stats->dropped_packets % 10000 == 0) {
            send_attack_event(ip->saddr, dport, stats, EVENT_ATTACK_MITIGATED, now);
        }
        
        update_global_stats(pkt_bytes, 1);
        return XDP_DROP;
    }
    
    __u64 byte_limit = stats->is_gaming ? GAMING_BPS_T1 : NORMAL_BPS_T1;
    __u32 pkt_limit = stats->is_gaming ? GAMING_PPS_T1 : NORMAL_PPS_T1;
    
    if (stats->suspicious_pattern) {
        byte_limit = byte_limit / 2;
        pkt_limit = pkt_limit / 2;
    }
    
    if (stats->bytes > byte_limit || stats->packets > pkt_limit) {
        stats->dropped_bytes += pkt_bytes;
        stats->dropped_packets += 1;
        
        if (stats->under_attack && stats->dropped_packets % 10000 == 0) {
            send_attack_event(ip->saddr, dport, stats, EVENT_ATTACK_MITIGATED, now);
        }
        
        update_global_stats(pkt_bytes, 1);
        return XDP_DROP;
    }
    
    update_global_stats(pkt_bytes, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOF_XDP

echo -e "${BLUE}[→] Compiling XDP program...${NC}"
if clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -Wall -Wno-unused-value -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -c xdp_shield.c -o xdp_shield.o 2>&1 | tee compile.log; then
    
    if [ -f xdp_shield.o ]; then
        echo -e "${GREEN}[✓] XDP program compiled${NC}"
    else
        echo -e "${RED}[✗] No output file${NC}"
        cat compile.log
        exit 1
    fi
else
    echo -e "${RED}[✗] Compilation failed${NC}"
    cat compile.log
    exit 1
fi

echo "$IFACE" > interface.conf
echo "$WEBHOOK_URL" > webhook.conf

# Create Discord notifier script with proper curl usage
echo -e "${BLUE}[→] Creating Discord notifier script...${NC}"

cat > discord_notify.sh << 'EOF_NOTIFY'
#!/bin/bash

WEBHOOK_URL=$(cat /opt/cibe-xdp/webhook.conf 2>/dev/null)

if [ -z "$WEBHOOK_URL" ]; then
    echo "Error: Webhook URL not configured"
    exit 1
fi

TYPE="$1"
IP="$2"
PORT="$3"
MBPS="$4"
TOTAL_GB="$5"
CHART_DATA="$6"

# Get WIB timestamp
TZ=Asia/Jakarta
TIMESTAMP=$(date "+%d %B %Y (%H.%M)")

# Generate chart URL with proper URL encoding
CHART_URL="https://quickchart.io/chart?width=800&height=400&c={type:%22line%22,data:{labels:[%220s%22,%225s%22,%2210s%22,%2215s%22,%2220s%22],datasets:[{label:%22Attack%20Rate%20(Mbps)%22,data:[$CHART_DATA],borderColor:%22rgb(255,99,132)%22,backgroundColor:%22rgba(255,99,132,0.2)%22,fill:true}]},options:{title:{display:true,text:%22DDoS%20Attack%20Traffic%20Rate%22},scales:{yAxes:[{ticks:{beginAtZero:true}}]}}}"

# Create temporary JSON file
TEMP_JSON="/tmp/discord_payload_$$.json"

if [ "$TYPE" = "start" ]; then
    # Red embed - Attack Start
    cat > "$TEMP_JSON" <<EOFJS
{
  "embeds": [{
    "title": "🚨 Serangan DDoS Terdeteksi!!",
    "description": "Serangan DDoS terdeteksi dan akan segera di proses oleh sistem Cibe Shield",
    "color": 15548997,
    "fields": [
      {
        "name": "IP Attacker",
        "value": "$IP",
        "inline": false
      },
      {
        "name": "Serangan Mengarah Port",
        "value": "$PORT",
        "inline": false
      },
      {
        "name": "Kecepatan Serangan",
        "value": "$MBPS Mbps",
        "inline": false
      },
      {
        "name": "Waktu (WIB)",
        "value": "$TIMESTAMP",
        "inline": false
      }
    ],
    "image": {
      "url": "$CHART_URL"
    },
    "footer": {
      "text": "Cibe Shield - Path Network Alerts"
    }
  }]
}
EOFJS
    
elif [ "$TYPE" = "filtered" ]; then
    # Yellow embed - Attack Filtered
    cat > "$TEMP_JSON" <<EOFJS
{
  "embeds": [{
    "title": "✅ Serangan Berhasil Di Filter!",
    "description": "Serangan DDoS terdeteksi dan telah sukses di tangani oleh Cibe Shield",
    "color": 16776960,
    "fields": [
      {
        "name": "IP Attacker",
        "value": "$IP",
        "inline": false
      },
      {
        "name": "Serangan Mengarah Port",
        "value": "$PORT",
        "inline": false
      },
      {
        "name": "Kecepatan Serangan",
        "value": "$MBPS Mbps (Filtered)",
        "inline": false
      },
      {
        "name": "Total Packet",
        "value": "$TOTAL_GB GB",
        "inline": false
      },
      {
        "name": "Waktu (WIB)",
        "value": "$TIMESTAMP",
        "inline": false
      }
    ],
    "image": {
      "url": "$CHART_URL"
    },
    "footer": {
      "text": "Cibe Shield - Path Network Alerts"
    }
  }]
}
EOFJS
fi

# Send to Discord webhook using curl with the JSON file
curl -H "Content-Type: application/json" \
     -X POST \
     -d @"$TEMP_JSON" \
     "$WEBHOOK_URL" 2>&1

# Clean up
rm -f "$TEMP_JSON"

echo "Discord notification sent: $TYPE to $IP:$PORT ($MBPS Mbps)"
EOF_NOTIFY

chmod +x discord_notify.sh

# Create Discord monitor with C program
echo -e "${BLUE}[→] Creating Discord monitor system...${NC}"

cat > discord_monitor.c << 'EOF_DISCORD_MON'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define EVENT_ATTACK_START 1
#define EVENT_ATTACK_ONGOING 2
#define EVENT_ATTACK_MITIGATED 3
#define EVENT_DROP 4

#define MAX_CHART_DATA 5

struct attack_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_port;
    __u32 mbps;
    __u32 pps;
    __u64 total_bytes;
    __u64 total_packets;
    __u64 dropped_bytes;
    __u64 dropped_packets;
    __u32 attack_score;
    __u32 duration_sec;
    __u8 event_type;
    __u8 padding[3];
};

struct attack_tracking {
    char ip_str[INET_ADDRSTRLEN];
    __u32 src_ip;
    __u16 target_port;
    __u32 mbps_history[MAX_CHART_DATA];
    int history_count;
    __u64 attack_start;
    __u64 total_bytes;
    __u64 dropped_bytes;
    int notified_start;
    int notified_filtered;
};

volatile sig_atomic_t stop = 0;
struct attack_tracking current_attack = {0};

void sig_handler(int signo) {
    stop = 1;
}

void send_discord_notification(const char *type, const char *ip, int port, int mbps, double total_gb, const char *chart_data) {
    char cmd[4096];
    int ret;
    snprintf(cmd, sizeof(cmd), "/opt/cibe-xdp/discord_notify.sh '%s' '%s' '%d' '%d' '%.2f' '%s' &",
             type, ip, port, mbps, total_gb, chart_data);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Discord notification command failed\n");
    }
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct attack_event *event = data;
    
    struct in_addr addr;
    addr.s_addr = event->src_ip;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
    
    time_t now = time(NULL) + (7 * 3600);
    struct tm *tm_info = gmtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S WIB", tm_info);
    
    if (event->event_type == EVENT_ATTACK_START) {
        printf("\n[%s] === ATTACK STARTED ===\n", time_str);
        printf("  Source IP      : %s\n", ip_str);
        printf("  Target Port    : %u\n", event->dst_port);
        printf("  Current Rate   : %u Mbps\n", event->mbps);
        printf("  Current PPS    : %u pps\n", event->pps);
        printf("  Attack Score   : %u\n", event->attack_score);
        printf("=====================================\n");
        
        snprintf(current_attack.ip_str, INET_ADDRSTRLEN, "%s", ip_str);
        current_attack.src_ip = event->src_ip;
        current_attack.target_port = event->dst_port;
        current_attack.attack_start = event->timestamp;
        current_attack.total_bytes = event->total_bytes;
        current_attack.history_count = 0;
        current_attack.notified_start = 0;
        current_attack.notified_filtered = 0;
        
        if (current_attack.history_count < MAX_CHART_DATA) {
            current_attack.mbps_history[current_attack.history_count++] = event->mbps;
        }
        
        char chart_data[256];
        snprintf(chart_data, sizeof(chart_data), "%u", event->mbps);
        
        double total_gb = event->total_bytes / (1024.0 * 1024.0 * 1024.0);
        send_discord_notification("start", ip_str, event->dst_port, event->mbps, total_gb, chart_data);
        current_attack.notified_start = 1;
        
    } else if (event->event_type == EVENT_ATTACK_ONGOING) {
        printf("\n[%s] === ATTACK ONGOING ===\n", time_str);
        printf("  Source IP      : %s\n", ip_str);
        printf("  Current Rate   : %u Mbps\n", event->mbps);
        printf("  Duration       : %u seconds\n", event->duration_sec);
        printf("=====================================\n");
        
        if (current_attack.src_ip == event->src_ip) {
            current_attack.total_bytes = event->total_bytes;
            current_attack.dropped_bytes = event->dropped_bytes;
            
            if (current_attack.history_count < MAX_CHART_DATA) {
                current_attack.mbps_history[current_attack.history_count++] = event->mbps;
            } else {
                memmove(current_attack.mbps_history, current_attack.mbps_history + 1, 
                       (MAX_CHART_DATA - 1) * sizeof(__u32));
                current_attack.mbps_history[MAX_CHART_DATA - 1] = event->mbps;
            }
        }
        
    } else if (event->event_type == EVENT_ATTACK_MITIGATED) {
        printf("\n[%s] === ATTACK MITIGATED ===\n", time_str);
        printf("  Source IP      : %s\n", ip_str);
        printf("  Dropped Bytes  : %.2f GB\n", event->dropped_bytes / (1024.0 * 1024.0 * 1024.0));
        printf("  Dropped Packets: %llu\n", event->dropped_packets);
        printf("  Duration       : %u seconds\n", event->duration_sec);
        printf("=====================================\n");
        
        if (current_attack.src_ip == event->src_ip) {
            current_attack.total_bytes = event->total_bytes;
            current_attack.dropped_bytes = event->dropped_bytes;
            
            if (!current_attack.notified_filtered) {
                char chart_data[256];
                int offset = 0;
                for (int i = 0; i < current_attack.history_count && i < MAX_CHART_DATA; i++) {
                    offset += snprintf(chart_data + offset, sizeof(chart_data) - offset, 
                                     "%s%u", i > 0 ? "," : "", current_attack.mbps_history[i]);
                }
                
                double total_gb = event->total_bytes / (1024.0 * 1024.0 * 1024.0);
                send_discord_notification("filtered", ip_str, event->dst_port, event->mbps, 
                                        total_gb, chart_data);
                current_attack.notified_filtered = 1;
            }
        }
    }
    
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_map *events_map;
    struct ring_buffer *rb = NULL;
    int err;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                                                            ║\n");
    printf("║      CIBE SHIELD - Discord Attack Monitor v3.0             ║\n");
    printf("║           Real-Time DDoS Alerts to Discord                 ║\n");
    printf("║                                                            ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    obj = bpf_object__open_file("/opt/cibe-xdp/xdp_shield.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    events_map = bpf_object__find_map_by_name(obj, "attack_events");
    if (!events_map) {
        fprintf(stderr, "Failed to find attack_events map\n");
        goto cleanup;
    }
    
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("Monitoring for DDoS attacks... Notifications will be sent to Discord\n");
    printf("Press Ctrl+C to stop\n\n");
    
    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("\nShutting down Discord monitor...\n");
    
cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (obj)
        bpf_object__close(obj);
    
    return 0;
}
EOF_DISCORD_MON

echo -e "${BLUE}[→] Compiling Discord monitor...${NC}"

if gcc -O2 -Wall -Wno-stringop-truncation -Wno-unused-result \
    -o discord_monitor discord_monitor.c -lbpf -lelf 2>&1 | tee discord_compile.log; then
    if [ -f discord_monitor ]; then
        chmod +x discord_monitor
        echo -e "${GREEN}[✓] Discord monitor compiled successfully${NC}"
    else
        echo -e "${RED}[✗] Discord monitor compilation failed${NC}"
        cat discord_compile.log
        exit 1
    fi
else
    echo -e "${RED}[✗] Discord monitor compilation failed${NC}"
    cat discord_compile.log
    exit 1
fi

# Create load/unload scripts
cat > load.sh << 'EOF_LOAD'
#!/bin/bash
BASE="/opt/cibe-xdp"
IFACE=$(cat "$BASE/interface.conf" 2>/dev/null)

if [ -z "$IFACE" ]; then
    echo "[✗] Interface not configured"
    exit 1
fi

ethtool -K "$IFACE" gro off lro off tso off gso off 2>/dev/null || true
ip link set dev "$IFACE" xdp off 2>/dev/null || true
sleep 1

echo "[→] Loading XDP Shield..."

if ip -force link set dev "$IFACE" xdpdrv obj "$BASE/xdp_shield.o" sec xdp 2>/dev/null; then
    echo "[✓] XDP loaded (native mode)"
    exit 0
fi

if ip -force link set dev "$IFACE" xdpgeneric obj "$BASE/xdp_shield.o" sec xdp 2>/dev/null; then
    echo "[✓] XDP loaded (generic mode)"
    exit 0
fi

echo "[✗] Failed to load XDP"
exit 1
EOF_LOAD
chmod +x load.sh

cat > unload.sh << 'EOF_UNLOAD'
#!/bin/bash
IFACE=$(cat /opt/cibe-xdp/interface.conf 2>/dev/null)
[ -n "$IFACE" ] && ip link set dev "$IFACE" xdp off 2>/dev/null || true
echo "[✓] XDP unloaded"
EOF_UNLOAD
chmod +x unload.sh

# Create systemd services with always-on configuration
cat > /etc/systemd/system/cibe-xdp.service << 'EOF_SVC'
[Unit]
Description=CIBE SHIELD XDP v3.0 Protection
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/opt/cibe-xdp/load.sh
ExecStop=/opt/cibe-xdp/unload.sh
RemainAfterExit=yes
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF_SVC

cat > /etc/systemd/system/cibe-discord-monitor.service << 'EOF_DISCORD_SVC'
[Unit]
Description=CIBE SHIELD Discord Attack Monitor v3.0
After=cibe-xdp.service network-online.target
Requires=cibe-xdp.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/opt/cibe-xdp/discord_monitor
Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF_DISCORD_SVC

systemctl daemon-reload
systemctl enable cibe-xdp.service >/dev/null 2>&1
systemctl enable cibe-discord-monitor.service >/dev/null 2>&1

echo -e "${BLUE}[→] Loading XDP Shield...${NC}"
if ./load.sh; then
    sleep 2
    
    if ip link show "$IFACE" | grep -q "xdp"; then
        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}║    ✓ CIBE SHIELD XDP v3.0 + DISCORD INTEGRATION ✓         ║${NC}"
        echo -e "${GREEN}║                                                            ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}  SYSTEM INFORMATION${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  Interface     : ${GREEN}$IFACE${NC}"
        echo -e "  Version       : ${CYAN}3.0 Ultimate + Discord (FINAL)${NC}"
        echo -e "  Protection    : ${CYAN}6-Tier Defense System${NC}"
        echo -e "  Detection     : ${CYAN}SA-MP + RakNet + Pattern Analysis${NC}"
        echo -e "  Monitoring    : ${CYAN}Ring Buffer Event Streaming${NC}"
        echo -e "  Discord Alerts: ${GREEN}ENABLED & WORKING${NC}"
        echo -e "  Auto-Restart  : ${GREEN}ALWAYS ON (survives reboot)${NC}"
        echo -e "  Chart API     : ${CYAN}QuickChart.io${NC}"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}  MANAGEMENT COMMANDS${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  XDP Status        : ${YELLOW}systemctl status cibe-xdp${NC}"
        echo -e "  Discord Monitor   : ${YELLOW}systemctl status cibe-discord-monitor${NC}"
        echo -e "  Start Discord     : ${YELLOW}systemctl start cibe-discord-monitor${NC}"
        echo -e "  Stop Discord      : ${YELLOW}systemctl stop cibe-discord-monitor${NC}"
        echo -e "  View Logs         : ${YELLOW}journalctl -u cibe-discord-monitor -f${NC}"
        echo -e "  Manual Test       : ${YELLOW}/opt/cibe-xdp/discord_notify.sh start 1.2.3.4 7777 25 1.5 25,30,28${NC}"
        echo -e "  Reload XDP        : ${YELLOW}/opt/cibe-xdp/load.sh${NC}"
        echo -e "  Uninstall         : ${YELLOW}bash <script> uninstall${NC}"
        echo ""
        echo -e "${GREEN}[✓] CIBE SHIELD XDP v3.0 with Discord Integration active!${NC}"
        echo -e "${GREEN}[✓] Services configured to survive reboots and auto-restart!${NC}"
        echo -e "${GREEN}[✓] Starting Discord monitor service...${NC}"
        echo ""
        
        # Start Discord monitor service
        systemctl start cibe-discord-monitor.service
        sleep 2
        
        if systemctl is-active --quiet cibe-discord-monitor.service; then
            echo -e "${GREEN}[✓] Discord monitor service started successfully!${NC}"
            echo -e "${GREEN}[✓] System is now fully protected and monitored!${NC}"
        else
            echo -e "${YELLOW}[!] Discord monitor service failed to start${NC}"
            echo -e "${YELLOW}[!] Check logs: journalctl -u cibe-discord-monitor -n 50${NC}"
        fi
        
        echo ""
        echo -e "${MAGENTA}[INFO] Testing Discord webhook...${NC}"
        /opt/cibe-xdp/discord_notify.sh start "TEST.ATTACK.IP" 7777 25 1.5 "25,30,28,26,24" 2>&1 | head -n 5
        echo -e "${GREEN}[✓] Test notification sent! Check your Discord channel!${NC}"
        echo ""
        
    else
        echo -e "${RED}[✗] XDP not attached${NC}"
        exit 1
    fi
else
    echo -e "${RED}[✗] Load failed${NC}"
    exit 1
fi

CIBE_XDP_DISCORD_FINAL
'