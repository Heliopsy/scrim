// SPDX-License-Identifier: AGPL-3.0-only
//
// eBPF cgroup interception (specs/interception "Transparent mode with eBPF").
//
// Attached to the control groups scrim covers, these programs do what the
// nftables rules of the transparent mode do, per control group:
//
//   connect4/connect6  TCP connections to port 80 or 443 of any address
//                      that is not loopback are rewritten to scrim's
//                      transparent listener on 127.0.0.1 or ::1, which
//                      routes them by TLS server name or Host header. A
//                      datagram socket connecting to port 443 (QUIC) is
//                      refused.
//   sendmsg4/sendmsg6  an unconnected datagram sent to port 443 is refused.
//   egress             a second, independent check on the packets
//                      themselves: any TCP packet to port 80 or 443, or UDP
//                      packet to port 443, that leaves for an address that
//                      is not loopback is dropped. Nothing the connect hooks
//                      redirected matches it; it catches whatever reached
//                      the wire some other way.
//
// Loopback destinations (127.0.0.0/8, ::1, the unspecified address and
// their IPv4-mapped forms) are never touched, so local listeners, scrim's
// own listeners and the DNS override keep working.
//
// No libbpf headers: the context structures below are the stable UAPI
// layouts from include/uapi/linux/bpf.h, and the only helper is
// bpf_skb_load_bytes, which is not GPL-only.
//
// Regenerate the committed objects with `just ebpf` after changing this
// file; `just ebpf-check` fails when they are stale.

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define IPPROTO_HOPOPTS 0
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_DSTOPTS 60

#define ALLOW 1
#define DENY 0

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16(x) __builtin_bswap16(x)
#define be32(x) __builtin_bswap32(x)
#else
#define be16(x) (x)
#define be32(x) (x)
#endif

// struct bpf_sock_addr (include/uapi/linux/bpf.h). Addresses and ports are
// in network byte order; user_port holds the port in its low 16 bits.
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
};

// struct __sk_buff is only passed through to bpf_skb_load_bytes.
struct __sk_buff;

static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;

// redirect_port is the transparent listener's port, set by the loader.
volatile const __u16 redirect_port = 9792;

static __always_inline int loopback4(__u32 ip_be)
{
	__u32 ip = be32(ip_be);
	return (ip >> 24) == 127 || ip == 0;
}

// loopback6 is ::1, ::, and the IPv4-mapped forms of loopback4.
static __always_inline int loopback6(__u32 a, __u32 b, __u32 c, __u32 d)
{
	if (a != 0 || b != 0)
		return 0;
	if (c == 0)
		return d == 0 || d == be32(1);
	if (c == be32(0x0000ffff))
		return loopback4(d);
	return 0;
}

static __always_inline int mapped4(__u32 a, __u32 b, __u32 c)
{
	return a == 0 && b == 0 && c == be32(0x0000ffff);
}

static __always_inline int http_port(__u16 port)
{
	return port == 80 || port == 443;
}

SEC("cgroup/connect4")
int scrim_connect4(struct bpf_sock_addr *ctx)
{
	__u32 ip = ctx->user_ip4;
	__u16 port = be16((__u16)ctx->user_port);

	if (loopback4(ip))
		return ALLOW;
	if (ctx->type != SOCK_STREAM)
		return port == 443 ? DENY : ALLOW;
	if (!http_port(port))
		return ALLOW;
	ctx->user_ip4 = be32(0x7f000001);
	ctx->user_port = be16(redirect_port);
	return ALLOW;
}

SEC("cgroup/connect6")
int scrim_connect6(struct bpf_sock_addr *ctx)
{
	__u32 a = ctx->user_ip6[0];
	__u32 b = ctx->user_ip6[1];
	__u32 c = ctx->user_ip6[2];
	__u32 d = ctx->user_ip6[3];
	__u16 port = be16((__u16)ctx->user_port);

	if (loopback6(a, b, c, d))
		return ALLOW;
	if (ctx->type != SOCK_STREAM)
		return port == 443 ? DENY : ALLOW;
	if (!http_port(port))
		return ALLOW;
	// A dual-stack socket connecting to an IPv4-mapped address goes out
	// over IPv4: send it to the IPv4 listener, in mapped form.
	if (mapped4(a, b, c)) {
		ctx->user_ip6[3] = be32(0x7f000001);
	} else {
		ctx->user_ip6[0] = 0;
		ctx->user_ip6[1] = 0;
		ctx->user_ip6[2] = 0;
		ctx->user_ip6[3] = be32(1);
	}
	ctx->user_port = be16(redirect_port);
	return ALLOW;
}

SEC("cgroup/sendmsg4")
int scrim_sendmsg4(struct bpf_sock_addr *ctx)
{
	if (loopback4(ctx->user_ip4))
		return ALLOW;
	return be16((__u16)ctx->user_port) == 443 ? DENY : ALLOW;
}

SEC("cgroup/sendmsg6")
int scrim_sendmsg6(struct bpf_sock_addr *ctx)
{
	if (loopback6(ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3]))
		return ALLOW;
	return be16((__u16)ctx->user_port) == 443 ? DENY : ALLOW;
}

// blocked reports whether a transport header at off, of protocol proto, is
// TCP to port 80 or 443 or UDP to port 443.
static __always_inline int blocked(const struct __sk_buff *skb, __u32 off, __u8 proto)
{
	__u16 port_be;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;
	if (bpf_skb_load_bytes(skb, off + 2, &port_be, sizeof(port_be)) < 0)
		return 0;
	__u16 port = be16(port_be);
	if (proto == IPPROTO_TCP)
		return http_port(port);
	return port == 443;
}

// The IPv4 header fields the egress check reads.
struct ip4 {
	__u8 vhl;
	__u8 tos;
	__u16 len;
	__u16 id;
	__u16 frag;
	__u8 ttl;
	__u8 proto;
	__u16 sum;
	__u32 saddr;
	__u32 daddr;
};

struct ip6 {
	__u32 vtcfl;
	__u16 len;
	__u8 next;
	__u8 hops;
	__u32 saddr[4];
	__u32 daddr[4];
};

// Extension headers walked to find the transport header. A later fragment
// carries no ports; its first fragment was checked.
#define MAX_EXT 6

SEC("cgroup_skb/egress")
int scrim_egress(struct __sk_buff *skb)
{
	__u8 version;

	if (bpf_skb_load_bytes(skb, 0, &version, 1) < 0)
		return ALLOW;
	version >>= 4;

	if (version == 4) {
		struct ip4 h;
		if (bpf_skb_load_bytes(skb, 0, &h, sizeof(h)) < 0)
			return ALLOW;
		if (loopback4(h.daddr))
			return ALLOW;
		if (be16(h.frag) & 0x1fff)
			return ALLOW;
		return blocked(skb, (h.vhl & 0x0f) * 4, h.proto) ? DENY : ALLOW;
	}
	if (version != 6)
		return ALLOW;

	struct ip6 h;
	if (bpf_skb_load_bytes(skb, 0, &h, sizeof(h)) < 0)
		return ALLOW;
	if (loopback6(h.daddr[0], h.daddr[1], h.daddr[2], h.daddr[3]))
		return ALLOW;
	__u32 off = sizeof(h);
	__u8 next = h.next;
#pragma unroll
	for (int i = 0; i < MAX_EXT; i++) {
		__u8 ext[2];
		if (next == IPPROTO_FRAGMENT) {
			__u16 frag;
			if (bpf_skb_load_bytes(skb, off, ext, 2) < 0 ||
			    bpf_skb_load_bytes(skb, off + 2, &frag, 2) < 0)
				return ALLOW;
			if (be16(frag) & 0xfff8)
				return ALLOW;
			next = ext[0];
			off += 8;
			continue;
		}
		if (next != IPPROTO_HOPOPTS && next != IPPROTO_ROUTING && next != IPPROTO_DSTOPTS)
			break;
		if (bpf_skb_load_bytes(skb, off, ext, 2) < 0)
			return ALLOW;
		next = ext[0];
		off += ((__u32)ext[1] + 1) * 8;
	}
	// More extension headers than MAX_EXT: refuse rather than guess.
	if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING || next == IPPROTO_DSTOPTS ||
	    next == IPPROTO_FRAGMENT)
		return DENY;
	return blocked(skb, off, next) ? DENY : ALLOW;
}

char LICENSE[] SEC("license") = "AGPL-3.0-only";
