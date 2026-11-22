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
//   sockops            records where each redirected connection was going.
//
// Attached to the root control group, so it applies wherever scrim runs:
//
//   getsockopt         answers SO_ORIGINAL_DST (IPv4) and
//                      IP6T_SO_ORIGINAL_DST (IPv6) on the transparent
//                      listener's accepted sockets, which the listener reads
//                      as it does after an nftables redirect. A connect
//                      rewrite leaves no conntrack entry, so without this the
//                      kernel has no answer and the listener closes the
//                      connection.
//
// How the original destination travels: connect4/connect6 run before the
// kernel picks the source port, so they store it under the socket's cookie
// (scrim_pending). The sockops program sees the same socket when TCP sends
// its SYN (BPF_SOCK_OPS_TCP_CONNECT_CB), by which time the source port is
// set, and moves the entry to scrim_origdst under the connection's address
// pair: client address and port, listener address and port. That is what
// the listener's accepted socket sees from the other side, so getsockopt can
// find it. The entry is deleted when the client socket closes
// (BPF_SOCK_OPS_STATE_CB to TCP_CLOSE). Only these programs write the maps,
// which are not pinned; a connection without an entry gets the kernel's own
// answer (none), and the listener closes it.
//
// Loopback destinations (127.0.0.0/8, ::1, the unspecified address and
// their IPv4-mapped forms) are never touched, so local listeners, scrim's
// own listeners and the DNS override keep working.
//
// No libbpf headers: the context structures below are the stable UAPI
// layouts from include/uapi/linux/bpf.h, and none of the helpers used
// (bpf_skb_load_bytes, the map helpers, bpf_get_socket_cookie,
// bpf_sock_ops_cb_flags_set) is GPL-only.
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

#define SOL_IP 0
#define SOL_IPV6 41
// SO_ORIGINAL_DST (linux/netfilter_ipv4.h) and IP6T_SO_ORIGINAL_DST
// (linux/netfilter_ipv6/ip6_tables.h) share the number.
#define SO_ORIGINAL_DST 80

#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_ANY 0
#define BPF_SOCK_OPS_TCP_CONNECT_CB 3
#define BPF_SOCK_OPS_STATE_CB 10
#define BPF_SOCK_OPS_STATE_CB_FLAG 4
#define BPF_TCP_CLOSE 7

// Map sizes. LRU maps cannot grow past them: under pressure the least
// recently used entry goes, which is an old connection whose original
// destination was read long ago; at worst a connection not yet accepted
// loses its entry and is closed, never misrouted. A pending entry lives for
// the duration of one connect call.
#define MAX_PENDING 4096
#define MAX_CONNS 16384

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

// struct bpf_sock_ops, up to the fields read here. Addresses and
// remote_port are in network byte order (remote_port as a 32-bit value),
// local_port in host byte order.
struct bpf_sock_ops {
	__u32 op;
	__u32 args[4];
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
};

// struct bpf_sock, up to the fields read here. src_port is in host byte
// order, dst_port in network byte order in its low 16 bits (a 32-bit read
// works on kernels before and after it was narrowed to 16 bits).
struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__u32 dst_port;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
};

struct bpf_sockopt {
	union {
		struct bpf_sock *sk;
		__u64 : 64;
	};
	union {
		void *optval;
		__u64 : 64;
	};
	union {
		void *optval_end;
		__u64 : 64;
	};
	int level;
	int optname;
	int optlen;
	int retval;
};

// struct __sk_buff is only passed through to bpf_skb_load_bytes.
struct __sk_buff;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *ctx, int flags) = (void *)59;

// orig_dst is where a redirected connection was going. An IPv4
// destination, also one a dual-stack socket reached in IPv4-mapped form, is
// AF_INET with the address in addr[3]. The port is in network byte order.
struct orig_dst {
	__u32 family;
	__u32 addr[4];
	__u16 port;
	__u16 pad;
};

// conn_key is a connection seen from the client: its address and port, and
// the listener's. IPv4 addresses are in IPv4-mapped form, so a connection
// is found whether either side holds it in an AF_INET or a dual-stack
// AF_INET6 socket. Ports in host byte order. No padding.
struct conn_key {
	__u32 client[4];
	__u32 server[4];
	__u16 client_port;
	__u16 server_port;
};

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

// scrim_pending: socket cookie of a redirected client socket -> where it
// was going, from connect4/connect6 until the SYN.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PENDING);
	__type(key, __u64);
	__type(value, struct orig_dst);
} scrim_pending SEC(".maps");

// scrim_origdst: the redirected connection -> where it was going, from the
// SYN until the client socket closes.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_CONNS);
	__type(key, struct conn_key);
	__type(value, struct orig_dst);
} scrim_origdst SEC(".maps");

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

static __always_inline void set_mapped(__u32 *a, __u32 ip4)
{
	a[0] = 0;
	a[1] = 0;
	a[2] = be32(0x0000ffff);
	a[3] = ip4;
}

// remember stores where the socket of a connect hook was going.
static __always_inline void remember(struct bpf_sock_addr *ctx, struct orig_dst *o)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	bpf_map_update_elem(&scrim_pending, &cookie, o, BPF_ANY);
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
	struct orig_dst o = {};
	o.family = AF_INET;
	o.addr[3] = ip;
	o.port = (__u16)ctx->user_port;
	remember(ctx, &o);
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
	struct orig_dst o = {};
	o.port = (__u16)ctx->user_port;
	if (mapped4(a, b, c)) {
		o.family = AF_INET;
		o.addr[3] = d;
	} else {
		o.family = AF_INET6;
		o.addr[0] = a;
		o.addr[1] = b;
		o.addr[2] = c;
		o.addr[3] = d;
	}
	remember(ctx, &o);
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

// sockops_key is the connection of a client socket.
static __always_inline int sockops_key(struct bpf_sock_ops *ctx, struct conn_key *k)
{
	if (ctx->family == AF_INET) {
		set_mapped(k->client, ctx->local_ip4);
		set_mapped(k->server, ctx->remote_ip4);
	} else if (ctx->family == AF_INET6) {
		k->client[0] = ctx->local_ip6[0];
		k->client[1] = ctx->local_ip6[1];
		k->client[2] = ctx->local_ip6[2];
		k->client[3] = ctx->local_ip6[3];
		k->server[0] = ctx->remote_ip6[0];
		k->server[1] = ctx->remote_ip6[1];
		k->server[2] = ctx->remote_ip6[2];
		k->server[3] = ctx->remote_ip6[3];
	} else {
		return 0;
	}
	k->client_port = (__u16)ctx->local_port;
	k->server_port = (__u16)be32(ctx->remote_port);
	return 1;
}

SEC("sockops")
int scrim_sockops(struct bpf_sock_ops *ctx)
{
	struct conn_key k = {};

	if (ctx->op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
		__u64 cookie = bpf_get_socket_cookie(ctx);
		struct orig_dst *o = bpf_map_lookup_elem(&scrim_pending, &cookie);
		if (!o)
			return 1;
		struct orig_dst v = *o;
		bpf_map_delete_elem(&scrim_pending, &cookie);
		if (!sockops_key(ctx, &k) || k.server_port != redirect_port)
			return 1;
		bpf_map_update_elem(&scrim_origdst, &k, &v, BPF_ANY);
		// Called back when the socket changes state, to delete the
		// entry when it closes.
		bpf_sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
		return 1;
	}
	if (ctx->op == BPF_SOCK_OPS_STATE_CB && ctx->args[1] == BPF_TCP_CLOSE) {
		if (sockops_key(ctx, &k))
			bpf_map_delete_elem(&scrim_origdst, &k);
	}
	return 1;
}

// struct sockaddr_in and sockaddr_in6, as getsockopt returns them.
struct sockaddr_in4 {
	__u16 family;
	__u16 port;
	__u32 addr;
	__u8 zero[8];
};

struct sockaddr_in6 {
	__u16 family;
	__u16 port;
	__u32 flowinfo;
	__u32 addr[4];
	__u32 scope_id;
};

// answer makes getsockopt succeed with the optlen bytes written to optval.
// The context fields are stored one at a time: the verifier refuses a
// store that spans two of them, which clang could otherwise merge them into.
static __always_inline void answer(struct bpf_sockopt *ctx, int optlen)
{
	*(volatile int *)&ctx->optlen = optlen;
	*(volatile int *)&ctx->retval = 0;
}

SEC("cgroup/getsockopt")
int scrim_getsockopt(struct bpf_sockopt *ctx)
{
	if (ctx->optname != SO_ORIGINAL_DST || (ctx->level != SOL_IP && ctx->level != SOL_IPV6))
		return 1;
	// The kernel answered (conntrack after an nftables redirect): keep it.
	if (ctx->retval == 0)
		return 1;
	struct bpf_sock *sk = ctx->sk;
	if (!sk || sk->protocol != IPPROTO_TCP || sk->src_port != redirect_port)
		return 1;

	// The accepted socket sees the connection from the listener's side.
	struct conn_key k = {};
	if (sk->family == AF_INET) {
		set_mapped(k.client, sk->dst_ip4);
		set_mapped(k.server, sk->src_ip4);
	} else if (sk->family == AF_INET6) {
		k.client[0] = sk->dst_ip6[0];
		k.client[1] = sk->dst_ip6[1];
		k.client[2] = sk->dst_ip6[2];
		k.client[3] = sk->dst_ip6[3];
		k.server[0] = sk->src_ip6[0];
		k.server[1] = sk->src_ip6[1];
		k.server[2] = sk->src_ip6[2];
		k.server[3] = sk->src_ip6[3];
	} else {
		return 1;
	}
	k.client_port = be16((__u16)sk->dst_port);
	k.server_port = (__u16)sk->src_port;
	struct orig_dst *o = bpf_map_lookup_elem(&scrim_origdst, &k);
	if (!o)
		return 1;

	if (ctx->level == SOL_IP && o->family == AF_INET) {
		struct sockaddr_in4 *sa = ctx->optval;
		if ((void *)(sa + 1) > ctx->optval_end)
			return 1;
		__builtin_memset(sa, 0, sizeof(*sa));
		sa->family = AF_INET;
		sa->port = o->port;
		sa->addr = o->addr[3];
		answer(ctx, sizeof(*sa));
	} else if (ctx->level == SOL_IPV6 && o->family == AF_INET6) {
		struct sockaddr_in6 *sa = ctx->optval;
		if ((void *)(sa + 1) > ctx->optval_end)
			return 1;
		__builtin_memset(sa, 0, sizeof(*sa));
		sa->family = AF_INET6;
		sa->port = o->port;
		sa->addr[0] = o->addr[0];
		sa->addr[1] = o->addr[1];
		sa->addr[2] = o->addr[2];
		sa->addr[3] = o->addr[3];
		answer(ctx, sizeof(*sa));
	}
	return 1;
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
