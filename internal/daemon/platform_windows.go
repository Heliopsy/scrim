// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/bpfredirect"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/dataplane"
	"github.com/heliopsy/scrim/internal/dbproxy"
	"github.com/heliopsy/scrim/internal/execbroker"
)

// platformRefusals lists the settings in cfg Windows cannot honour, each
// with why and what to use instead.
func platformRefusals(cfg *config.Config) []string {
	var out []string
	if ProxySocket.Get(cfg) != "" {
		out = append(out, "proxy.socket: the data plane serves no Unix socket listeners on Windows; use proxy.listen")
	}
	if len(TransparentListen.Get(cfg)) > 0 {
		out = append(out, "proxy.transparent-listen: transparent interception needs nftables or eBPF (Linux)")
	}
	if len(bpfredirect.CgroupsSetting.Get(cfg)) > 0 {
		out = append(out, "interception.ebpf.cgroups: eBPF interception is Linux only")
	}
	if len(execbroker.Commands.Get(cfg)) > 0 {
		out = append(out, "exec.commands: brokered commands (secret_exec) need Unix process groups and accounts")
	}
	if len(dbproxy.Databases.Get(cfg)) > 0 {
		out = append(out, "databases: the database proxies identify callers by Unix socket or loopback TCP peer credentials, which Windows does not provide for TCP")
	}
	if m := agentapi.SocketMode.Get(cfg); m != "" && m != "0600" {
		out = append(out, "api.permissions: a Windows socket has no mode bits; who may connect follows the socket directory's DACL")
	}
	if agentapi.SocketGroup.Get(cfg) != "" {
		out = append(out, "api.group: Windows sockets have no group")
	}
	for agent, sel := range agentapi.Peers.Get(cfg) {
		if slices.ContainsFunc(strings.Fields(sel), func(s string) bool {
			return strings.HasPrefix(s, "uid:") || strings.HasPrefix(s, "gid:") || strings.HasPrefix(s, "group:")
		}) {
			out = append(out, "identity.peers."+agent+": Windows has no user or group IDs; only user:NAME of the account scrim runs as can be mapped")
		}
	}
	if dataplane.MlockSetting.Get(cfg) == "require" {
		out = append(out, "dataplane.memory-lock: require cannot be met on Windows, where the data plane does not lock its memory")
	}
	slices.Sort(out)
	return out
}
