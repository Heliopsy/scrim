// SPDX-License-Identifier: AGPL-3.0-only

package install

import (
	"fmt"
	"strings"
)

const docURL = "https://github.com/Heliopsy/scrim/blob/main/docs/service.md"

// systemEnv is the environment of the system service, unit or container:
// state in /var/lib/scrim, sockets in /run/scrim (the agent API given to
// the agent group), the config file in /etc/scrim.
func systemEnv() []string {
	return []string{
		"HOME=" + SystemStateDir,
		"XDG_STATE_HOME=/var/lib",
		"XDG_RUNTIME_DIR=/run",
		"SCRIM_CONFIG=" + SystemConfigFile,
		"SCRIM_API_SOCKET=" + SystemRuntimeDir + "/api.sock",
		"SCRIM_API_PERMISSIONS=0660",
		"SCRIM_API_GROUP=" + AgentGroup,
		"SCRIM_ADMIN_URL=unix:" + SystemRuntimeDir + "/admin.sock",
	}
}

// Seccomp and namespace hardening shared by the system and user units.
// MemoryDenyWriteExecute is compatible with the data plane: it runs from a
// sealed memfd through execve, which maps the image read-only and
// executable, never writable and executable, and neither half JIT-compiles.
const commonHardening = `UMask=0077
LimitCORE=0
NoNewPrivileges=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
`

// SystemUnit is /etc/systemd/system/scrim.service.
func SystemUnit(binary string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --system; scrim uninstall --system removes it.
# Change settings in %s or with systemctl edit scrim.service.
[Unit]
Description=scrim, keeps secrets away from LLM providers
Documentation=%s
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%s
Group=%s
SupplementaryGroups=%s
ExecStart=%s proxy
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
`, SystemConfigFile, docURL, ServiceUser, ServiceUser, AgentGroup, binary)
	for _, kv := range systemEnv() {
		fmt.Fprintf(&b, "Environment=%s\n", kv)
	}
	b.WriteString(`StateDirectory=scrim
StateDirectoryMode=0700
RuntimeDirectory=scrim
RuntimeDirectoryMode=0755
# The data plane locks its memory so values are never swapped.
LimitMEMLOCK=infinity
` + commonHardening + `CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RemoveIPC=yes
# ProtectProc stays at its default: scrim reads /proc/<pid>/stat of the
# agents that connect, to bind sessions to their process trees.

[Install]
WantedBy=multi-user.target
`)
	return b.String()
}

// UserUnit is ~/.config/systemd/user/scrim.service. A user manager cannot
// set up mount namespaces without user namespaces, so the unit keeps to
// the seccomp-based hardening. memlock is raised only when the user's hard
// limit allows it; otherwise systemd would refuse to start the unit.
func UserUnit(binary string, memlock bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --user; scrim uninstall --user removes it.
[Unit]
Description=scrim, keeps secrets away from LLM providers
Documentation=%s

[Service]
Type=simple
ExecStart=%s proxy
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
`, docURL, binary)
	if memlock {
		b.WriteString("LimitMEMLOCK=infinity\n")
	}
	b.WriteString(commonHardening + `
[Install]
WantedBy=default.target
`)
	return b.String()
}

// QuadletRootless is ~/.config/containers/systemd/scrim.container: the
// image under the user's podman, sockets in $XDG_RUNTIME_DIR/scrim at the
// same path inside and outside the container, so `scrim run` on the host
// finds them as it finds a user service.
func QuadletRootless(image string, configDir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --quadlet; scrim uninstall --user removes it.
[Unit]
Description=scrim (container), keeps secrets away from LLM providers
Documentation=%s

[Container]
Image=%s
Exec=proxy
# Loopback listeners as on the host, and the agents' processes visible for
# session binding.
Network=host
PodmanArgs=--pid=host
# The container user is this user, so the sockets and the state volume
# belong to it.
UserNS=keep-id:uid=65532,gid=65532
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Ulimit=core=0
Volume=%s:/var/lib/scrim
Volume=%%t/scrim:%%t/scrim:z
`, docURL, image, QuadletVolume)
	if configDir != "" {
		fmt.Fprintf(&b, "Volume=%s:/etc/scrim:ro,z\n", configDir)
	}
	b.WriteString(`Environment=XDG_RUNTIME_DIR=%t
Environment=XDG_STATE_HOME=/var/lib
Environment=HOME=/var/lib/scrim

[Service]
RuntimeDirectory=scrim
RuntimeDirectoryMode=0700
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=default.target
`)
	return b.String()
}

// QuadletSystem is /etc/containers/systemd/scrim.container: the image under
// root's podman, running as the dedicated user with the same paths and
// environment as the system unit.
func QuadletSystem(image string, uid, gid, agentGID int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# Written by scrim install --quadlet --system; scrim uninstall --system removes it.
[Unit]
Description=scrim (container), keeps secrets away from LLM providers
Documentation=%s
Wants=network-online.target
After=network-online.target

[Container]
Image=%s
Exec=proxy
Network=host
PodmanArgs=--pid=host --group-add=%d
User=%d
Group=%d
ReadOnly=true
NoNewPrivileges=true
DropCapability=all
Ulimit=memlock=-1:-1
Ulimit=core=0
Volume=%s:%s:Z
Volume=%s:%s:z
Volume=%s:%s:ro,z
`, docURL, image, agentGID, uid, gid, SystemStateDir, SystemStateDir, SystemRuntimeDir, SystemRuntimeDir, SystemConfigDir, SystemConfigDir)
	for _, kv := range systemEnv() {
		fmt.Fprintf(&b, "Environment=%s\n", kv)
	}
	fmt.Fprintf(&b, `
[Service]
StateDirectory=scrim
StateDirectoryMode=0700
RuntimeDirectory=scrim
RuntimeDirectoryMode=0755
ExecStartPre=/usr/bin/chown %d:%d %s %s
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
`, uid, gid, SystemStateDir, SystemRuntimeDir)
	return b.String()
}

// SystemConfig is /etc/scrim/config.yaml when none exists: the agent users
// mapped to agents named after them, by user ID so the same file works in
// the container.
func SystemConfig(agents []Account) string {
	var b strings.Builder
	b.WriteString(`# Written by scrim install --system; scrim uninstall --system removes it
# while it is unchanged. Put your own settings in conf.d/*.yaml next to it, so
# this file stays as written. Settings: docs/configuration.md.
apiVersion: scrim.dev/v1
kind: Config
include:
  - {path: conf.d, optional: true}
`)
	if len(agents) == 0 {
		b.WriteString(`# Agents of other users must be in the ` + AgentGroup + ` group and mapped here:
# identity:
#   peers:
#     alice: "uid:1000"
`)
		return b.String()
	}
	b.WriteString("identity:\n  peers:\n")
	for _, a := range agents {
		fmt.Fprintf(&b, "    %s: \"uid:%d\"\n", a.Name, a.UID)
	}
	return b.String()
}
