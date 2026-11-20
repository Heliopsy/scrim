// SPDX-License-Identifier: AGPL-3.0-only

package cli

import "net"

func netListenUnix(path string) (net.Listener, error) { return net.Listen("unix", path) }
