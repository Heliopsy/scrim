#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Prints one line per file system entry outside the runtime and log trees:
# path, type, mode, owner and, for regular files, the SHA-256. Run inside the
# disposable host before an install and after the uninstall; the two outputs
# must be equal.
#
# Left out on purpose: the kernel and runtime trees (/proc, /sys, /dev, /run,
# /tmp, /var/tmp), logs and caches (/var/log, /var/cache), the test's own
# mount (/opt/scrim-test), systemd's own bookkeeping that changes with every
# boot or unit start (/var/lib/systemd), and the backups the shadow tools
# rewrite on every account change (/etc/passwd-, /etc/group-, /etc/shadow-,
# /etc/gshadow-, /etc/subuid-, /etc/subgid-).
set -eu
find / -xdev \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \
     -o -path /var/log -o -path /var/cache -o -path /opt/scrim-test -o -path /var/lib/systemd \
     -o -path /etc/passwd- -o -path /etc/group- -o -path /etc/shadow- -o -path /etc/gshadow- \
     -o -path /etc/subuid- -o -path /etc/subgid- \) -prune \
  -o -printf '%p %y %m %u:%g\n' | sort > /tmp/snapshot.meta
find / -xdev \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \
     -o -path /var/log -o -path /var/cache -o -path /opt/scrim-test -o -path /var/lib/systemd \) -prune \
  -o -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/snapshot.sums
cat /tmp/snapshot.meta
grep -v -E ' /etc/(passwd|group|shadow|gshadow|subuid|subgid)-$' /tmp/snapshot.sums
rm -f /tmp/snapshot.meta /tmp/snapshot.sums
