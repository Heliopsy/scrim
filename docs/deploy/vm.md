# VM or bare metal

scrim as a long-running service on a Linux host with systemd: a shared development VM, a CI
runner, a jump host where agents run unattended. Four ways to get there, all ending in a systemd
unit that runs `scrim proxy`:

| Way | Use it when |
| --- | --- |
| [`scrim install`](#scrim-install) | you set up one machine by hand and want every change recorded and reverted by `scrim uninstall` |
| [Plain unit files](#plain-unit-files) | you manage units yourself (configuration management, an image build, a golden AMI) |
| [cloud-init](#cloud-init) | the machine is created from a cloud image and should come up with scrim running |
| [Ansible](#ansible) | you already manage the hosts with Ansible |

Files: [`deploy/examples/systemd/`](../../deploy/examples/systemd/),
[`deploy/examples/cloud-init/`](../../deploy/examples/cloud-init/),
[`deploy/examples/ansible/`](../../deploy/examples/ansible/).

The plain unit files (also used by cloud-init and Ansible) are not the unit `scrim install` writes.
The system unit `scrim install --system` writes adds the group `scrim-agents` as a supplementary
group and gives it the agent API socket through `SCRIM_API_*` variables; the plain one gives the
socket to the group `scrim` through `api.permissions` in its config. The user unit from `scrim
install --user` adds `MemoryDenyWriteExecute`, `RestrictAddressFamilies` and `SystemCallFilter`.
[service.md](../service.md#hardening) lists what `scrim install` sets.

## Prerequisites

- Linux with systemd 250 or later, amd64 or arm64.
- For the system service: root, and a place for secrets. The examples read them from files under
  `/etc/scrim/secrets/agents/`, one token per file; [config-openbao.yaml](../../deploy/examples/systemd/system/config-openbao.yaml)
  reads them from OpenBao with an AppRole instead.
- `curl` and cosign to verify the release (cloud-init and Ansible fetch a pinned cosign
  themselves).

## scrim install

`scrim install` writes the unit, creates the user, starts the service and records every change in
a manifest that `scrim uninstall` reverts. The reference is [service.md](../service.md).

```sh
scrim install --user --dry-run                       # show every change, make none
scrim install --user                                 # user unit, runs as you
sudo scrim install --system --agent-user alice       # system unit, user scrim, alice may use it
sudo scrim install --quadlet --system                # the signed image under root's podman
```

Verify, upgrade and uninstall:

```sh
scrim status                                         # includes the installed service
journalctl -u scrim -f                               # --user for a user unit
sudo ./scrim install --system                        # upgrade: install again with the new binary
sudo scrim uninstall --system                        # revert everything install recorded
sudo scrim uninstall --system --purge                # and remove the state
```

A rollback is an install of the previous binary. After a rollback across a state schema change,
move the state database aside: an older scrim refuses a database a newer one migrated.

## Plain unit files

### System service

[`scrim.service`](../../deploy/examples/systemd/system/scrim.service) runs `scrim proxy` as the
user `scrim`, with its state in `/var/lib/scrim`, its sockets in `/run/scrim` and the hardening
systemd allows for a network service. The config
([`config.yaml`](../../deploy/examples/systemd/system/config.yaml)) reads every file under
`/etc/scrim/secrets/agents/` as a secret and binds `agents/github-token` to `api.github.com`.

<!-- x-release-please-start-version -->
```sh
sudo env VERSION=1.4.0 PREFIX=/usr/local bash deploy/examples/workstation/install.sh   # cosign on root's PATH

cd deploy/examples/systemd/system
sudo install -m 0644 scrim.sysusers.conf /etc/sysusers.d/scrim.conf
sudo install -m 0644 scrim.tmpfiles.conf /etc/tmpfiles.d/scrim.conf
sudo systemd-sysusers /etc/sysusers.d/scrim.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/scrim.conf
sudo install -D -o root -g scrim -m 0640 config.yaml /etc/scrim/config.yaml
sudo install -m 0644 scrim.service /etc/systemd/system/scrim.service

# One file per secret, owned by scrim, mode 0600. The value comes from your
# secret manager on stdin, never from a command-line argument.
sudo install -o scrim -g scrim -m 0600 /dev/stdin /etc/scrim/secrets/agents/github-token

sudo systemctl daemon-reload
sudo systemctl enable --now scrim
```
<!-- x-release-please-end -->

The config file holds references, never secret values. Mode 0640 with the group `scrim` lets the
service and the agent users you add to that group read it, as `scrim install` does with
`scrim-agents`.

New files under `agents/` are picked up within `refresh.interval` (one minute here), changed files
within ten seconds. `sudo systemctl reload scrim` reloads the config file; listener changes need a
restart.

With OpenBao instead of files, use `config-openbao.yaml` as `/etc/scrim/config.yaml` and add the
drop-in that hands the AppRole credentials over as systemd credentials:

```sh
sudo install -D -o root -g scrim -m 0640 config-openbao.yaml /etc/scrim/config.yaml
sudo install -D -m 0644 scrim.service.d/openbao.conf /etc/systemd/system/scrim.service.d/openbao.conf
sudo install -d -m 0700 /etc/scrim/credentials
sudo install -m 0600 /dev/stdin /etc/scrim/credentials/bao-role-id     # paste, then Ctrl-D
sudo install -m 0600 /dev/stdin /etc/scrim/credentials/bao-secret-id
sudo systemctl daemon-reload && sudo systemctl restart scrim
```

The credential files stay root-only; systemd passes them to the service, which reads them as
`cred:bao-role-id` and `cred:bao-secret-id`. Give the AppRole read access to the agents' tree only
([OpenBao least privilege](../stores/openbao.md#least-privilege)).

Agents on the host reach the service on loopback: `http://127.0.0.1:9790/anthropic` and
`/openai/v1` as base URLs, `http://127.0.0.1:9791` as `HTTPS_PROXY`. Redaction applies to every
caller. Credential injection needs an identified agent: `scrim run` finds the system service
through `/run/scrim/api.sock`, and `identity.peers` names the agent behind each user. With these
unit files the socket belongs to the group `scrim`, so add each agent user to it
(`sudo usermod -a -G scrim ci-runner`, effective at the next login). A service from
`scrim install --system` uses the group `scrim-agents` instead, which is also the group `scrim run`
names when the socket refuses a user.

### User service

[`user/scrim.service`](../../deploy/examples/systemd/user/scrim.service) runs `scrim proxy` as you,
from `~/.local/bin/scrim` with `~/.config/scrim/config.yaml`. `scrim run` finds it through
`$XDG_RUNTIME_DIR/scrim/admin.sock` and leaves it running when the agent exits.

```sh
install -D -m 0644 deploy/examples/systemd/user/scrim.service ~/.config/systemd/user/scrim.service
install -m 0600 /dev/null ~/.config/scrim/secrets.env    # then add SCRIM_SECRET_GITHUB_TOKEN=...
systemctl --user daemon-reload
systemctl --user enable --now scrim
loginctl enable-linger "$USER"     # keep it running without a login session
```

The unit does not raise `LimitMEMLOCK`: a user manager cannot go above its own hard limit, so the
data plane warns that its memory is not locked. To lock it, raise that hard limit, as
[service.md](../service.md#hardening) describes for `scrim install --user`: for example a root
drop-in `/etc/systemd/system/user@.service.d/memlock.conf` holding `[Service]` and
`LimitMEMLOCK=infinity`, or `/etc/security/limits.conf`. The user manager picks it up when it
starts again: log out of every session, or with lingering on run `sudo systemctl restart
user@$(id -u)`.

### Verify

```sh
systemctl status scrim                              # active (running)
sudo -u scrim env XDG_RUNTIME_DIR=/run XDG_STATE_HOME=/var/lib scrim status
sudo -u scrim env XDG_RUNTIME_DIR=/run XDG_STATE_HOME=/var/lib scrim doctor
curl -s http://127.0.0.1:9792/readyz                # {"status":"ok",...}
```

`scrim status` and `scrim doctor` talk to the daemon over its admin socket, which accepts only the
user scrim runs as and root, so run them as `scrim` with the same paths the unit sets. Plain
`sudo scrim status` reports the service's state in `/var/lib/scrim` only when it finds the manifest of
`scrim install --system`; with these unit files it would look for state under `/root` instead. For
a user service, plain `scrim status` works.

Then send the canary request from [workstation.md](workstation.md#verify) to
`http://127.0.0.1:9790`. To see what the provider received, turn capture mode on for a while with
a drop-in (`Environment=SCRIM_PROXY_CAPTURE_DIR=/var/lib/scrim/capture`), restart, send the request
and look in `/var/lib/scrim/capture`; remove the drop-in afterwards.

### Upgrade and roll back

<!-- x-release-please-start-version -->
```sh
sudo env VERSION=1.4.0 PREFIX=/usr/local bash deploy/examples/workstation/install.sh
sudo systemctl restart scrim
sudo mv /usr/local/bin/scrim.prev /usr/local/bin/scrim && sudo systemctl restart scrim   # roll back
```
<!-- x-release-please-end -->

### Uninstall

```sh
sudo systemctl disable --now scrim
sudo rm -r /etc/systemd/system/scrim.service /etc/systemd/system/scrim.service.d
sudo systemctl daemon-reload
sudo rm /usr/local/bin/scrim /usr/local/bin/scrim.prev /etc/sysusers.d/scrim.conf /etc/tmpfiles.d/scrim.conf
sudo rm -r /etc/scrim /var/lib/scrim      # config, secrets and state
sudo userdel scrim
```

## cloud-init

[`user-data.yaml`](../../deploy/examples/cloud-init/user-data.yaml) writes the system unit, its
sysusers and tmpfiles entries, the config and the install script, fetches cosign pinned by version
and sha256, verifies and installs scrim and enables the service. Pass it as the instance's user
data:

```sh
# OpenStack
openstack server create --image ubuntu-24.04 --flavor m1.small \
  --user-data deploy/examples/cloud-init/user-data.yaml agent-host-1
# AWS
aws ec2 run-instances --image-id ami-0123456789abcdef0 --instance-type t3.small \
  --user-data file://deploy/examples/cloud-init/user-data.yaml
```

User data is readable from inside the instance through the metadata service, so it carries no
secret. Your provisioning writes the secrets to `/etc/scrim/secrets/agents/` afterwards (a
configuration management run, a secret agent, `scp`) and then starts scrim:

```sh
sudo install -o scrim -g scrim -m 0600 github-token /etc/scrim/secrets/agents/github-token
sudo systemctl start scrim
```

The service is enabled but not started by cloud-init, because scrim refuses to start while a
redact target loads nothing: `files://agents/*` over an empty directory would stop it at once.
Files added later are picked up within `refresh.interval`.

Check it on the instance:

```sh
cloud-init status --wait          # status: done
systemctl is-active scrim         # active, once the provisioning started it
curl -s http://127.0.0.1:9792/readyz
```

Upgrade by changing `VERSION` in `runcmd` for new instances; for running ones, use the plain
unit steps above. Uninstall as for the plain units.

## Ansible

The role in [`deploy/examples/ansible/roles/scrim`](../../deploy/examples/ansible/roles/scrim/)
installs the same unit and config. It downloads cosign pinned by sha256, verifies the release
signature and checksum, installs the binary, writes the secrets from `scrim_secret_files`, checks
the config with `scrim config validate` before it replaces the old one, and waits for `/readyz`.
It stops before changing anything when `scrim_secret_files` is empty and the config uses the files
store, since scrim would refuse to start with nothing to redact.

```sh
cd deploy/examples/ansible
$EDITOR inventory.ini                         # your hosts under [scrim]
ansible-vault create group_vars/scrim/vault.yml
#   vault_scrim_github_token: <the token>
cat > group_vars/scrim/main.yml <<'EOF'
scrim_secret_files:
  github-token: "{{ vault_scrim_github_token }}"
EOF
ansible-playbook playbook.yml --ask-vault-pass
```

`scrim_config` replaces the whole config (its default is the systemd example's config), and
`scrim_version` picks the release:

<!-- x-release-please-start-version -->
```sh
ansible-playbook playbook.yml -e scrim_version=1.4.0   # upgrade
ansible-playbook playbook.yml -e scrim_version=<the previous version>   # roll back
ansible-playbook playbook.yml -e scrim_state=absent    # uninstall, keep config and state
ansible-playbook playbook.yml -e scrim_state=absent -e scrim_purge=true
```
<!-- x-release-please-end -->

Verify with the same commands as for the plain units.
