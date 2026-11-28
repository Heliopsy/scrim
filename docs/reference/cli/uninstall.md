# scrim uninstall

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim uninstall

Revert every change `scrim install` recorded.

```text
scrim uninstall [--user | --system | --hooks | --managed-settings] [--purge] [flags]

Reverts each change in the install manifest, newest first: the CA trust, the service, the unit, the configuration file
it wrote, the binary, the users and groups it created. A change that cannot be reverted (a file edited since) stays
listed with the manual step, and the command exits 1.

The state (CA, placeholder keys, state database, audit log), and for Quadlet the volume and the pulled image, are kept
unless --purge is given.

Without --user or --system: the system install when run as root, otherwise this user's. Each also reverts the agent-side
mode of its scope: managed settings for the system, hooks for a user. --hooks or --managed-settings reverts only that
mode.
```

Flags:

```text
      --dry-run[=true|false]            show what would be reverted without changing anything
      --hooks[=true|false]              revert only the agent hooks of this user
      --managed-settings[=true|false]   revert only the managed agent settings (needs root)
      --purge[=true|false]              also remove the state directory, the podman volume and the pulled image
      --system[=true|false]             uninstall the system service (needs root)
      --user[=true|false]               uninstall this user's service
```
