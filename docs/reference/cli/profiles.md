# scrim profiles

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim profiles

List, show and test tool profiles for command-line tools.

```text
scrim profiles [command]

A tool profile says where a command-line tool (gh, git, kubectl, aws, ...) reads its credentials and which hosts it
sends them to. scrim run generates that configuration with placeholders in the session directory, points the tool at it
with the tool's own override variables and removes it when the agent exits. A catalog entry fills a profile by naming it
in its tools list. See docs/cli-tools.md.
```

| Subcommand | Description |
| --- | --- |
| [`scrim profiles list`](#scrim-profiles-list) | List tool profiles and whether scrim run applies them |
| [`scrim profiles show`](#scrim-profiles-show) | Show a tool profile and what it generates for the current catalog |
| [`scrim profiles test`](#scrim-profiles-test) | Check that installed tools read only the generated placeholder configuration |

## scrim profiles list

List tool profiles and whether scrim run applies them.

```text
scrim profiles list [flags]
```

Flags:

```text
      --json[=true|false]   print JSON
```

## scrim profiles show

Show a tool profile and what it generates for the current catalog.

```text
scrim profiles show <profile> [flags]

Shows the profile's credential slots, the hosts and the catalog entries that fill them, and the variables and files
scrim run would generate (rendered under <session-dir>/profiles). With --sample, every slot is filled with a sample
placeholder. Only placeholders are ever shown.
```

Flags:

```text
      --json[=true|false]     print JSON
      --sample[=true|false]   fill every slot with a sample placeholder instead of the catalog
```

## scrim profiles test

Check that installed tools read only the generated placeholder configuration.

```text
scrim profiles test [profile...]

Runs each profile's test command (for example gh auth token, aws configure get, kubectl config view --raw) with an empty
home directory and the profile applied with sample placeholders. Decoys sit at the tool's fixed credential paths and in
the variables the profile removes; the test fails if the tool prints a decoy or not the generated placeholder. Profiles
without a test command or whose tool is not installed are skipped. No real credential is read or sent anywhere.
```
