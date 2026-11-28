# scrim catalog

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim catalog

Show and suggest secret catalog entries.

```text
scrim catalog [command]

The secret catalog maps logical names and declared placeholders to store references and the hosts they may be injected
toward. It never holds values.
```

| Subcommand | Description |
| --- | --- |
| [`scrim catalog labels`](#scrim-catalog-labels) | List every label a secret has, as policy rules see it in secret.labels |
| [`scrim catalog show`](#scrim-catalog-show) | Show the effective catalog and which reference each entry selects |
| [`scrim catalog suggest`](#scrim-catalog-suggest) | Print draft catalog entries from the project, tool profiles and store contents; nothing is applied |

## scrim catalog labels

List every label a secret has, as policy rules see it in secret.labels.

```text
scrim catalog labels <name|reference> [flags]

Reads the secret's metadata from its store (never its value) and prints the labels rules see as secret.labels: the
store's native labels (<kind>.*), user metadata (<kind>.meta.*), scrim.* keys, the generic store.* labels and the labels
the store's `labels` option derives. A secret the store does not hold yet shows the labels a new item there would get.
Paste any line into `scrim policy eval --label`.
```

Flags:

```text
      --json[=true|false]   print JSON
```

## scrim catalog show

Show the effective catalog and which reference each entry selects.

```text
scrim catalog show [name] [flags]

Show the effective catalog. With a name, show that entry and the labels its secret has (secret.labels in policy rules),
read from its store.
```

Flags:

```text
      --agent string         show the selection for this agent
      --for-profile string   show the selection for this catalog profile instead of catalog.profile
      --json[=true|false]    print JSON
      --namespace string     show the selection for this namespace
```

## scrim catalog suggest

Print draft catalog entries from the project, tool profiles and store contents; nothing is applied.

```text
scrim catalog suggest [flags]

Scans the project's .env files, configured tool profiles and the names of secrets under the given store prefixes (and
catalog.metadata-from), and prints draft catalog entries for whatever the catalog does not map yet. Values are never
printed or read from stores, and nothing is written: review the draft and save it yourself.
```

Flags:

```text
      --dir string       project directory to scan (default ".")
      --prefix strings   store prefix to list secret names from (repeatable)
      --store string     base reference for candidate references (default bao://kv/agents)
```
