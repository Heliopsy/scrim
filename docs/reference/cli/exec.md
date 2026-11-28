# scrim exec

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim exec

Run an allowed command with a secret you never hold (secret_exec).

```text
scrim exec [--env NAME=PLACEHOLDER]... [--stdin] [--dir DIR] -- <command> [args...] [flags]

Asks scrim's exec broker to run the command with the secrets its placeholders name. scrim runs it as another user,
outside this process, and prints its standard output and standard error with every secret replaced by its placeholder.
The command must be allowed by exec.commands or a policy rule; shells, interpreters and commands that print or encode
their input are refused.

Exit status: the command's own, or 1 for an error and 3 when scrim refused to run it. With --output json the result is
printed whole and exit_code holds the command's status.

Examples:
  scrim exec --env PGPASSWORD=SCRIM_DB_PASSWORD -- psql -h db.internal -c 'select 1'
  scrim exec --dir "$PWD" -- git push https://x-access-token:SCRIM_GITHUB_TOKEN@github.com/org/repo HEAD
```

Flags:

```text
      --dir string           absolute working directory, where exec.commands allows it
      --env stringArray      set NAME=VALUE in the command's environment; VALUE holds a placeholder (repeatable)
  -o, --output string        output format: text or json (default "text")
      --stdin[=true|false]   pass this command's standard input to the brokered command
      --timeout int          seconds the command may run (default and maximum exec.timeout)
```
