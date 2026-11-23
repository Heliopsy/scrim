# Databases

scrim lets an agent use a PostgreSQL or MySQL database without holding its password, in two ways:

- **Auth proxies.** A local endpoint per configured database. The agent's client (psql, mysql, a
  driver, an ORM) connects without a password; scrim decides whether this caller may use the
  database, logs in to the real server with the password from your store, over verified TLS, and
  then relays the session.
- **The read-only database tool.** `database_query` over MCP, the local API and
  `scrim database query`. The agent sends one read statement with placeholders in it; scrim binds
  the real values as query parameters, runs the statement in a read-only transaction and returns the
  result redacted.

Both work with MariaDB as well as MySQL.

## Configuration

```yaml
databases:
  app:
    kind: postgres                       # or mysql
    address: db.internal:5432            # the real server
    user: app_agent                      # the user scrim logs in as
    password: bao://kv/db/app#password   # a reference: store, env:, file: or cred:
    database: app                        # optional: the only database the agent gets
    # listen: unix:/run/user/1000/scrim/db/app/.s.PGSQL.5432   (the default)
    # listen: 127.0.0.1:15432
    # tls: verify-full                   # the default; insecure-plaintext turns TLS off
    # tls-ca: /etc/ssl/db-ca.pem         # default: the system roots
    # tls-server-name: db.internal       # default: the host of address
    # tool: true                         # false: proxy only, no database_query
    # query-timeout: 10s
    # query-max-rows: 1000
```

Every field is in [configuration.md](configuration.md) under `databases`. The collection needs a
restart to change; a reload that changes the password's value takes effect on the next login.

- The password is a secret-valued setting: give a reference, not a literal. scrim reads it only to log
  in and adds it to the redaction set, so it is redacted from provider requests like any store value.
- `tls: verify-full` requires TLS and verifies the certificate chain and host name. With
  `insecure-plaintext` scrim still never sends the password in clear (SCRAM, MD5 and the MySQL
  scrambles carry proofs, not the password), and refuses logins that would (a PostgreSQL cleartext
  password request, MySQL's caching_sha2_password full authentication), but the session and the
  server's identity are unprotected. scrim logs a warning at start-up for each such database.
- Give scrim a database user with only the privileges the agent needs. The proxy is the agent's
  session: it can write whatever that user can. The tool only reads, but a read-only role is still
  the strongest limit.

## Auth proxies

The default listener is a Unix socket named the way clients look for one:

<!-- docs-test: skip: needs a configured database -->

```sh
psql "host=$XDG_RUNTIME_DIR/scrim/db/app dbname=app user=anything"
mysql --socket "$XDG_RUNTIME_DIR/scrim/db/shop/mysql.sock" -u anything shop
scrim database ls        # every database with its listener
```

The user name and password the client sends are ignored; scrim logs in as `user`. A TCP listener
(`listen: 127.0.0.1:15432`) must be on a loopback address. Agents in other pods or hosts reach the
proxies through the edge forwarder (tasks.md 12.5), which hands connections to the same proxy.

### Who is connecting

Every connection is decided as `database.auth` before scrim logs in, for the caller the transport
identifies:

| Listener | Identity |
| --- | --- |
| Unix socket | the kernel's peer credentials: the `scrim run` session whose process tree the client is in, else `identity.peers` |
| Loopback TCP | the owner of the client socket from the kernel's socket table (Linux), and the process holding it when it runs as scrim's user; same mapping as a Unix socket |
| anything else | unknown |

Policy sees `op == "database.auth"`, `dest.host` (the server's host), `dest.method == "connect"`,
`dest.path == "/<name>"`, `tool.name == "database-proxy"` and `tool.command` (`postgres` or
`mysql`); `secret.ref` is the password's store reference when it is one. The shipped default denies
everything that is not provider traffic, so add a rule:

```yaml
- name: app-database
  decision: allow
  when: op == "database.auth" && agent.known && dest.path == "/app"
```

An ask rule holds the client's login until a human approves it. Every decision is in the audit log.

### What the proxy guarantees

- The agent's handshake is answered by scrim. No message from the agent's side carries the
  password, and the agent cannot pick another user: MySQL's COM_CHANGE_USER is refused.
- Every server message is checked for the password's bytes before it is relayed. A message that
  carries it, such as a row where someone stored the password, closes the session with a scrim
  error instead.
- Compression is not negotiated, so the check sees plain messages. The agent's side has no TLS: it is
  a local socket, and encryption is between scrim and the server.

Rows are relayed as the server sends them. Values other than the password are not redacted on the
proxy (the agent can read what the database user can read); what the agent then sends to a model
provider is redacted as always.

## The read-only database tool

```json
{"name": "database_query", "arguments": {"database": "app",
  "sql": "SELECT id, created_at FROM api_keys WHERE key = '⟦scrim:stripe:01a1b2c3d4e5f60718⟧'"}}
```

<!-- docs-test: skip: needs a configured database -->

```sh
scrim database query app "SELECT id FROM api_keys WHERE key = \$1" --param '⟦scrim:stripe:01a1b2c3d4e5f60718⟧'
```

```json
{"database": "app", "columns": ["id", "created_at"], "rows": [["42", "2026-11-02 10:14:00+00"]]}
```

- A placeholder inside a plain string literal becomes a parameter (`$n` for PostgreSQL, `?` for
  MySQL) whose value is the literal's text with the real value in place of the placeholder.
  Placeholders in `params` are substituted the same way. The value never becomes SQL text: the
  server's own record of the statement shows the parameter marker.
- A placeholder is bound only when it is the current placeholder of a value scrim holds, its
  credential is bound to the database host in the catalog (`hosts: [db.internal]`; display values
  need no binding), and the injection policy (`op == "inject"`, `tool.name == "database_query"`)
  allows it. Anything else is refused before the statement is sent.
- The statement must be one read: its first keyword is SELECT, WITH, VALUES, TABLE, SHOW or EXPLAIN
  (and DESCRIBE for MySQL); INSERT, UPDATE, DELETE, MERGE, INTO, DDL, COPY, CALL, LOCK and a second
  statement are refused wherever they appear outside literals and comments, as are MySQL executable
  comments (`/*! ... */`) and placeholders outside plain string literals.
- It runs in a read-only transaction (`BEGIN TRANSACTION READ ONLY`, `START TRANSACTION READ ONLY`)
  with a statement timeout, and is rolled back. A write hidden in a function the statement calls
  fails there.
- At most `query-max-rows` rows and 1 MiB of cell text come back; more sets `truncated`.
- The result and any database error message pass the data plane's redactor and guard. Known values
  come back as placeholders, including a bound value the server quotes in an error. If redaction
  fails, the output is withheld.

The tool decides `database.auth` with `dest.method == "query"` and `tool.name ==
"database_query"` first, so one rule can allow the tool and not the proxy, or the other way round.
Each call is audited as `tool.database_query` with the database and the row count, never SQL text
or values.

## Limits

- PostgreSQL cancel requests through the proxy are not supported; the connection closes instead.
- GSSAPI, SSPI, client certificates and MySQL's sha256_password are not supported for scrim's own
  login.
- The tool recognises the standard placeholder form for the current placeholder key. Format-preserving
  placeholders and placeholders made with an older key version are refused as unknown.
- The statement check follows each server's default lexing. A MySQL server with `ANSI_QUOTES` or
  `NO_BACKSLASH_ESCAPES` lexes some text differently; the read-only transaction, the single-statement
  protocol and the database user's privileges still apply.
