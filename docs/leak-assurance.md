# Leak assurance

scrim claims that no secret value it knows reaches a model provider. This page explains how that
claim is tested, how to run the same tests against your own setup, what the results mean, and where
the claim stops.

The leak suite has four parts:

- a **fake provider** that speaks the Anthropic Messages API, the OpenAI Chat Completions and
  Responses APIs and the Google Gemini API, streaming and not, with tool calls, and records every
  byte it receives;
- a **leak checker**, written independently of scrim's redactor and guard, that looks for every
  seeded value in what the fake provider received, under far more encodings than the redactor
  matches, including fragments;
- the **bypass matrix**: 571 rows, each a way a secret can sit in a request other than verbatim,
  with the outcome scrim must produce;
- a **scenario corpus** of realistic agent sessions (reading `.env`, printing configs, a diff with
  keys, a log with tokens, an MCP tool result, a Kubernetes Secret, `curl -v`, `env`), played by a
  built-in agent on every API, streaming and not, twice each, to measure prompt caching. The agent
  keeps what it received (after the proxy restored placeholders) in its history, so each restored
  value must be redacted again, byte for byte the same, on the way back out.

All secrets are fake values generated at run time. Reports identify a seed by name, kind, length and
the first 12 hex digits of its SHA-256, never by value.

## Running it

The suite runs as `scrim audit run`. It starts the fake provider, generates seeds, sends traffic
through the proxy you name and checks what arrived.

```sh
# Check the suite itself: every row must leak through a proxy that forwards everything,
# and only the verbatim rows are redacted by a stand-in that matches nothing else.
scrim audit run --proxy builtin:passthrough
scrim audit run --proxy builtin:naive

# Your own setup: write the seeds, load them into the store your scrim reads, point scrim's
# provider routes at the fake provider, then run the suite through scrim.
scrim audit run --proxy http://127.0.0.1:8484 \
  --upstream-listen 127.0.0.1:18089 --seeds-out ./leak-seeds.json --report leak-report.json
```

`--driver claude` plays the scenarios with Claude Code itself instead of the built-in agent: the
fake model asks it to run `cat`, `rev`, `base64`, `xxd`, `tr` and `od` over a workspace of seeded
files, and Claude Code runs them for real. Claude Code starts with an empty `HOME` in a scratch
directory, so it reads none of your settings, hooks, MCP servers or credentials, and it
authenticates with a fake key. A Codex driver is not implemented yet.

With `--proxy-cmd`, the suite starts the proxy itself and stops it afterwards. The command gets
`SCRIM_LEAK_UPSTREAM` (the fake provider's URL), `SCRIM_LEAK_SEEDS` (the seed file) and
`SCRIM_LEAK_LISTEN` (the address from `--proxy`) in its environment and must listen there.

In the repository, `just leak-selftest` runs the suite's own tests and `just leak` runs the gate
(set `SCRIM_LEAK_PROXY`, and `SCRIM_LEAK_PROXY_CMD` if the suite should start the proxy). CI runs
both in the `Leak suite` workflow and keeps the JSON reports as artifacts.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--suite matrix,scenarios` | which parts to run (default both) |
| `--api anthropic,openai-chat,openai-responses,gemini` | which provider APIs (default all) |
| `--rows <prefix>` | only matrix rows whose ID starts with the prefix, for example `openai-chat/header/` |
| `--route api=/prefix` | the proxy serves an API under a path prefix |
| `--header 'Name: value'` | sent with every request, typically the agent's own provider key (never a seed) |
| `--seeds <file>` | use seeds you already loaded instead of generating new ones |
| `--placeholder <regexp>` | how the proxy's placeholders look, if not `⟦scrim:...⟧` |
| `--min-partial`, `--partial-fraction`, `--max-partial` | leak checker fragment thresholds |
| `--report <file>` | JSON report (mode 0600), `-` for stdout |
| `--list-matrix` | print the matrix catalogue below |

The seed file holds the fake values in plain text so a store can load them. It is written with mode
0600. Delete it after the run, and never put a real secret in it: the suite would print its hash and
locations, and the fake provider would record it.

The exit status is 0 when the gate passes and 1 when it fails or the run could not complete.

## The fake provider

`scrim-fakeprovider` (`just fakeprovider`, or `go run ./internal/testing/fakeprovider/cmd/scrim-fakeprovider`)
runs the fake provider on its own, for testing a proxy from another language or by hand. It answers
`/v1/messages`, `/v1/messages/count_tokens`, `/v1/chat/completions`, `/v1/responses`,
`/v1/models` and Gemini's `/v1beta/models/{model}:generateContent`, `:streamGenerateContent`
(server-sent events with `alt=sse`, otherwise a JSON array flushed element by element) and
`:countTokens` under any path prefix, streams text and tool-call arguments in small deltas so
placeholders are split across events (a Gemini `functionCall` part arrives whole, as it does from
Google), reports prompt-cache usage the way providers do (a block
counts as cached only when it and everything before it is byte-identical to an earlier request),
and returns provider-shaped errors. `/_fake/exchanges` lists what it received, `/_fake/reset`
forgets it, `-capture-dir` writes each exchange to a file and `-script` takes scripted replies.

## What each outcome means

Each matrix row runs once per seed. The suite observes one of these outcomes:

| Outcome | Observed |
| --- | --- |
| `redacted` | the request was forwarded, the value is absent in every encoding the checker knows, and a placeholder is present |
| `repaired` | the request was forwarded and the value is absent, but no placeholder is present (the value was removed another way, or the fragment was too short to count) |
| `withheld` | the proxy refused the request and forwarded nothing |
| `leaked` | the value, or a fragment above the threshold, reached the fake provider |
| `error` | the suite could not reach a verdict (proxy unreachable, fake provider failed) |

Each row states which outcomes it accepts:

| Expectation | Accepts | Used for |
| --- | --- | --- |
| `redacted` | `redacted` | the plain value and the encodings the redactor itself matches: JSON escapes, base64 at every alignment, hex, URL encoding |
| `guard` | `redacted`, `repaired`, `withheld` | transforms the redactor does not match and the independent guard or a refusal must catch: case changes, reversal, rot13, byte dumps, escape printing, spacing, truncation, SQL functions |
| `withheld` | `withheld` | requests that must be refused |
| `limitation` | anything but `error` | documented limitations: the row runs and is reported, but does not fail the gate |

A run **passes** when every row's outcome is accepted, every scenario has zero leaks, every
scenario replay is byte-identical, and every turn after the first finds the previous turn's whole
prompt in the fake provider's cache. A guard row that comes back `withheld` passes: refusing is
always safe. A `redacted` row that comes back `withheld` fails: scrim refused traffic it is
specified to redact, which breaks the agent.

From outside, the suite cannot tell whether the redactor or the guard removed a value; the audit
log records guard interventions.

### Findings

A failure names the row, the seed (name and hash), the request number, the location in the
request (`body:messages[2].content[0].content`, `header:X-Debug-Context`, `query`), and the
decoding chain that exposed the value, for example `json>base64@1` (base64 decoded starting one
character into the run) or `json>skeleton>reversed` (letters and digits only, lower-cased,
reversed). `exact` means the whole value was recovered; `partial 20/39` means a 20-byte run of a
39-byte value.

### The leak checker

The checker decodes base64 (standard and URL-safe, every alignment, line-wrapped), base32,
ascii85, base85, hex (plain, wrapped, `0x`, `X'..'`, `\x`, `%`, `xxd` and `hexdump -C` dumps),
decimal byte lists, C, shell, Python and JSON escapes, URL encoding (repeatedly), HTML entities,
spelling alphabets, gzip and zlib, up to three layers deep. It compares every result as is, ASCII
case-folded, and reduced to letters and digits after folding look-alike Unicode and dropping
invisible characters, against each value, its reversal and its rot13 and rot47 forms. It also
joins the strings of a request, and of consecutive requests, to catch values split across fields,
messages and requests.

A fragment counts as a leak when it is at least half the value's length (capped at 24 bytes, so a
single line of a private key counts) and at least 8 bytes outside the parts fixed by the value's
format, such as `ghp_` or PEM armour. Values shorter than 8 bytes count only whole.

## The matrix

Rows are every transform below in the primary placement (a tool result) of each API, plus every
placement below with the transforms `raw`, `json-html-escaped`, `base64-std@1`, `reversed` and
`spaced-letters`. Row IDs read `<api>/<placement>/<transform>`. A row takes the more lenient of its
transform's and its placement's expectation.

<!-- matrix:begin -->
| Transform | Representative command | Expected | Note |
| --- | --- | --- | --- |
| `raw` | `cat .env` | redacted | |
| `json-html-escaped` | `client using Go encoding/json` | redacted | same JSON value, < > & as \u escapes |
| `json-ascii-escaped` | `client using Python json.dumps` | redacted | same JSON value, non-ASCII as \u escapes |
| `base64-std@0` | `base64 -w0 <<< "$TOKEN"` | redacted | |
| `base64-std@1` | `base64 -w0 of the value after one byte` | redacted | |
| `base64-std@2` | `base64 -w0 of the value after two bytes` | redacted | |
| `base64-std-nopad` | `base64 -w0 \| tr -d =` | redacted | |
| `base64-url@0` | `basenc --base64url` | redacted | |
| `base64-url@1` | `basenc --base64url, one byte offset` | redacted | |
| `base64-url@2` | `basenc --base64url, two byte offset` | redacted | |
| `hex-lower` | `xxd -p -c0` | redacted | |
| `url-encoded` | `python3 -c 'print(urllib.parse.quote_plus(v))'` | redacted | |
| `url-path-encoded` | `python3 -c 'print(urllib.parse.quote(v))'` | redacted | |
| `upper` | `tr a-z A-Z < .env` | guard | guard: case-insensitive match |
| `lower` | `tr A-Z a-z < .env` | guard | guard: case-insensitive match |
| `swapcase` | `python3 -c 'print(v.swapcase())'` | guard | guard: case-insensitive match |
| `sql-upper` | `SELECT UPPER(token) FROM creds` | guard | guard: case-insensitive match |
| `reversed` | `rev .env` | guard | guard decodes: reversed form indexed (rev is a common shell tool), and reversed fragments catch rev per line |
| `rot13` | `tr 'A-Za-z' 'N-ZA-Mn-za-m' < .env` | guard | guard decodes: rot13 form indexed (one tr command, no runtime cost) |
| `rot47` | `tr '!-~' 'P-~!-O' < .env` | guard | guard decodes: rot47 form indexed (one tr command, no runtime cost) |
| `hex-upper` | `SELECT HEX(token) FROM creds` | guard | guard: hex view, any case |
| `hex-wrapped` | `xxd -p .env` | guard | guard decodes: dump view joins hex lines (xxd -p wraps at 60 columns) |
| `sql-hex-0x` | `SELECT CONCAT('0x', HEX(token))` | guard | guard: hex view |
| `sql-hex-literal` | `pg_dump with bytea hex literals` | guard | guard: hex view |
| `xxd-dump` | `xxd .env` | guard | guard decodes: dump view joins hex groups across lines and covers the ASCII column |
| `hexdump-canonical` | `hexdump -C .env` | guard | guard decodes: dump view joins hex bytes across lines and covers the \|ASCII\| column |
| `od-hex-bytes` | `od -An -tx1 .env` | guard | guard decodes: dump view (od -An -tx1, with or without offsets) |
| `od-chars` | `od -c .env` | guard | guard decodes: od -c cells, and spaced characters on one line |
| `decimal-bytes` | `od -An -tu1 .env` | guard | guard decodes: separated decimal bytes (od -tu1) |
| `python-byte-list` | `python3 -c 'print(list(v.encode()))'` | guard | guard decodes: separated decimal bytes |
| `c-hex-escapes` | `printf '%s' "$TOKEN" \| xxd -i \| ...` | guard | guard decodes: runs of \xNN escapes |
| `octal-escapes` | `printf '%s' "$TOKEN" \| od -b \| ...` | guard | guard decodes: runs of \NNN escapes |
| `unicode-escapes` | `node -e 'console.log(escapeAll(v))'` | guard | guard: JSON view of the inner string |
| `json-escape-all` | `client escaping every character as \uXXXX` | guard | same JSON value: the provider decodes it to the plain value |
| `url-every-byte` | `printf '%s' "$TOKEN" \| od -An -tx1 \| tr ' ' %` | guard | guard: percent-decoded view |
| `url-every-byte-lower` | `curl --data-urlencode style, lower-case hex` | guard | guard: percent-decoded view |
| `url-double` | `url-encode twice` | guard | guard decodes: runs of %25NN escapes |
| `html-entities` | `python3 -c 'print("".join(f"&#{ord(c)};" for c in v))'` | guard | guard decodes: runs of &#NN; entities |
| `html-hex-entities` | `html entity encoder, hex form` | guard | guard decodes: runs of &#xNN; entities |
| `base64-mime-wrapped` | `base64 .env (wraps at 76 columns)` | guard | guard: base64 runs continue across line breaks |
| `base64-double` | `base64 -w0 .env \| base64 -w0` | guard | guard decodes: inner base64 forms indexed, found in the base64 view |
| `base32` | `base32 -w0 .env` | guard | guard decodes: base32 view at every alignment (base32 is a coreutils tool) |
| `base32hex` | `basenc --base32hex -w0` | guard | guard decodes: base32hex view at every alignment |
| `one-char-per-line` | `fold -w1 .env` | guard | guard decodes: separated characters (fold -w1) |
| `spaced-letters` | `sed 's/./& /g' .env` | guard | guard decodes: separated characters (sed, tr) |
| `comma-separated` | `python3 -c 'print(",".join(v))'` | guard | guard decodes: separated characters |
| `dash-separated` | `sed 's/./&-/g' .env` | guard | guard decodes: separated characters |
| `python-char-list` | `python3 -c 'print(list(v))'` | guard | guard decodes: quoted characters separated by commas |
| `zero-width-interleaved` | `sed 's/./&\u200b/g'` | guard | guard decodes: zero-width characters are separators |
| `truncated-prefix` | `head -c 75% of the value` | guard | guard decodes: fragments of at least half the value (8 to 24 bytes); shorter fragments are a documented limitation |
| `truncated-suffix` | `tail -c 75% of the value` | guard | guard decodes: fragments of at least half the value (8 to 24 bytes) |
| `truncated-half` | `cut -c1-half` | guard | guard decodes: fragments of at least half the value (8 to 24 bytes) |
| `sql-substring` | `SELECT SUBSTRING(token, 9, 24) FROM creds` | guard | guard decodes: fragments of at least half the value (8 to 24 bytes) |
| `homoglyphs` | `substitute Cyrillic look-alike letters` | limitation | limitation: look-alike Unicode substitution is not matched (unbounded confusable tables, no shell tool produces it) |
| `fullwidth` | `convert to fullwidth forms` | limitation | limitation: look-alike Unicode substitution is not matched (no shell tool produces it) |
| `nato-spelling` | `spell the value in the NATO alphabet` | limitation | limitation: spelled-out values are not matched (any language or alphabet, unbounded) |
| `gzip-base64` | `gzip -c .env \| base64 -w0` | limitation | limitation: compressed content is not decompressed (unbounded work per byte) |
| `ascii85` | `python3 -c 'base64.a85encode(v, adobe=True)'` | limitation | limitation: base85 family encodings are not matched (alphabet covers most printable text, runs cannot be delimited cheaply) |
| `base85` | `python3 -c 'base64.b85encode(v)'` | limitation | limitation: base85 family encodings are not matched (alphabet covers most printable text, runs cannot be delimited cheaply) |

| Placement | Where | Expected | Note |
| --- | --- | --- | --- |
| `tool-result` | tool result content as a string (primary placement) ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `tool-result-streaming` | tool result in a streaming request ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `tool-result-blocks` | tool result content as text blocks ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `user-text` | user message text ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `user-blocks` | user message content parts ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `system-prompt` | system prompt, instructions or system/developer message ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `tool-call-input` | a prior tool call's input in the history (a restored value sent back) ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `assistant-text` | a prior assistant message in the history ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `tool-definition` | a tool description (an MCP server describing itself) ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `metadata` | request metadata (user id, metadata map) ([anthropic-messages openai-chat openai-responses]) | redacted | |
| `unknown-field` | an undocumented top-level field (like Claude Code's safeguards field) ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `unknown-block-field` | an undocumented field inside a content block ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `document-text` | a plain-text document or file input ([anthropic-messages openai-chat openai-responses]) | redacted | |
| `header` | a custom HTTP request header ([anthropic-messages gemini openai-chat openai-responses]) | guard | |
| `query` | the request URL query string ([anthropic-messages gemini openai-chat openai-responses]) | guard | |
| `image-metadata` | text in an image's PNG tEXt metadata ([anthropic-messages gemini openai-chat openai-responses]) | limitation | limitation: images and other binary parts pass unscanned under the default binary policy |
| `split-blocks` | the value split across two content blocks of one message ([anthropic-messages gemini openai-chat openai-responses]) | limitation | limitation: a value split by the agent across separate fields is matched only by the guard's fragment rules, if at all |
| `split-tool-results` | the value split across two tool results ([anthropic-messages gemini openai-chat openai-responses]) | limitation | limitation: a value split by the agent across separate tool results is not reassembled |
| `split-requests` | the value split across two requests chained by previous_response_id ([openai-responses]) | limitation | limitation: server-side conversation state lets halves arrive in separate requests |
<!-- matrix:end -->

### What the guard decodes

The guard (design D4) re-reads the exact outgoing bytes, request head included, through views the
redactor never compiles. Besides JSON escapes, percent-encoding, base64 and hex it decodes what an
agent's own tools make of a value, because agents run `cat`, `rev`, `base64`, `base32`, `xxd`,
`od`, `tr` and `fold` on files that hold secrets:

| Transform | How the guard finds it |
| --- | --- |
| reversal (`rev`), rot13 and rot47 (`tr`) | the reversed, rot13 and rot47 forms of each value are indexed next to it, so every view finds them at no cost per request; reversed fragments also catch `rev` of a multi-line value, which reverses each line |
| base64 of base64 (and base64 documents holding base64) | the inner base64 forms of each value are indexed and found in the base64 view |
| one unit at a time: spaced or separated characters (`sed 's/./& /g'`, `fold -w1`, commas, dashes, zero-width characters), Python character and byte lists, decimal bytes (`od -tu1`), `0x41, ...` (`xxd -i`) | runs of at least eight units with one fixed separator are decoded; every separator length is tried, since a separator character can also be part of the value |
| runs of `\x41`, `\101`, `&#65;`, `&#x41;`, `%2541` | runs of at least eight self-delimiting escapes are decoded |
| byte dumps: `xxd`, `xxd -p`, `hexdump -C`, `od -tx1`, `od -An -tx1`, `od -c` | dump lines are joined across line breaks; the repair also covers each line's ASCII column |
| base32 and base32hex | upper-case runs of at least thirteen characters, at every alignment, across line breaks |
| truncation and substrings | any run of at least half a value (at least the minimum length, at most 24 bytes) outside its format-fixed parts (PEM armour, a JWT header) |
| the above inside a text document sent as a base64 data URL | the document is decoded and the same views are taken over its text |

A value that lies inside another one (LocalStack's `test` credentials inside an `sk-test-...` key)
is handled before the guard: in a form only the guard decodes, replacing the shorter value would
cut the longer one apart and leave the guard nothing whole to find. Around such a match the
redactor runs the guard's decoders over the request as it came in and replaces the whole longer
value. The gate's proxy (`test/leak/start-proxy.sh`) redacts `test` next to the seeds to keep this
covered.

Each decoder is linear in the input and allocates nothing on a clean request once its buffers have
grown. Lower-case base32, look-alike Unicode, spelling alphabets, compression, the base85 family
and ciphers beyond rot13 and rot47 are not decoded: none is a common shell tool's output, and each
is either unbounded work or an alphabet that cannot be delimited in ordinary text.

## End-to-end matrix

`scrim audit run` checks one proxy URL. The end-to-end matrix (`test/e2e/matrix`, CI job
`e2e-matrix`) runs the same gate through every way an agent's traffic reaches scrim, with the
secrets in real stores and every provider route. Each cell starts the real `scrim proxy` with the
real data plane, writes freshly generated seeds into the cell's store (and, for a cloud route, the
cloud credentials scrim signs with), and runs an agent process that sends the matrix through its
interception mode. The gate is the one above: every row at its expected outcome, zero gated leaks,
no errors. Cells for the four native APIs run the scenario corpus as well. A cell also fails when a
seed appears in scrim's own log.

| Axis | Values |
| --- | --- |
| Interception mode | `run-base-url`: the agent runs under `scrim run` and uses the base URLs it sets. `run-forward-proxy`: under `scrim run`, the agent sends to the provider's own host through `HTTPS_PROXY`, trusting the CA bundle scrim run hands it. `transparent`: the agent has no configuration and connects to the provider's host on port 443; an nftables redirect in the test's network namespace sends it to the transparent listener, as `scrim install --transparent` does. `mcp-only`: the agent uses `scrim mcp` and sends its model requests to the provider itself. |
| Store | `file`; `openbao` and `vault` (dev servers); `awssm` (AWS Secrets Manager on LocalStack). All but the file store run in rootless podman. |
| Provider | `anthropic`, `openai-chat`, `openai-responses`, `gemini` (built-in routes); `bedrock` (SigV4 with a session token), `bedrock-mantle` (Bedrock API key), `anthropic-aws` (SigV4), `foundry` (API key), `foundry-entra` (Entra ID client credentials), `vertex` (service account) as cloud routes. |

A cloud cell sends the Anthropic Messages rows in that provider's wire format (Bedrock InvokeModel,
Vertex `rawPredict`, Foundry under `/anthropic`) to a fake of the provider that refuses any request
scrim did not authenticate with the credentials from the store under test, and the cell fails on
any unauthenticated request. The MCP-only cell lists the seeded secrets, generates one, captures
one from a command's output and requests a grant, then sends every tool result to the provider: no
tool result and nothing the provider received may hold a seeded, generated or captured value. On the
read-only file store generation and capture must be refused.

The full product is 4 modes x 4 stores x 10 providers. The matrix runs a covering design instead:
provider `p` runs with store `s` in mode `(p + s) mod 3` of the three traffic modes, so every pair
of values from two axes runs together at least once (`TestPlanCoversEveryPair` checks it), plus one
MCP-only cell per store: 44 cells, one CI job of 11 per store.

| Provider | `file` | `openbao` | `vault` | `awssm` |
| --- | --- | --- | --- | --- |
| `anthropic` | base URL | forward proxy | transparent | base URL |
| `openai-chat` | forward proxy | transparent | base URL | forward proxy |
| `openai-responses` | transparent | base URL | forward proxy | transparent |
| `gemini` | base URL | forward proxy | transparent | base URL |
| `bedrock` | forward proxy | transparent | base URL | forward proxy |
| `bedrock-mantle` | transparent | base URL | forward proxy | transparent |
| `anthropic-aws` | base URL | forward proxy | transparent | base URL |
| `foundry` | forward proxy | transparent | base URL | forward proxy |
| `foundry-entra` | transparent | base URL | forward proxy | transparent |
| `vertex` | base URL | forward proxy | transparent | base URL |
| (none) | MCP only | MCP only | MCP only | MCP only |

In Kubernetes, `test/k8s/e2e.sh` (CI job `e2e-matrix-kubernetes`) runs the matrix through the
chart's central scrim (Anthropic Messages) and an agent pod's sidecar (OpenAI Chat Completions) on
kind, with the seeds in the cluster's OpenBao, which scrim reads with its own service account token.
The edge forwarder's own end-to-end test is `test/k8s/edge-e2e.sh`.

```sh
test/e2e/matrix/run.sh openbao            # the 11 cells of one store
SCRIM_MATRIX_CELLS="transparent/vault/bedrock mcp-only/vault" test/e2e/matrix/run.sh vault
```

Not in the matrix: the eBPF connect hooks land on the same transparent listener, and
`just ebpf-install-vm-test` runs scrim behind them in a VM; DNS override mode is covered by
`just service-transparent-test`. The other stores are not in the matrix: Google Secret Manager,
Azure Key Vault, Infisical, Vaultwarden, 1Password, Doppler and Bitwarden Secrets Manager have no
emulator here, and SSM, Kubernetes, SOPS, the keyring, `env` and plugins were left out to keep the
matrix to one CI job per store. Their adapters run the conformance suite against fakes or
containers in the store jobs (Kubernetes in kind), and they reach the data plane through the same
redaction set as the stores above.

## Published results

Every release runs the leak gates again on the commit it releases, with the linux-amd64 binaries it
ships, and attaches the results to the GitHub release next to the archives:

| File | What it is |
| --- | --- |
| `scrim_<version>_results.md` | Summary: leak suite totals, every documented limitation that leaked, each matrix cell, fuzzing time and the latency gate |
| `scrim_<version>_results_leak-report.json` | `scrim audit run` against `scrim proxy` (the report described under [Running it](#running-it)) |
| `scrim_<version>_results_leak-control.json` | The same suite against a pass-through proxy, which must fail: evidence that the checker finds leaks |
| `scrim_<version>_results_e2e-matrix.json` | One result per [end-to-end matrix](#end-to-end-matrix) cell of the `file`, `openbao`, `vault` and `awssm` stores |
| `scrim_<version>_results_fuzz.json` | Seconds and runs per cargo-fuzz target, run from an empty corpus for the release |
| `scrim_<version>_results_latency-gate.md` | The LLM proxy latency gate against `budget.json`, with the machine it ran on |
| `scrim_<version>_results_redact-bench.txt` | The `scrim-redact` benchmarks: throughput and latency per secret set and body size |

The release fails, and nothing is published, when the leak gate or a matrix cell fails, the
pass-through control does not leak, a fuzz target finds a crash or a p99 exceeds its budget. The
result files are listed in the signed `checksums.txt` and carry SLSA provenance like the archives,
so they are checked the same way ([install.md](install.md#check-the-published-results)). The
reports name seeds by kind, length and a short hash only; the seeds are generated for the run.

The Kubernetes cell of the matrix and the multi-replica load test run in CI, not in the release.
`scripts/release/results.sh` holds the commands, so you can produce the same files on your own
machine.

## Known limitations

These are the redaction limits the matrix can express. The matrix runs a row for each one, marked
`limitation`, so the report shows whether a given setup happens to contain it.
[limitations.md](limitations.md) has the full list, including limits of the implementation, of
identity and of test coverage.

| Limitation | Matrix rows | Mitigation |
| --- | --- | --- |
| The agent's local transcripts, memory and history files hold real values: scrim protects the wire, not the agent's disk. | none | Keep agent state on an encrypted disk; restored values only reach tools the tool policy names. |
| Images, PDFs and other binary parts pass unscanned, including text in image metadata. In the Gemini API that is every `inlineData` part, a `text/plain` document included, so the matrix has no Gemini `document-text` row. scrim 1.0 has no setting to block them. | `image-metadata` | Keep secrets out of images and documents the agent attaches. |
| Look-alike Unicode substitution (Cyrillic or fullwidth letters) is not matched: confusable tables are unbounded and no shell tool produces it. | `homoglyphs`, `fullwidth` | none yet |
| Values spelled out in words (NATO alphabet) are not matched: any language or alphabet would do. | `nato-spelling` | none yet |
| Compressed content (`gzip`, `zlib`) is not decompressed: decompression is unbounded work per byte. | `gzip-base64` | none yet |
| The base85 family (ascii85, RFC 1924 base85) is not matched: its alphabet covers most printable text, so runs cannot be delimited cheaply. | `ascii85`, `base85` | none yet |
| A value the agent splits across fields, tool results or requests (including server-side state such as `previous_response_id`) is not reassembled. | `split-blocks`, `split-tool-results`, `split-requests` | Fragment rules in the guard catch long halves; short values are not protected. |
| Values shorter than the minimum length (default 8 bytes) are matched only whole and in their encoded forms, never as fragments. Truncations of short values pass as `repaired`. | truncation rows for short seeds | Raise the minimum only with care; `scrim status` lists short values. |
| Transforms not in the matrix, and secrets unknown to every store and missed by the fallback detectors, are not protected. | none | Add stores for every secret source; report new transforms as issues so they become matrix rows. |

Each release publishes its audit report, matrix results and fuzzing time; the summary lists every
limitation row that leaked in that run ([Published results](#published-results)).
