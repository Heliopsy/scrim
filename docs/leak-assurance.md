# Leak assurance

scrim claims that no secret value it knows reaches a model provider. This page explains how that
claim is tested, how to run the same tests against your own setup, what the results mean, and where
the claim stops.

The leak suite has four parts:

- a **fake provider** that speaks the Anthropic Messages API, the OpenAI Chat Completions and
  Responses APIs and the Google Gemini API, streaming and not, with tool calls, and over WebSocket
  the OpenAI Realtime API and the Responses API's WebSocket mode, and records every byte it
  receives;
- a **leak checker**, written independently of scrim's redactor and guard, that looks for every
  seeded value in what the fake provider received, under far more encodings than the redactor
  matches, including fragments;
- the **bypass matrix**: 1189 rows, each a way a secret can sit in a request other than verbatim,
  or a secret in a known format that is in no store, with the outcome scrim must produce, over
  HTTP and over WebSocket;
- a **scenario corpus** of realistic agent sessions (reading `.env`, printing configs, a diff with
  keys, a log with tokens, an MCP tool result, a Kubernetes Secret, `curl -v`, `env`), played by a
  built-in agent on every HTTP API, streaming and not, twice each, to measure prompt caching. The
  agent keeps what it received (after the proxy restored placeholders) in its history, so each
  restored value must be redacted again, byte for byte the same, on the way back out.

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
| `--api anthropic,openai-chat,openai-responses,gemini,openai-realtime,openai-responses-ws` | which provider APIs (default all); the scenarios run on the HTTP ones |
| `--rows <prefix>` | only matrix rows whose ID starts with the prefix, for example `openai-chat/header/` |
| `--route api=/prefix` | the proxy serves an API under a path prefix; `openai-realtime` and `openai-responses-ws` default to the `openai-responses` prefix |
| `--header 'Name: value'` | sent with every request, typically the agent's own provider key (never a seed) |
| `--seeds <file>` | use seeds you already loaded instead of generating new ones |
| `--placeholder <regexp>` | how the proxy's placeholders look, if not `⟦scrim:...⟧` |
| `--min-partial`, `--partial-fraction`, `--max-partial` | leak checker fragment thresholds |
| `--driver synthetic\|claude\|codex\|opencode`, `--agent-bin <path>` | who plays the scenarios ([Agent drivers](#agent-drivers)) |
| `--report <file>` | JSON report (mode 0600), `-` for stdout |
| `--list-matrix` | print the matrix catalogue below |

The seed file holds the fake values in plain text so a store can load them. It is written with mode
0600. Delete it after the run, and never put a real secret in it: the suite would print its hash and
locations, and the fake provider would record it.

The exit status is 0 when the gate passes and 1 when it fails or the run could not complete.

### Agent drivers

`--driver claude`, `--driver codex` and `--driver opencode` play the scenarios with a real agent CLI
instead of the built-in agent: the fake model asks it to run `cat`, `rev`, `base64`, `xxd`, `tr` and
`od` over a workspace of seeded files, and the agent runs them for real with its own shell tool, so
what reaches the proxy is the agent's own request format, tool output framing and history. Each
agent starts with an empty `HOME` (and XDG directories under it) in a scratch directory, so it reads
none of your settings, hooks, MCP servers or credentials, and it authenticates with a fake key the
proxy passes through. `--agent-bin` names the binary; the default is the agent's name on `PATH`.

| Driver | Command | Provider API | Base URL |
| --- | --- | --- | --- |
| `claude` | `claude -p`, the commands allowed with `--allowedTools` | Anthropic Messages, streamed | `ANTHROPIC_BASE_URL` |
| `codex` | `codex exec --dangerously-bypass-approvals-and-sandbox` | Responses API over WebSocket (HTTPS when the proxy refuses the handshake) | `-c openai_base_url=...` |
| `opencode` | `opencode run --pure`, `bash` allowed | Anthropic Messages, streamed | `OPENCODE_CONFIG_CONTENT` with only the `anthropic` provider enabled |

Codex runs without its own sandbox and approvals because nothing can answer an approval and a CI
runner may not allow the namespaces its sandbox needs; the commands are the fake model's, in the
scratch directory. A session fails when the agent exits non-zero or sends fewer model requests than
it has commands to run (the proxy refused one). The prompt cache is measured for the HTTP drivers;
Codex's WebSocket messages carry only the new input, chained by `previous_response_id`, so there is
no prefix to measure and its sessions show `cache=0/0`. Real agents add timestamps and counters, so
no driver but the synthetic one is replayed for byte-identical requests.

`just leak-agents` (`test/leak/agents.sh`) runs the scenario gate with each driver against `scrim
proxy` inside `test/e2e/sandbox.sh` (loopback only). `SCRIM_E2E_CLAUDE`, `SCRIM_E2E_CODEX` and
`SCRIM_E2E_OPENCODE` name the binaries. CI's `e2e-agents` job installs Claude Code, Codex and
OpenCode at pinned versions (Codex 0.171.0, OpenCode 1.19.6 when this was written), runs
`TestAgentDriversPassThrough` (each driver through the pass-through stand-in must complete its
sessions and leak) and then this gate, with `SCRIM_E2E_REQUIRE_TOOLS=1` so a missing agent fails.

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

Over WebSocket it serves the OpenAI Realtime API on `/v1/realtime` (with `?model=`) and the
Responses API's WebSocket mode on `/v1/responses` upgraded from a `GET`, under any prefix; a
`POST /v1/responses` stays HTTP. Authentication is checked on the handshake, which is refused with
401 before the upgrade when it is missing and `RequireAuth` is set. Realtime uses the GA event
names: `session.created` on connect; `session.update`, `conversation.item.create` and
`response.create` answered as the real API answers them; `input_audio_buffer.append` recorded and
not answered; a response streamed as `response.created`, output items, `response.output_text.delta`
and `response.function_call_arguments.delta` events split into small deltas, done events and
`response.done` with the whole output, every event with an `event_id`. The Responses WebSocket mode
takes one `{"type":"response.create", ...}` event per response, with the fields of a Responses
create body at its top level, and answers with the events the SSE stream carries
(`response.created` to `response.completed`), one per message. A failed reply, an unknown client
event or a message that is not JSON is answered with an `error` event and the socket stays open.

A connection records one exchange for its handshake (`"ws": "handshake"`, method `GET`, empty
body, status 101 or the refusal status) and then one per client message (`"ws": "text"` or
`"binary"`) whose body is the message exactly as received and whose response is the server events
sent in reply, one JSON event per line. Every exchange of a connection carries the handshake's
path, query and headers, and `"conn"` numbers the connections.

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

The `unknown-secret` rows (`<api>/unknown-secret/<format>`) carry a value that is in no store: it is
generated for the run and never written to the seed file, so only scrim's fallback detectors
(`redaction.detectors.*`) can stop it. Each runs once per API in a tool result. Formats a default
detector covers expect `redacted` and gate; the others are limitations.

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
| `tool-result` | tool result content as a string (primary placement) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `tool-result-streaming` | tool result in a streaming request ([anthropic-messages gemini openai-chat openai-responses]) | redacted | |
| `tool-result-blocks` | tool result content as text blocks ([anthropic-messages gemini openai-chat openai-responses openai-responses-ws]) | redacted | |
| `user-text` | user message text ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `user-blocks` | user message content parts ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `system-prompt` | system prompt, instructions or system/developer message ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `tool-call-input` | a prior tool call's input in the history (a restored value sent back) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `assistant-text` | a prior assistant message in the history ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `tool-definition` | a tool description (an MCP server describing itself) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `metadata` | request metadata (user id, metadata map) ([anthropic-messages openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `unknown-field` | an undocumented top-level field (like Claude Code's safeguards field) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `unknown-block-field` | an undocumented field inside a content block ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | redacted | |
| `document-text` | a plain-text document or file input ([anthropic-messages gemini openai-chat openai-responses openai-responses-ws]) | redacted | |
| `header` | a custom HTTP request header (on a WebSocket API, in the handshake) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | guard | |
| `query` | the request URL query string (on a WebSocket API, the handshake URL's) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | guard | |
| `image-metadata` | text in an image's PNG tEXt metadata ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | withheld | the scan binary policy reads PNG text chunks and refuses the request: an image cannot be redacted in place |
| `image-metadata-compressed` | text in an image's compressed PNG zTXt metadata ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | withheld | the scan binary policy inflates compressed PNG text chunks |
| `jpeg-comment` | text in a JPEG COM segment ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | withheld | the scan binary policy reads JPEG comment and APP segments |
| `svg-text` | text drawn by an SVG image ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | withheld | the scan binary policy reads SVG as text, entities decoded |
| `pdf-text` | text in a PDF page's Flate-compressed content stream ([anthropic-messages gemini openai-chat openai-responses openai-responses-ws]) | withheld | the scan binary policy inflates PDF streams and reads their strings |
| `image-pixels` | the value as an image's pixel data (rendered text in a screenshot) ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | limitation | limitation: pixel data is not decoded and text in an image is not recognised (no OCR) |
| `split-blocks` | the value split across two content blocks of one message ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | limitation | limitation: a value split by the agent across separate fields is matched only by the guard's fragment rules, if at all |
| `split-tool-results` | the value split across two tool results ([anthropic-messages gemini openai-chat openai-realtime openai-responses openai-responses-ws]) | limitation | limitation: a value split by the agent across separate tool results is not reassembled |
| `split-requests` | the value split across two requests chained by previous_response_id (two events on one socket in the WebSocket mode) ([openai-responses openai-responses-ws]) | limitation | limitation: server-side conversation state lets halves arrive in separate requests |
| `ws-binary-frame` | the tool result event sent as a binary WebSocket frame ([openai-realtime openai-responses-ws]) | redacted | |
| `audio-buffer` | text in base64 audio appended to the Realtime input buffer ([openai-realtime]) | withheld | the scan binary policy decodes base64 audio and refuses the message when its bytes hold a value (speech is not transcribed) |

| Unknown secret | Representative command | Expected | Note |
| --- | --- | --- | --- |
| `aws-secret-access-key` | `cat .env` | redacted | |
| `aws-credentials-csv` | `cat credentials.csv` | redacted | |
| `github-token` | `cat .env` | redacted | |
| `github-fine-grained-token` | `gh auth status -t` | redacted | |
| `gitlab-token` | `cat ~/.config/glab-cli/config.yml` | redacted | |
| `slack-token` | `cat .env` | redacted | |
| `slack-webhook-url` | `cat alerting.yaml` | redacted | |
| `stripe-key` | `cat .env` | redacted | |
| `google-api-key` | `cat config.js` | redacted | |
| `openai-api-key` | `cat .env` | redacted | |
| `anthropic-api-key` | `cat .env` | redacted | |
| `npm-token` | `cat ~/.npmrc` | redacted | |
| `pypi-token` | `cat ~/.pypirc` | redacted | |
| `docker-hub-token` | `cat .env` | redacted | |
| `huggingface-token` | `cat ~/.cache/huggingface/token` | redacted | |
| `twilio-auth-token` | `cat .env` | redacted | |
| `sendgrid-api-key` | `cat .env` | redacted | |
| `azure-storage-key` | `cat appsettings.json` | redacted | |
| `digitalocean-token` | `cat ~/.config/doctl/config.yaml` | redacted | |
| `shopify-token` | `cat .env` | redacted | |
| `atlassian-api-token` | `cat .env` | redacted | |
| `database-url-password` | `cat .env` | redacted | |
| `private-key` | `cat id_ed25519` | redacted | |
| `groq-api-key` | `cat .env` | redacted | |
| `xai-api-key` | `cat .env` | redacted | |
| `openrouter-api-key` | `cat .env` | redacted | |
| `aws-bedrock-api-key` | `cat .env` | redacted | |
| `tailscale-key` | `cat .env` | redacted | |
| `random-password` | `cat .env` | limitation | limitation: a secret in no store and in no known format is not matched by default (redaction.detectors.entropy.enabled covers values after a key name that says secret, off by default) |
| `base64-encoded-token` | `kubectl get secret billing -o yaml` | limitation | limitation: detectors match a format as written by default (redaction.detectors.encoded decodes base64, hex and percent-encoding, off by default) |
<!-- matrix:end -->

### WebSocket rows

A WebSocket row is one conversation on one socket: the handshake, with the row's header or query
when it has one, then the client events, the secret-bearing event first and `response.create`
last, so a proxy that refuses that event has forwarded nothing. In a real Realtime session a
`function_call` item comes from the model and stays on the server, so a tool result is sent as its
`function_call_output` alone. The suite reads server events until every `response.create` has its
`response.done` or `response.completed`. A conversation that completes counts as answered (status
200); a refused handshake has its HTTP status; a socket the proxy closes with 1008 (policy
violation) or 1009 (message too big) counts as a refusal (422 and 413), so a refused first event
with nothing forwarded is `withheld`. The handshake is checked for seeds like any request but is
not a forwarded message: a proxy that opened the upstream socket and refused the first event has
still withheld the conversation, while a seed in the handshake it forwarded is a leak. Rows that
exist only over WebSocket are `ws-binary-frame` (the event as a binary frame, which scrim redacts
as text when it is UTF-8) and `audio-buffer` (text in base64 audio, a binary part scanned like an image).
A placement with no WebSocket form (a streaming flag, a tool result made of blocks in Realtime, a
file input in Realtime) has no row there.

The scenario corpus does not run on the WebSocket APIs. Its sessions replay a conversation and
compare each request's prompt with the previous one's, which assumes the client resends the whole
history; a WebSocket session keeps its history on the server and sends only what is new. The
WebSocket APIs are gated by the matrix rows above.

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

## Fuzzing

Every fuzz target runs under `scripts/fuzz.sh`, in CI from `.github/workflows/fuzz.yaml` and in the
release workflow:

- the cargo-fuzz targets of the data plane (`dataplane/crates/scrim-redact/fuzz`: the two matcher
  engines agree, encoded values never leave `protect()`, the guard's repairs leave nothing and agree
  with its oracle, chunked restore equals whole restore, shaped placeholders keep their shape;
  `dataplane/crates/scrim-toolproxy/fuzz`: SigV4 parsing, verification and re-signing);
- the Go fuzz tests of the control plane (`grep -rn 'func Fuzz' internal`: store references, policy
  globs and the snapshot against CEL, the leak checker, the database proxy's placeholder scan,
  Vaultwarden cipher strings).

| Run | Targets | Time per target |
| --- | --- | --- |
| Pull request | Those whose code the pull request changes: a crate the fuzz crate builds, a package the Go test imports (all of them when the fuzzing workflow or script changes) | 5 minutes |
| Nightly | All, one GitHub-hosted job each | 1 hour |
| Release | All, on the commit released | 10 minutes |

Each run starts from three sets of inputs:

1. The persistent corpus, kept on the `fuzz-corpus` branch of the repository: per target, the inputs
   earlier runs found that reach new code, minimised with `cargo fuzz cmin` (Go keeps only inputs
   that widened coverage and has no minimiser), and in `stats.json` the fuzzing hours and runs
   behind them. The nightly run is the only writer: after every target has fuzzed, a separate job
   with the only write token in the workflow checks the uploaded corpora (known target paths, plain
   files, size limits) and replaces the branch with one new commit, unless the branch moved since it
   was fetched. Pull requests and the release read it anonymously and never write it. When it
   cannot be fetched, the run starts from the next two sets with a warning, and a release's results
   say so.
2. Seeds committed per target, built from the repository's fixtures: the recorded provider requests
   and streams and the leak suite's scenarios with generated test values in place of secrets
   (`fuzz/seeds/<target>`, rewritten with `SCRIM_FUZZ_SEEDS=update cargo test -p scrim-redact --test
   fuzz_seeds`), AWS's SigV4 test suite for `sigv4` (`-p scrim-toolproxy`), and for Go the `f.Add`
   seeds, which read the scenario corpus, the provider fixtures and the policy conformance vectors.
   A test fails when a fixture changes and the committed seeds do not.
3. Earlier findings, committed as regression inputs (below).

A release reports, per target, the seconds and runs of its own fuzzing, the corpus size it started
and ended with, its seeds and findings, and the hours of nightly fuzzing behind the corpus, with the
corpus commit (`scrim_<version>_results_fuzz.json` and the summary). The corpus is input to the
fuzzing jobs only; no build job reads it.

### When a fuzz target finds something

The job fails and uploads the input as the artifact `fuzz-finding-<target>`; a finding in a
release fails the release. Inputs are generated bytes, never secrets. To turn it into a regression
test:

1. Download the artifact and reproduce: `cd dataplane/crates/<crate>/fuzz && cargo +nightly fuzz
   run <target> <file>`, or for Go copy the file to `<package>/testdata/fuzz/<FuzzName>/` and run
   `go test -run '<FuzzName>/<file>' ./<package>`.
2. Fix the cause. Where the finding is the target's own mistake, fix the target and say so in the
   pull request.
3. Commit the input. cargo-fuzz: under `fuzz/regressions/<target>/` with a name saying what it found,
   which every later run of the target reads first, and as a unit test in the crate (the existing
   ones are in `tests/nested_json.rs` and `src/guard_tests.rs`), so `cargo test` checks it without
   nightly. Go: the file stays in `testdata/fuzz/<FuzzName>/`, which `go test` runs on every change.
4. Watch the regression test fail without the fix, then pass with it.

## Published results

Every release runs the leak gates again on the commit it releases, with the linux-amd64 binaries it
ships, and attaches the results to the GitHub release next to the archives:

| File | What it is |
| --- | --- |
| `scrim_<version>_results.md` | Summary: leak suite totals, every documented limitation that leaked, each matrix cell, fuzzing time and the latency gate |
| `scrim_<version>_results_leak-report.json` | `scrim audit run` against `scrim proxy` (the report described under [Running it](#running-it)) |
| `scrim_<version>_results_leak-control.json` | The same suite against a pass-through proxy, which must fail: evidence that the checker finds leaks |
| `scrim_<version>_results_e2e-matrix.json` | One result per [end-to-end matrix](#end-to-end-matrix) cell of the `file`, `openbao`, `vault` and `awssm` stores |
| `scrim_<version>_results_fuzz.json` | Per fuzz target, cargo-fuzz and Go: seconds, runs, result and the corpus it started from ([Fuzzing](#fuzzing)) |
| `scrim_<version>_results_latency-gate.md` | The latency gate with the production engine against `budget.json`, with the machine it ran on ([performance.md](performance.md)) |
| `scrim_<version>_results_latency-gate.json` | The same measurements with every round, for machines; the next release's regression check reads it |
| `scrim_<version>_results_latency-regression.md` | The gate's results against the previous release's |
| `scrim_<version>_results_redact-bench.txt` | The `scrim-redact` criterion benchmarks: throughput per secret set and body size |

The release fails, and nothing is published, when the leak gate or a matrix cell fails, the
pass-through control does not leak, a fuzz target finds a crash, a latency misses its budget or a
gated latency regressed against the previous release. The
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
| Text rendered into image pixels is not recognised (no OCR); pixel data is not decoded, and speech in audio is not transcribed. Binary parts under the weakening `redaction.binary: pass` are not scanned at all. | `image-pixels` | Keep secrets off screen when the agent takes screenshots; keep the default `scan` policy. |
| Look-alike Unicode substitution (Cyrillic or fullwidth letters) is not matched: confusable tables are unbounded and no shell tool produces it. | `homoglyphs`, `fullwidth` | none yet |
| Values spelled out in words (NATO alphabet) are not matched: any language or alphabet would do. | `nato-spelling` | none yet |
| Compressed content (`gzip`, `zlib`) is not decompressed: decompression is unbounded work per byte. | `gzip-base64` | none yet |
| The base85 family (ascii85, RFC 1924 base85) is not matched: its alphabet covers most printable text, so runs cannot be delimited cheaply. | `ascii85`, `base85` | none yet |
| A value the agent splits across fields, tool results or requests (including server-side state such as `previous_response_id`) is not reassembled. | `split-blocks`, `split-tool-results`, `split-requests` | Fragment rules in the guard catch long halves; short values are not protected. |
| Values shorter than the minimum length (default 8 bytes) are matched only whole and in their encoded forms, never as fragments. Truncations of short values pass as `repaired`. | truncation rows for short seeds | Raise the minimum only with care; `scrim status` lists short values. |
| JSON text nested in JSON strings more deeply than `redaction.json_depth` (default 3) is not unescaped further. Backslashes written just before an escaped value pair with its own and count as one more level. | none | Set `redaction.json_depth` to 4 for deeper tool chains; the guard's fragment rule still catches a long half left readable at a shallower level. |
| Transforms not in the matrix, and secrets unknown to every store and missed by the fallback detectors, are not protected. | none | Add stores for every secret source; report new transforms as issues so they become matrix rows. |

Each release publishes its audit report, matrix results and fuzzing time; the summary lists every
limitation row that leaked in that run ([Published results](#published-results)).
