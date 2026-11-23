## Purpose

Redaction finds every known secret value in traffic bound for a model provider and replaces it with
a deterministic placeholder, checks the result independently, and resolves placeholders in responses
only where the tool policy allows.

## ADDED Requirements

### Requirement: Known values are matched

Redaction SHALL match every secret value currently known from the configured stores, wherever it
appears in a request, and SHALL refuse requests while the set of known values has not yet loaded.

#### Scenario: Secret read from a file

- **WHEN** a tool result in the request contains a value stored in a configured store
- **THEN** the forwarded request contains the value's placeholder instead of the value

#### Scenario: Known values not loaded yet

- **WHEN** a request arrives before the known values have loaded from the stores
- **THEN** the request is refused with an error stating redaction is not ready

### Requirement: Encoded variants are matched

Redaction SHALL also match each known value in its JSON-escaped, base64 (standard and URL-safe, at
every byte offset), hexadecimal and URL-encoded forms, and SHALL replace each occurrence with the
placeholder.

#### Scenario: Base64-encoded secret in a log

- **WHEN** a request contains the base64 encoding of a known value embedded at any offset
- **THEN** the forwarded request contains no substring that decodes back to the value

### Requirement: Nested JSON is matched

JSON text inside a JSON string (tool-call `arguments`, a tool result holding `JSON.stringify`
output, an MCP text block wrapping JSON) escapes a value once per level. Redaction SHALL match each
value JSON-escaped up to `redaction.json_depth` times (default 3, accepted 2 to 4), and the guard
SHALL unescape the outgoing bytes as often. Identical escaped forms SHALL be compiled once.

#### Scenario: Value without JSON-escaped characters

- **WHEN** a known value contains no character any JSON escaping style changes
- **THEN** nesting adds no compiled patterns for it

#### Scenario: Inner and outer serialisers differ

- **WHEN** a value's inner levels are escaped in any JSON style redaction matches singly and its
  outer levels in minimal, Go HTML-safe or non-ASCII `\uXXXX` escaping
- **THEN** the redactor replaces it, and other mixes of styles are left to the guard

#### Scenario: Password with quotes in tool-call arguments

- **WHEN** an OpenAI Chat request carries a known value containing `"` and `\` inside a prior tool
  call's `arguments`, and inside a tool result whose JSON holds another JSON string
- **THEN** the forwarded request holds the placeholder at both places and no string, decoded to
  any depth up to `redaction.json_depth`, contains the value

#### Scenario: Nesting the redactor does not compile

- **WHEN** a value reaches the guard JSON-escaped up to `redaction.json_depth` times in any mix of
  styles, including every character as `\uXXXX`
- **THEN** the guard finds it in the matching unescaped view and repairs the escaped bytes, so
  the body stays valid JSON at every level

### Requirement: Short values

Values shorter than the configured minimum length (`redaction.min_length`, default 8 bytes) SHALL
be matched only verbatim and in their complete encodings, never as fragments such as the inner
base64 substring of a longer stream, and the status command SHALL list how many known values fall
below the minimum.

#### Scenario: Eight-character password

- **WHEN** a known value is shorter than the minimum length
- **THEN** it is replaced where it appears whole and the status command reports it as a short value

#### Scenario: Short value inside base64

- **WHEN** a short value is base64-encoded together with other bytes
- **THEN** the encoded stream is not altered, while the base64 encoding of the value alone is replaced

### Requirement: Value floor

Values shorter than the floor (`redaction.short_floor`, default and minimum 4 bytes) SHALL be
rejected when the value set is built, listed by reference in the status output and documented as
not protected.

#### Scenario: Value below the floor

- **WHEN** a store holds a three-byte value
- **THEN** the value set builds without it and the status command names its reference as unprotected

### Requirement: Values inside other values

When a known value lies inside another one, raw or in hex form, replacing the shorter value
SHALL NOT leave the rest of the longer one in the outgoing bytes: the redactor SHALL replace the
whole occurrence of the longer value, in any form the guard decodes, with its placeholder, or the
request SHALL be refused.

#### Scenario: Cloud emulator credential inside an API key

- **WHEN** `test` (LocalStack's default credentials) and an API key `sk-test-...` are both known,
  and a tool result holds the key as hex wrapped at 60 columns, `xxd` or `hexdump -C` output, or
  truncated to the part that ends with or starts at the shorter value
- **THEN** the whole occurrence of the key is replaced with the key's placeholder and no run of the
  key's bytes reaches the provider in any form the guard decodes

#### Scenario: Shorter value on its own

- **WHEN** the shorter value appears with bytes on both sides that cannot border it inside an
  encoding of the longer value (spaces in prose, `test_case`)
- **THEN** it is replaced with its own placeholder and the guard is not asked about it

### Requirement: Deterministic placeholders

Each value SHALL map to a placeholder derived from a keyed hash of the value, so the same value
always yields the same placeholder across requests, sessions and replicas sharing the key. The
placeholder SHALL name the secret reference's alias, never the value.

#### Scenario: Same secret in two requests

- **WHEN** the same value appears in two separate requests
- **THEN** both forwarded requests contain the identical placeholder

### Requirement: Placeholder format

Placeholders SHALL use a fixed, documented format with distinctive delimiters that compression and
tokenisation do not split or alter, and SHALL be valid inside JSON strings, shell words and source
code without escaping. The format SHALL be `⟦scrim:<slug>:<vv><tag>⟧` with `⟦` U+27E6 and `⟧`
U+27E7, at most 79 bytes.

#### Scenario: Placeholder survives a compression proxy

- **WHEN** a placeholder passes through a chained context-compression proxy and back
- **THEN** the placeholder returned by the model is byte-identical and resolves

#### Scenario: Placeholder in a shell command

- **WHEN** a placeholder appears unquoted in a shell word, a JSON string or a YAML plain scalar
- **THEN** it needs no escaping and contains no whitespace or shell metacharacter

### Requirement: Percent-form placeholders

Where only ASCII may go (an HTTP request header value or request target), a placeholder SHALL be
written in its percent form `%E2%9F%A6scrim:<slug>:<vv><tag>%E2%9F%A7`, at most 91 bytes: the two
brackets percent-encoded, either hex case accepted, nothing else changed. The percent form SHALL
name the same entry: it SHALL resolve wherever the placeholder resolves, the redactor and guard
SHALL treat it as that placeholder, and a value restored in its place SHALL be percent-encoded.

#### Scenario: Placeholder in a request header

- **WHEN** a known value in a request header value is replaced
- **THEN** the header carries the placeholder's percent form, holds only visible ASCII (an RFC 9110 field-value without obs-text), is accepted by a provider front end that rejects obs-text, and resolves to the same entry as the placeholder

#### Scenario: Percent-form placeholder restored

- **WHEN** a model's tool call carries a display value's placeholder in percent form and the tool policy restores it
- **THEN** the tool receives the value percent-encoded in its place

### Requirement: Placeholder fields

The slug SHALL be the reference alias in `[a-z0-9-]`, 1 to 48 bytes, not starting or ending with
`-`. `<vv>` SHALL be the key version as two lowercase hexadecimal digits, `01` to `ff`. `<tag>`
SHALL be the first 8 bytes of `HMAC-SHA256(key, "scrim-placeholder-v1" || 0x00 || value)` as 16
lowercase hexadecimal digits.

#### Scenario: Pinned derivation

- **WHEN** the value `correct horse battery staple` with slug `db-password` is placeholdered under key version 1 with key `0123456789abcdef0123456789abcdef`
- **THEN** the placeholder is `⟦scrim:db-password:0120a7d732ee4c8da2⟧` in every process and on every replica

### Requirement: Format-preserving placeholders

A credential MAY opt in (`placeholder_format: shape`) to a placeholder keeping the value's known
prefix, length and alphabet. The redactor SHALL write it, the resolver SHALL resolve it for every
retained key, one already in the input SHALL be copied byte for byte and never taken for a token
by a detector, and the guard SHALL check for the value as before. Display values and values
without a shape keep the bracket form.

#### Scenario: Client that checks the token prefix

- **WHEN** a GitHub token credential uses `placeholder_format: shape` and a CLI accepts only tokens of the form `ghp_` and 36 characters
- **THEN** the placeholder is `ghp_` and 36 characters, the CLI sends it, and the tool proxy injects the real token toward the bound host

#### Scenario: Guard still catches the value

- **WHEN** a request carries a shaped placeholder and, next to it, the raw value
- **THEN** the value is replaced and the guard finds the value if it is left anywhere, while the placeholder stays byte for byte

#### Scenario: Detector and shaped placeholder

- **WHEN** the agent's text holds a shaped GitHub placeholder and an unknown `ghp_` token
- **THEN** the placeholder is forwarded unchanged and the unknown token is replaced by the detector

### Requirement: Shaped placeholder layout

For a value of 16 to 1,024 visible ASCII bytes, a JWT SHALL become a fixed `alg: none` header,
`{"scrim":"<slug>"}` and drawn base64url characters (its signature's length, at least 22).
Otherwise the longest known token prefix and trailing `=` SHALL be kept (Slack and GitHub
fine-grained separators too), and the rest drawn from `A-Z2-7` after `AKIA` or `ASIA`, else from
the digit and letter classes and other characters the value holds.

#### Scenario: AWS access key id

- **WHEN** an `AKIA` access key id is placeholdered in shape
- **THEN** the placeholder is `AKIA` and 16 characters of `A-Z2-7`

### Requirement: Shaped placeholder draw

Characters SHALL be drawn from the bytes of `HMAC-SHA256(key, "scrim-placeholder-shape-v1" ||
0x00 || u32be(i) || slug || 0x00 || value)` for `i = 0, 1, ...`; a byte `b` SHALL be used when
`b < 256 - 256 mod n` and give character `b mod n` of the `n`-character alphabet. A value whose
drawn positions carry fewer than 64 bits (`count * floor(log2 n)`) has no shape. The control plane
and the data plane SHALL derive the same placeholder, checked by shared vectors.

#### Scenario: Pinned shaped derivation

- **WHEN** the value `ghp_TeStV4lu3N0tR34l0123456789abcdefABCD` with slug `github` is placeholdered in shape under key version 1 with key `0123456789abcdef0123456789abcdef`
- **THEN** the placeholder is `ghp_ViGGu17pAiIX4X4q0Jnc8ybu4sYAj9UXAfnb`, and its last six characters are not a CRC32 checksum of the first thirty

### Requirement: Shaped placeholders are not valid tokens

A shaped placeholder SHALL never carry a valid token checksum: after `ghp_`, `gho_`, `ghu_`,
`ghs_` and `ghr_` with 36 characters, the last character SHALL be drawn again while the last six
are a base62 CRC32 of the first thirty. A shaped placeholder equal to a known value or to another
shaped placeholder SHALL make the snapshot fail.

#### Scenario: Checksum

- **WHEN** two thousand GitHub-style values are placeholdered in shape
- **THEN** no placeholder's last six characters are a CRC32 checksum of its first thirty

### Requirement: Placeholder key rotation

The placeholder key SHALL be versioned. After rotation, new placeholders SHALL use the new key and
placeholders made with retained older keys SHALL still resolve until those keys are retired.

#### Scenario: Conversation spanning a rotation

- **WHEN** the key is rotated during an open conversation
- **THEN** placeholders from before the rotation still resolve in later responses

### Requirement: Fallback detectors

Redaction SHALL run configurable fallback detectors (pattern rules and entropy thresholds) for
secrets not in any store, replacing matches with placeholders. Each detector SHALL be individually
enabled, disabled or tuned in configuration.

#### Scenario: Unknown token matching a pattern

- **WHEN** a request contains a token matching an enabled pattern rule that no store holds
- **THEN** the token is replaced with a placeholder and the audit log records the detector name

#### Scenario: Detector defaults

- **WHEN** no detector settings are configured
- **THEN** every built-in pattern rule is enabled, the entropy detector is disabled, and detector placeholders use the slug `det-<rule>` and never resolve to a value

### Requirement: Independent guard

After redaction, an independent guard SHALL scan the exact outgoing bytes for every known value and
its variants, repair any it finds, and refuse the request when it cannot repair. The guard SHALL
not share matching logic with the redactor. The one exception runs the other way: around a match
of a value that lies inside another one, the redactor asks the guard's decoders what they read in
its input (see "Values inside other values"); the guard's check of the outgoing bytes does not
depend on it.

#### Scenario: Redactor misses a value

- **WHEN** a known value remains in the bytes after redaction
- **THEN** the guard replaces it or refuses the request
- **AND** the audit log records a guard intervention

#### Scenario: Guard decodes what the redactor does not

- **WHEN** a known value of at least the minimum length reaches the guard upper-cased, JSON-escaped up to `redaction.json_depth` times, percent-encoded, base64-encoded at any alignment (wrapped or not), hex-encoded in any case, or in one of the tool transforms the guard decodes
- **THEN** the guard finds it in the decoded view, replaces the covering bytes with the value's placeholder, and checks the repaired bytes again

#### Scenario: Value bytes inside a genuine placeholder

- **WHEN** the slug or tag of a genuine placeholder (one that resolves with the current keyring) contains the bytes of a known value by coincidence, for example a short value of hex digits inside a tag
- **THEN** the redactor and the guard keep the placeholder byte for byte, and the occurrence is not a surviving value, because every byte of a genuine placeholder is fixed by the keyring, the slug and its own value
- **AND** the same bytes outside a genuine placeholder are replaced or refused like any other occurrence

#### Scenario: Repair cannot complete

- **WHEN** a known value is still present after repair, or more values reach the guard than `redaction.guard.max_repairs` allows
- **THEN** the request is refused and nothing is forwarded

### Requirement: Guard decodes tool transforms

The guard SHALL find a known value of at least the minimum length in the output of tools agents
run over files: reversal, rot13, rot47, base64 of base64, base32, byte dumps joined across lines,
units written one at a time with a fixed separator, runs of byte escapes, and these inside a
base64 text data URL. Repairs SHALL cover a dump's ASCII column and keep JSON valid.

#### Scenario: Reversed value in a tool result

- **WHEN** a tool result holds the output of `rev` over a file containing a known value
- **THEN** the guard replaces the reversed value with the value's placeholder

#### Scenario: Byte dump across lines

- **WHEN** a tool result holds `xxd` output of a known value longer than one dump line
- **THEN** the guard joins the lines, replaces the hex groups and the ASCII column with the
  placeholder, and the body stays valid JSON

#### Scenario: Spaced letters in a header

- **WHEN** a request header carries a known value with a space after every character
- **THEN** the guard repairs the header or the request is refused

### Requirement: Guard fragments

The guard SHALL find any run of at least half a known value (at least the minimum length, at most
24 bytes) or of its reversal, unless the run holds fewer than the minimum length of bytes outside
the value's format-fixed parts (PEM armour, a JWT header and payload start).

#### Scenario: Half a value

- **WHEN** the first half of a 40-byte known value reaches the guard
- **THEN** the guard replaces it, while PEM armour or a JWT header alone is left unchanged

### Requirement: Guard decoder cost

Each transform decoder of the guard SHALL do bounded work per input byte, decode only runs above a
length threshold, see the whole body regardless of how the guard splits work between threads, and
allocate nothing on a clean request once its buffers have grown.

#### Scenario: Value across a worker cut

- **WHEN** a reversed or spaced value straddles the point where the guard splits a large body
  between worker threads
- **THEN** the guard still finds it

### Requirement: Guard decoding limitations

The guard SHALL NOT be required to decode look-alike Unicode (no shell tool produces it, tables
are unbounded), spelling alphabets (unbounded), compressed content (unbounded work per byte), the
base85 family (its alphabet covers most printable text), lower-case base32, other ciphers, or
fragments below the threshold, and the documentation SHALL list each with its reason.

#### Scenario: Documented limitation

- **WHEN** a known value reaches the guard in NATO spelling
- **THEN** the guard is not required to find it and the documentation lists the limitation

### Requirement: Split placeholders in streams

Placeholder resolution SHALL handle placeholders split across stream chunks and events of the same
content block, and SHALL emit an unresolvable fragment unchanged rather than a partial value.

#### Scenario: Placeholder across two chunks

- **WHEN** a placeholder arrives split across two streamed chunks
- **THEN** the agent receives the resolved form exactly once, in order

### Requirement: Signed content is byte-identical

Content the provider signs or verifies on return, such as thinking blocks and their signatures,
SHALL reach the provider again with exactly the bytes the provider produced.

#### Scenario: Thinking block sent back

- **WHEN** an agent sends a prior thinking block and its signature back in a later request
- **THEN** the provider receives the block byte-identical to what it originally emitted

### Requirement: Prompt-cache stability

Redaction of an unchanged conversation prefix SHALL produce byte-identical output on every request,
so provider prompt caching keeps working.

#### Scenario: Repeated prefix

- **WHEN** two consecutive requests share the same conversation prefix
- **THEN** the redacted prefixes are byte-identical

#### Scenario: Placeholder from an earlier turn

- **WHEN** a request carries a placeholder that resolves with the current keyring, and a known value happens to occur inside its text
- **THEN** the placeholder is forwarded byte-identical rather than redacted again

### Requirement: Resolution follows tool policy

Placeholders in responses SHALL be resolved to real values only in tool calls the tool policy
allows. Read, search and shell tools MAY receive values classed as display data; edit and write
tools only values already in the target file; unknown and network-capable tools none.

#### Scenario: Unknown tool

- **WHEN** a model calls a tool the policy does not name, with a placeholder in its arguments
- **THEN** the tool receives the placeholder unresolved

#### Scenario: Write introducing a new value

- **WHEN** a write tool call would put a resolved value into a file that does not already contain it
- **THEN** the value stays a placeholder in that call

#### Scenario: Network-capable tool

- **WHEN** a model calls a web fetch tool with a display value's placeholder in its arguments
- **THEN** the tool receives the placeholder unresolved

### Requirement: Tool roles

Each tool name SHALL map to one role, `read`, `search`, `shell`, `edit`, `write`, `network` or
`none`, from the built-in table (Claude Code, Codex CLI and Gemini CLI tool names) or a tool alias.
Shell and edit decisions SHALL be taken on the complete arguments of the call, and while those
stream in the placeholder SHALL stay. Policy rules SHALL only take a restore away
(policy-approvals "Rules only restrict restore").

#### Scenario: Shell call still streaming

- **WHEN** a shell tool call's arguments are streamed and the proxy cannot hold them until complete
- **THEN** every placeholder in them reaches the tool unresolved

### Requirement: Edit tools keep values already in the file

An edit tool SHALL receive a value only where the same call shows the value is already in the file:
in the text it replaces, or on a context or removed line of the same file in a patch. A write tool
replaces whole files and SHALL receive none.

#### Scenario: Edit keeping a value already in the file

- **WHEN** an edit tool call replaces text containing a display value's placeholder with text that contains the same placeholder
- **THEN** both the replaced and the replacement text receive the value

#### Scenario: Earlier edit creating the replaced text

- **WHEN** one call applies several edits and only an earlier edit's replacement introduces the placeholder that a later edit replaces
- **THEN** the earlier replacement keeps the placeholder

#### Scenario: Patch adding a value

- **WHEN** a patch adds a line with a placeholder that no context or removed line of the same file holds
- **THEN** the added line keeps the placeholder

### Requirement: Credentials are never restored into commands

Values classed as credentials SHALL never be resolved into tool arguments, commands or file
contents. They SHALL reach their destination only through credential injection.

#### Scenario: Curl command with a token placeholder

- **WHEN** the model writes a shell command containing a credential placeholder
- **THEN** the shell tool receives the placeholder, not the credential

### Requirement: Context-aware escaping

A resolved value SHALL be escaped for every language layer it lands in, including shell words,
heredocs, command substitution, interpreter `-c` strings, SQL literals, JSON and YAML. Where the
resolved output would itself be executed as code, the value SHALL stay a placeholder.

#### Scenario: Value containing shell metacharacters

- **WHEN** a value containing `$(` and quotes is resolved into a shell command
- **THEN** the command treats the value as data and executes nothing from it

#### Scenario: Value restored into tool-call arguments

- **WHEN** a display value containing `"` and `\` is resolved into a tool call's JSON `arguments`
- **THEN** it is escaped for the arguments JSON and again for the response JSON around it, so the
  tool receives the value exactly
- **AND** where the placeholder sits inside a quoted part of an arguments string (JSON nested in
  the string, a quoted shell word), a value that escaping changes stays a placeholder

#### Scenario: Output piped into a shell

- **WHEN** a resolved value would flow into a pipeline that executes its input
- **THEN** the value stays a placeholder

### Requirement: Data-only command lines

A value SHALL be resolved into a shell command only when every command on the line, including
those in substitutions and nested `sh -c` scripts, is a known data-only command, which takes no code
and runs nothing whatever its arguments, or an interpreter program the analyser can vouch for, and
when no command writes to a file that is code. Anything the analyser does not model SHALL keep
every placeholder on the line.

#### Scenario: Value in an interpreter string

- **WHEN** a display value is resolved into `python3 -c 'print("<placeholder>")'`
- **THEN** it is escaped for the Python string literal and then for the single-quoted shell word, and the program prints exactly the value

#### Scenario: Interpreter that evaluates strings

- **WHEN** the placeholder sits in a string the program passes to `exec`, `eval`, `os.system` or an f-string
- **THEN** the value stays a placeholder

#### Scenario: Value written to a code file

- **WHEN** a command that would receive a resolved value redirects its output to a shell start-up file or a script
- **THEN** the value stays a placeholder

### Requirement: Shell positions

Within a data-only command line a value SHALL be resolved only as an argument, a here-string,
heredoc content or an interpreter string literal; never as a command name, assignment, redirection
target or comment, never right after a backslash or `$`, and never starting a word with `-`.

#### Scenario: Value as a command name

- **WHEN** a placeholder is the first word of a shell command
- **THEN** the value stays a placeholder

#### Scenario: Value that would end a heredoc

- **WHEN** a placeholder fills a heredoc line and the value would make that line equal the delimiter
- **THEN** the value stays a placeholder

#### Scenario: Value read as an option

- **WHEN** a display value starts with `-` and its placeholder starts an argument
- **THEN** the value stays a placeholder

### Requirement: Verbatim restore paths

A restore path that inserts values without escaping them SHALL keep every value that would need
escaping at its site.

#### Scenario: Proxy that cannot escape

- **WHEN** a restore path inserts values verbatim and a value needs escaping at its site
- **THEN** the value stays a placeholder rather than being inserted unescaped

### Requirement: Tool aliases

The tool policy SHALL accept aliases that map another agent's tool names onto the built-in tool
roles, and tools without an alias or role SHALL be treated as unknown.

Aliases SHALL be delivered to the data plane in the snapshot (`Snapshot.restore.tools`), each naming
a role and, where the agent's argument names differ, the argument holding the command (shell) or
the replaced and replacement text (edit). An alias SHALL override the built-in table, and the
built-in table SHALL be switchable off.

#### Scenario: Agent with differently named shell tool

- **WHEN** an alias maps an agent's `run_shell` tool to the shell role
- **THEN** placeholders in `run_shell` calls follow the shell rules

### Requirement: Display modes

Users SHALL be able to switch, without restart, between showing resolved values and showing
placeholders in responses the agent displays, for example while screen sharing.

The display mode SHALL travel in the snapshot (`Snapshot.restore.display_mode`), so switching it
takes effect with the next snapshot. A snapshot without restore settings SHALL restore nothing.

#### Scenario: Screen sharing

- **WHEN** the display mode is set to placeholders
- **THEN** text shown to the user keeps placeholders while tool policy resolution continues

#### Scenario: Control plane without restore settings

- **WHEN** the data plane applies a snapshot that carries no restore settings
- **THEN** every placeholder in responses reaches the agent unresolved

### Requirement: Share and reveal

The CLI SHALL offer `share`, which replaces known values in a text or file with placeholders, and
`reveal`, which resolves placeholders in a text or file locally. `reveal` SHALL refuse credential
values unless explicitly allowed by policy.

Credentials SHALL be revealed only when their reference matches a pattern in
`Snapshot.restore.reveal_credential_refs`, a weakening setting. While break-glass deny-all is engaged,
`reveal` SHALL resolve nothing.

#### Scenario: Preparing a bug report

- **WHEN** a user runs `share` on a log file containing known values
- **THEN** the output contains placeholders in place of every known value

#### Scenario: Revealing a credential

- **WHEN** a user runs `reveal` on text holding a credential's placeholder that no reveal pattern names
- **THEN** the placeholder stays and display values in the same text are resolved
