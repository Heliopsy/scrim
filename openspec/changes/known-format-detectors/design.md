## Context

Detectors run over the bytes between exact matches. One Aho-Corasick automaton (leftmost-first)
found the 34 anchors of the 12 old rules, and each rule's anchored regex ran only where its anchor
was found. Teddy, the SIMD prefilter that makes this cheap, takes at most 64 patterns and uses
fingerprints as long as the shortest one (up to three bytes).

## Decisions

### Anchors and automata

Every rule has case-sensitive anchors of at least three bytes, chosen so their first three bytes
(Teddy's fingerprint) are rare in text. Several vendors share a short prefix (`xox` for Slack,
`glp` for GitLab `glpat-` and `glptt-`, `shp` for Shopify); an anchor that extends another is
dropped. Prefixes that start common words (`glo`, `lin`, `ops`, `doo`) are replaced by a later
part of the token and a fixed offset back (`oas-` for `gloas-`, `_eyJ` for `ops_eyJ`, `_v1_` for
DigitalOcean). Key-name rules anchor on part of the name in its usual spellings (`s_key`,
`S_KEY`, `sKey` for `aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY`, `SecretAccessKey`) and start
the match at the beginning of the identifier around it. Database URLs anchor on `://` and check
the scheme before the regex runs.

Teddy checks the two halves of each fingerprint byte separately, so a bucket of several
fingerprints also admits their crossings, and text, mostly lower case, keeps it verifying. One
automaton over all ~90 anchors ran at about a third of the old rules' speed. The anchors are
grouped by their first byte (upper case, lower case, other), the lower case group is split into
automata of at most 24, and `://` sits alone, where `memmem` finds it. Each automaton pattern
dispatches only to the rules with an anchor it starts. A case-insensitive automaton for key names
was tried and dropped: it disables Teddy and cost ten times a case-sensitive one.

The cost that remains is reported per release by the `detect` bench group (detectors alone over
request bodies and source code) next to the `redact` group.

### Value-only replacement

A rule with a group named `v` replaces only that group: the value after a key name, the password
of a URL. Such a rule can report a detection that starts after anchors still untried (a GitHub
token in the user part of a database URL), so the scan keeps trying candidates until they pass
the earliest start found, and keeps later detections for the next step instead of finding them
again. When the value itself starts with a known prefix, the specific rule's name is reported.

### AWS secret next to its key id

An AWS secret access key has no prefix. Besides a key name, it is recognised as the first run of
exactly 40 base64 characters on the same line within 200 bytes after an access key id, mixing
upper case, lower case and digits (`credentials.csv`, pasted pairs). A hex digest has no upper
case and does not qualify.

### No checksum gate

GitHub documents that its classic tokens end in a CRC32 but not exactly what is summed; the shaped
placeholder code already checks two readings. A detector that dropped tokens failing a guessed
checksum would miss real tokens if the guess were wrong, and the prefix, alphabet and exact length
already give no hit on the repository corpus. No published checksum exists for fine-grained
GitHub tokens. So no rule rejects a match on a checksum.

### Generic assignments off by default

`password = ...` style rules see code that assigns those names from variables and calls all the
time. The rule rejects variables, calls, dotted names, templates, URLs and values with fewer than
three character classes or no digit, but it stays off by default and can be enabled by name.

### Settings

`redaction.detectors.enabled` (default true) switches every pattern rule; `disable` and `enable`
list rule names. Names are validated in the control plane against the rule list the data plane
compiles (`internal/daemon/detectors.json`, checked by tests on both sides). The proto
fields are named so their zero value is the default (`detectors_off`), keeping an older control
plane's snapshot on the defaults.

## Risks

- Detector placeholders never resolve: an agent that sends an unknown token found by a new rule
  sees a placeholder and cannot use the token through scrim. That is the intent; disable the rule
  by name if a format is wrongly matched.
- Detection costs more than before (see the `detect` bench group); it stays well inside the 5 ms
  p99 budget for a 1 MB body.
