## MODIFIED Requirements

### Requirement: Fallback detectors

Redaction SHALL run configurable fallback detectors (pattern rules and entropy thresholds) for
secrets not in any store, replacing matches with placeholders. Each detector SHALL be individually
enabled, disabled or tuned in configuration, and the pattern rules SHALL also be switched as a
group (`redaction.detectors.enabled`, `redaction.detectors.disable`,
`redaction.detectors.enable`). An unknown rule name, or a name both enabled and disabled, SHALL be
a configuration error.

#### Scenario: Unknown token matching a pattern

- **WHEN** a request contains a token matching an enabled pattern rule that no store holds
- **THEN** the token is replaced with a placeholder and the audit log records the detector name

#### Scenario: Detector defaults

- **WHEN** no detector settings are configured
- **THEN** every built-in pattern rule except `generic-secret-assignment` is enabled, the entropy detector is disabled, and detector placeholders use the slug `det-<rule>` and never resolve to a value

#### Scenario: Group switch

- **WHEN** `redaction.detectors.enabled` is false
- **THEN** no pattern rule runs, whatever the `enable` and `disable` lists name

#### Scenario: One rule off

- **WHEN** `redaction.detectors.disable` names `slack-webhook-url`
- **THEN** a Slack webhook URL no store holds is forwarded, and every other rule still runs

## ADDED Requirements

### Requirement: Known-format detectors

The built-in pattern rules SHALL recognise secrets in known formats by a distinctive prefix, a key
name or a URL structure, together with an exact alphabet and length (the rule list is in
`docs/configuration.md`, setting `redaction.detectors.disable`). A match SHALL not be glued to a
longer token on either side. No rule SHALL drop a match because a vendor checksum does not verify.

#### Scenario: Cloud key in a .env file

- **WHEN** a tool result holds `AWS_SECRET_ACCESS_KEY=` followed by a 40-character key that no store holds
- **THEN** the key is replaced by a `det-aws-secret-access-key` placeholder and the key name is forwarded as it was

#### Scenario: AWS secret next to its key id

- **WHEN** a line holds an access key id followed, within 200 bytes, by a 40-character base64 value mixing upper case, lower case and digits
- **THEN** both are replaced, the second as `det-aws-secret-access-key`

#### Scenario: Token glued to a word

- **WHEN** a known prefix and body sit inside a longer identifier
- **THEN** nothing is replaced

### Requirement: Value-only detections

A rule that recognises a secret by a key name or inside a URL SHALL replace only the value: the
key name, the assignment, the URL scheme, user and host SHALL be forwarded unchanged. When the
value itself matches a prefix rule, that rule's name SHALL be reported. A URL password that is a
template, a variable, a run of one character or a word documentation uses for a password SHALL not
be replaced.

#### Scenario: Database URL

- **WHEN** a request holds `postgres://app:<password>@db:5432/app` with a password no store holds
- **THEN** only the password becomes a `det-database-url-password` placeholder

#### Scenario: Documentation URL

- **WHEN** a request holds `postgres://user:password@localhost/app` or `postgres://user:${DB_PASSWORD}@db/app`
- **THEN** it is forwarded unchanged

#### Scenario: Token in the user part

- **WHEN** a database URL carries a GitHub token as its user and a password
- **THEN** both are replaced, the token as `det-github-token`

### Requirement: Generic secret assignments

The rule `generic-secret-assignment` SHALL be off by default. When enabled, it SHALL replace the
literal value assigned to a key whose name contains `password`, `passwd`, `secret`, `token` or
`api_key`, and SHALL not replace variables, calls, dotted names, templates, URLs, or values with
fewer than three of lower case, upper case, digits and symbols or without a digit.

#### Scenario: Literal password

- **WHEN** the rule is enabled and a request holds `DB_PASSWORD=` followed by a random literal
- **THEN** the literal is replaced by a `det-generic-secret-assignment` placeholder

#### Scenario: Assignment from code

- **WHEN** the rule is enabled and a request holds `secret_key = settings.SECRET_KEY` or `password = getpass.getpass(prompt)`
- **THEN** nothing is replaced

### Requirement: Detector matching cost

The pattern rules SHALL be found by multi-pattern automata over their anchors (a fixed prefix,
part of a key name, or the `://` of a URL; each at least three bytes), and a rule's regular
expression SHALL run only where one of its own anchors was found. Detection SHALL add no false
positive on the repository's own documentation, specifications and source outside its deliberate
test credentials.

#### Scenario: Many rules, few passes

- **WHEN** every rule is enabled
- **THEN** the anchors fit in at most eight automata of at most 24 patterns, and a request body without secrets runs no rule's regular expression except where one of its anchors occurs
