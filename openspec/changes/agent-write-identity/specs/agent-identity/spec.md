## ADDED Requirements

### Requirement: Agent writes are checked as the agent

After scrim's rules allow an agent's write to a governed store (`secret_gen`, `secret_capture`,
`secret_ask_human`, `scrim secret put`), the control plane SHALL ask the agent's own store identity
whether it may write there where the store can tell without writing (OpenBao, Vault, Google,
Bitwarden Secrets Manager, Vaultwarden), before anything is generated, run or asked, and SHALL
refuse the write when it may not or when the agent has no identity for that store.

#### Scenario: Read-only Vaultwarden collection

- **WHEN** agent B's own Vaultwarden account may only view collection `TeamA`, scrim's rules allow
  B to write there and scrim's own account could
- **THEN** B's `secret_gen` into `TeamA` is refused with the store's reason and no item is created

#### Scenario: Rules deny first

- **WHEN** scrim's rules deny a write
- **THEN** it is refused without asking the store

### Requirement: Agent writes to stores that cannot check

For a governed store that cannot say whether an identity may write without writing (AWS, Azure Key
Vault, Infisical, Doppler, 1Password Connect), an agent's write SHALL be made with scrim's own
identity once scrim's rules allow it, unless `identity.refuse-unchecked-writes` names the store (or
is `*`), which SHALL refuse it. `scrim doctor` SHALL warn per such store that writes are unchecked.

#### Scenario: Refused by setting

- **WHEN** `identity.refuse-unchecked-writes` is `[aws]` and scrim's rules allow an agent's write to
  `aws://prod/db`
- **THEN** the write is refused and nothing is written

### Requirement: Skipping agent write checks is weakening

`identity.skip-agent-write-checks` SHALL default to off. When on, agents' writes SHALL be made with
scrim's own identity without asking the agent's identity, and the setting SHALL be logged at
start-up and listed as weakened in `scrim status` and `scrim doctor`.

#### Scenario: Skipped

- **WHEN** `identity.skip-agent-write-checks` is on and agent B's account may only view `TeamA`
- **THEN** B's `secret_gen` into `TeamA` is stored and audited with `store_write_check` `skipped`

### Requirement: Write audit names the store identity

Every agent write audit entry SHALL record which store identity checked it (`store_identity`) and
how (`store_write_check`: `checked`, `unchecked`, `skipped` or `shared`), and no refusal SHALL hold a
value or the agent's credential.

#### Scenario: Checked write

- **WHEN** an agent's write is allowed by scrim's rules and by its static store credential
- **THEN** its audit entry has `store_identity` `static` and `store_write_check` `checked`
