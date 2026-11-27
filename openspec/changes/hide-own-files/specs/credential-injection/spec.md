## ADDED Requirements

### Requirement: Session filesystem view hides scrim's own files

The daemon SHALL report, to a local user that may mint sessions and never to a session, the paths it
reads secrets or key material from: `file:` reference targets, config files, key and state
directories, store files. `scrim run` SHALL hide each one the agent's user can read. A readable one
the view cannot hide (outside `$HOME` in the home mirror, or holding a path the session needs) SHALL
refuse the start unless `run.fs-view-allow-readable-own-files` is set.

#### Scenario: Vaultwarden master password file

- **WHEN** scrim runs as the agent's user with `unlock: file:~/.config/scrim/vw-master` and the
  agent runs `cat` on that file inside a namespace session
- **THEN** the read fails, and the session still reaches the agent API

#### Scenario: System service

- **WHEN** scrim runs as a system service whose files are mode 0600 under its own user
- **THEN** the files are not covered, since the agent's user cannot read them

#### Scenario: Home mirror with a key outside the home

- **WHEN** the view is the home mirror and the agent's user can read a key file of scrim's outside
  `$HOME`
- **THEN** `scrim run` exits 125 naming the file and the weakening setting

#### Scenario: Asked by a session

- **WHEN** a session token asks the daemon for its own paths
- **THEN** the request is refused

### Requirement: Own paths follow the effective configuration

A setting or store field SHALL count as one of scrim's own paths only while the effective
configuration makes scrim read it. The default path of a feature that is off SHALL NOT count.

#### Scenario: Pod without Kubernetes identity

- **WHEN** scrim runs in a pod with `identity.kubernetes.enabled` off and the pod's service account
  token is readable at the default `identity.kubernetes.token-file`
- **THEN** the token is not one of scrim's own paths and `scrim run` starts the agent

#### Scenario: Kubernetes identity on

- **WHEN** `identity.kubernetes.enabled` is on
- **THEN** `identity.kubernetes.token-file` is one of scrim's own paths
