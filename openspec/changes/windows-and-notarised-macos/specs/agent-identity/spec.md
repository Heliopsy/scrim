## ADDED Requirements

### Requirement: Peer credentials on Windows

On Windows the system SHALL identify a caller on its Unix socket by the peer process ID the kernel
records (`SIO_AF_UNIX_GETPEERPID`) and the user of that process's token: a caller running as the
account scrim runs as is that account's peer identity, any other account is unknown. Peer rules
SHALL be able to name only scrim's own account there. Session tokens SHALL be bound to a process
tree through the process snapshot and creation times, and a parent created after its child SHALL
end the walk.

#### Scenario: Same account

- **WHEN** a process running as scrim's own Windows account connects to the agent API socket
- **THEN** it is identified as the default agent

#### Scenario: Other account

- **WHEN** a process running as another Windows account connects
- **THEN** it is unknown and denied

#### Scenario: Peer rule naming another account

- **WHEN** `identity.peers` names a Windows account other than scrim's own
- **THEN** scrim refuses the configuration
