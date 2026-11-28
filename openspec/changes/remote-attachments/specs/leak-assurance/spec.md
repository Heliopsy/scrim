## ADDED Requirements

### Requirement: Remote attachment rows

The fake provider SHALL hold files a request can reference and SHALL record a request that names one
as having read it. The bypass matrix SHALL carry rows for a seed in an image, a PDF and a text file
referenced by URL, and in a file referenced by a provider file ID, each expected not to reach the
provider.

#### Scenario: Pass-through leaks referenced files

- **WHEN** the matrix runs the remote attachment rows through a pass-through proxy
- **THEN** every row reports a leak

#### Scenario: Gate against the real proxy

- **WHEN** CI runs the remote attachment rows through `scrim proxy`
- **THEN** the image, PDF and file ID rows are withheld and the text rows are redacted
