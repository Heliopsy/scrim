## Context

The codecs already walk every content part to find inline binary data (`binary-parts-policy`).
References sit in the same parts: Anthropic `source.type: url` and `source.type: file` (image and
document blocks), `container_upload.file_id`; OpenAI Chat `image_url.url` and `file.file_id`;
OpenAI Responses `input_image.image_url`, `input_image.file_id`, `input_file.file_url` and
`input_file.file_id`; Gemini `fileData.fileUri` (a Files API URI, a `gs://` object, a YouTube URL
or any public URL); Bedrock Converse `source.s3Location`. Anthropic bodies on Bedrock and Vertex go
through the same codec. Field names were checked against the providers' documentation in
November 2026.

## Decisions

### R1. Default `inline`

The owner's preference is safety without breaking agents. `refuse` breaks every agent that passes
an image URL; `pass` leaves the leak open. `inline` keeps agents working (the provider gets the
same content, inline) and closes the leak, at the cost of one fetch per reference. Providers accept
inline data for every reference form scrim inlines, so a request that worked with a URL works
inline.

### R2. Plan, then fetch, then plan again

The codec records each reference in the plan with how its replacement is built. `outgoing::prepare_refs`
applies the policy right after planning, before anything is redacted, and returns the URLs to fetch.
The proxy fetches them (async), splices the inline forms into the body and prepares the new body
again with `fetched` set, where a URL left over refuses. A request without references pays nothing
beyond an empty vector: no extra parse, no extra pass.

### R3. Fetch safety

`remote::addr::permitted`: public unicast only, unless the setting names the network; scrim's own
listener addresses never. The host is resolved once and every address checked; any refused address
refuses the request (a name with one private address is suspect). The connection uses
`scrim_dns::FixedResolver` with exactly the checked addresses, so a second lookup cannot answer
differently (DNS rebinding). Redirects are not followed by the client: each `Location` is resolved
and checked like the first URL, at most 5 hops. When the upstream proxy applies, the proxy
resolves the name: scrim still checks address literals and what its own resolver answers, and
proceeds without its own answer only when the name does not resolve locally (networks without
outside DNS). The fetch carries no agent header. A URL in which the redactor or the guard finds a
known value is not fetched, since the fetch would send it.

### R4. Bounds

All fetches of one request share the largest decoded part the scan accepts (64 MiB) and the time
the scan allows a part of that size (2 s plus 250 ms per MiB, 18 s). Over the size is
`unscannable_content`, like a part over the scan bound; a slow or failing server is
`attachment_unavailable`. At most 32 URLs per request.

### R5. Media type

From magic bytes when the format is known (PNG, JPEG, GIF, WebP, PDF), as the binary scan decides
it; UTF-8 text without NUL is text (the server's text type, else `text/plain`); otherwise the
server's type, else the type the request declared. An Anthropic document that is plain text becomes
a text source, so it is redacted as text instead of refused.

### R6. File IDs

A provider file cannot be read, so it can only be trusted when its content went through scrim.
Uploads are recognised per provider and the file part scanned with the binary scan (a text file is
redacted in place by the normal body redaction); on a 2xx answer the ID (`id`, Gemini `file.name`)
is remembered for the route. In memory, 4096 per route, oldest out: another replica or a restart
does not know it and refuses. A Gemini resumable upload is tracked only when one request carries
the whole file from offset 0; chunked uploads keep today's handling and are not tracked.

### R7. WebSocket

A WebSocket message is redacted in the relay without a fetcher. References in one refuse it under
`inline` and `refuse`; agents that use the Realtime API or the Responses WebSocket mode send images
inline.

## Risks / Trade-offs

- scrim makes outbound requests on an agent's behalf. The address rules and the upstream proxy
  bound where; an operator who allows a private network accepts that an agent can make scrim read
  it.
- A URL that needs the agent's credentials (a signed request) fails: scrim sends none. Presigned
  URLs work.
- Bodies grow by the base64 of the fetched content, against provider request limits.

## Latency

Requests without references pay for an empty reference list and one `Arc` clone per request.
`latency_gate` (`SCRIM_PERF_ONLY=overhead,request`, production engine, 1,000 secrets shown), run
alternately on `origin/main` and this branch on the same machine, two rounds each:

| body | main p50 | branch p50 | main p99 | branch p99 |
| --- | ---: | ---: | ---: | ---: |
| 100 KB | 2.89 / 3.04 ms | 2.99 / 2.85 ms | 3.37 / 3.41 ms | 3.24 / 3.23 ms |
| 1 MB | 26.6 / 27.9 ms | 27.2 / 26.9 ms | 47.2 / 57.3 ms | 43.2 / 30.1 ms |
| 4 MB | 101.6 / 104.9 ms | 104.0 / 108.4 ms | 121.9 / 139.2 ms | 129.1 / 147.6 ms |

The p50 values are within run-to-run noise. The machine was shared with other builds, so the p99
tail moved in both directions on both trees: a 1 MB row went over the 60 ms p99 budget on both
(63.0 ms on `origin/main` with 10,000 secrets, 65.0 ms on the branch with 10), with p50 unchanged.
The gate in CI decides.
