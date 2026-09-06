# Threat model

## Protected properties

- A requester cannot choose the policy URL.
- A fetched policy must match its sealed byte digest.
- Policy identity markers must match the registered program.
- Invalid, unavailable, conflicting, or unrecognized evidence never becomes `IN_SCOPE`.
- Rejected writes do not advance counters or mutate existing records.

## Addressed attacks

- Contributor-selected JSON or HTTPS evidence.
- Hostname suffix confusion such as `example.com.attacker.org`.
- URL schemes, ports, paths, uppercase aliases, numeric hosts, and traversal payloads in hostname/path inputs.
- Policy content replacement after registration.
- A policy snapshot copied from another program.
- Prompt injection inside the fetched policy.
- Unknown model output and source/model exceptions.
- Non-owner program registration and duplicate program identities.

## Explicit limitations

- The owner-curated registry is a trust boundary.
- The contract interprets a sealed snapshot, not necessarily the latest live policy.
- HTTP redirect destination metadata is not asserted by this version; use immutable direct source URLs and verify hosting behavior operationally.
- DNS compromise, hosting-account compromise, validator/model failure, and legal authority are not solved by this contract.
- `IN_SCOPE` is informational and is not authorization to test or attack an asset.

