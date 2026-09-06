# BugBountyScopeOracle

BugBountyScopeOracle is a deliberately narrow GenLayer Intelligent Contract. It answers one question: **is a submitted hostname in scope under a registered bug-bounty policy?**

It has no frontend, token, escrow, or payout logic. The contract stores immutable policy-source coordinates, asks validators to retrieve and interpret that policy, and records one of four outcomes:

- `IN_SCOPE`
- `OUT_OF_SCOPE`
- `AMBIGUOUS`
- `UNAVAILABLE`

## Why GenLayer

Scope policies are natural-language documents. They contain explicit assets, exclusions, wildcard rules, and sometimes conflicting prose. A conventional deterministic contract cannot retrieve and interpret that changing off-chain text. GenLayer validators can, while strict equivalence commits one consensus result.

## Trust and evidence model

The contract owner curates the program registry. For each program it seals:

- a unique program key;
- the represented domain;
- an exact HTTPS source host and path;
- the expected SHA-256 of the policy bytes.

The requester supplies only `program_id` and `asset_host`; it cannot choose an evidence URL. Validators derive the URL, fetch it themselves, verify the digest, require `PROGRAM_ID` and `REPRESENTED_DOMAIN` markers, and only then invoke semantic classification. Any fetch, digest, identity, parsing, or model failure fails closed.

This proves a verdict against a curated policy snapshot. It does not prove that an arbitrary registry controller legally represents a company, so registry curation remains an explicit trust assumption.

## Public methods

### Writes

- `register_program(program_key, represented_domain, source_host, policy_path, policy_sha256)` — owner only.
- `deactivate_program(program_id)` — registered controller only.
- `request_scope_check(program_id, asset_host)` — creates a pending check.
- `assess_scope(check_id)` — validators fetch and classify the sealed policy.

### Views

- `get_counts()`
- `get_program(program_id)`
- `get_check(check_id)`

Hostnames must be lowercase DNS names without a scheme, port, path, wildcard, or trailing dot.

## Local verification

```bash
python -m pip install -r requirements.txt
pytest -q
```

The suite uses gltest Direct Mode with strict web and LLM mocks. It covers explicit inclusion, explicit exclusion, a proper wildcard subdomain, a lookalike suffix attack, policy silence, malformed model output, source outage, digest tampering, identity mismatch, unauthorized registration, duplicate registration, invalid URL-like hostnames, traversal paths, deactivation, and state preservation after rejected calls.

## Deployment

Deploy [`contracts/BugBountyScopeOracle.py`](contracts/BugBountyScopeOracle.py) as a new instance in GenLayer Studio. After deployment, follow [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). Do not register the demo snapshot until its final Git commit and SHA-256 have been substituted for the placeholders.

## Security boundary

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before using the contract. A recorded verdict is policy interpretation evidence, not permission to attack a system and not legal advice.

