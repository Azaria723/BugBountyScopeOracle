# Deployment and verification

## 1. Local gate

Run `pytest -q`. All tests must pass before deployment.

## 2. Publish the evidence snapshot

Commit `evidence/demo-policy.txt` to the final GitHub repository. Obtain:

- the 40-character commit SHA;
- the SHA-256 of the exact raw response bytes;
- the raw path `/OWNER/REPOSITORY/COMMIT/evidence/demo-policy.txt`.

Never use a branch such as `main` as the policy path. The commit must be immutable.

## 3. Deploy

Deploy `contracts/BugBountyScopeOracle.py` in GenLayer Studio. The deployment wallet becomes the registry owner.

## 4. Register the demo program

Call `register_program` with:

1. `program_key`: `BB-DEMO`
2. `represented_domain`: `example.com`
3. `source_host`: `raw.githubusercontent.com`
4. `policy_path`: the immutable raw path from step 2
5. `policy_sha256`: the exact digest from step 2

The expected return value is program ID `0`.

## 5. Positive and negative checks

Positive:

1. `request_scope_check(0, "api.example.com")`
2. `assess_scope(0)`
3. Expect `IN_SCOPE`; inspect `get_check(0)` and confirm digest and identity are `MATCH`.

Negative:

1. `request_scope_check(0, "example.com.attacker.org")`
2. `assess_scope(1)`
3. Expect `OUT_OF_SCOPE`.

Default exclusion:

1. Request `unknown.example.com`.
2. Assess it.
3. Expect `OUT_OF_SCOPE`, because the demo policy explicitly excludes every unlisted hostname.

An `AMBIGUOUS` on-chain case requires registering a separate policy snapshot that is conflicting or silent about unlisted assets. Do not claim ambiguity for the supplied demo policy.

## 6. Evidence to retain

Record the repository commit, contract address, source-parity hash, register transaction, all three assessment transactions, and returned `get_check` JSON. A finalized transaction alone is insufficient; retain the semantic return value and stored state.
