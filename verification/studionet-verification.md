# Studionet verification

Verified on 2026-09-06.

## Deployment and source parity

- Contract: `0xC6b6310B1f6e56B6D8e23F7785bd34bFCe7AFAB8`
- Explorer: https://explorer-studio.genlayer.com/address/0xC6b6310B1f6e56B6D8e23F7785bd34bFCe7AFAB8
- Chain ID: `61999`
- Local contract SHA-256: `937c2a5bbe5a32dc7bd0c6e9a38dd591f3b0e3fbf37b9e647e3eda8e0fcb2040`
- Deployed source SHA-256: `937c2a5bbe5a32dc7bd0c6e9a38dd591f3b0e3fbf37b9e647e3eda8e0fcb2040`
- Source parity: `true`

## Authority registration

The deployment owner registered program `BB-DEMO` using the immutable policy URL and digest documented in [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).

- Owner registration: `0x037f4ef00c2ff404f97d175547e6f9162f9152ed0d3942140fe26a7a96de4e2a`
- Registered controller: `0x64da1326d7788FF89326a9C8dbF374FCcb36B90B`
- Policy SHA-256: `8f881213721cdafc92386c50d8e364c699df74494ddc8c3d77575e8fe4d89c82`
- Raw policy returned HTTP `200`, `268` bytes, and the same SHA-256.

An attempted registration by non-owner `0x67A1A08Fc4cf7D05c859d0d3D8398a3A30B1677e` finalized without changing state, demonstrating the owner gate:

- Unauthorized registration: `0x97ad0b8dce52923f70574a6fcdfa6faba7ecd9283f4b804d2c435ff77728947a`

## Case 0 — explicit inclusion

- Asset: `api.example.com`
- Request: `0x3c621b421bd3970192599c10c2a17ed4a5ea3a1950b44f5faff8d9ee35ad2f42`
- Assessment: `0xa9ea28bbf45c95adbb90bf2e3b64925136a8685654eca531d65e1960f62e84f5`
- Stored verdict: `IN_SCOPE`
- Policy digest: `MATCH`
- Program identity: `MATCH`

## Case 1 — explicit exclusion

- Asset: `status.example.com`
- Request: `0x0e83d02993b25409bb4062b1365fdad20d740b21d96cc43fe8851f2e64033e95`
- Assessment: `0x505a3865b8e4ecf064135556099b3ebec7c209e4cb3cccace7c30589d273e629`
- Stored verdict: `OUT_OF_SCOPE`
- Policy digest: `MATCH`
- Program identity: `MATCH`

## Case 2 — lookalike suffix attack

- Asset: `example.com.attacker.org`
- Request: `0x32f221be5d01b1885a2e262ae2ce70687d39913592756d64ce481abdc668ef03`
- Assessment: `0x2bbfc5b4e4ee987fc61d9da464d1ba3b9604b545ab142f290d7496778b7c92cc`
- Stored verdict: `OUT_OF_SCOPE`
- Policy digest: `MATCH`
- Program identity: `MATCH`

## Final state

```json
{"check_count": 3, "program_count": 1}
```

All six lifecycle writes finalized. Each assessment was also verified through `get_check`, so this report does not infer success from transaction finalization alone. The runner aborts if a verdict differs from its expected value or if either evidence binding is not `MATCH`.

This is reproducible Studionet evidence, not a security audit or legal authorization to test an asset.
