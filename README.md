# PoC — Bull MCP `bull_fund_tokens` permit path: inflated permit value never checked, victim loses 999,900 tokens

## What it proves

`bull_fund_tokens` (gasless permit path) checks an EIP-2612 permit only for
`owner == me`, `spender` in the escrow allowlist, `value < 2**200`, and
`deadline` within 24h. It never compares the permit `value` against the
agreed sell amount — it never even asks what the agreed amount is (the tool
input is just a `quoteId`). A compromised/malicious API server returns a
permit for 1,000,000 tokens when the seller agreed to sell 100. The MCP
signs it and hands `v/r/s` to the server.

The theft then uses two on-chain facts, both verified while building this PoC:
1. EIP-2612 `permit()` is **permissionless** — anyone can submit the signed
   permit directly to the token. The relayer does that, setting
   `allowance[victim][escrow] = 1,000,000`.
2. `BullEscrow.fundTokensWithPermit` calls `permit(..., d.sellAmount, ...)` —
   the DEAL's amount, not the signed value — so a permit signed for 1,000,000
   can never execute through the escrow for the 100-token deal (the inner
   permit fails and is swallowed by `try/catch`; the first PoC attempt died
   exactly there, `TransferFailed`). But once the allowance exists on-chain,
   the escrow's `_pull` takes whatever the attacker's deal asks for: the
   server creates its own deal #2 (seller=victim, 999,900 tokens for 0.001
   ETH, buyer=attacker) and settles it with `fundTokensWithPermit` using the
   SAME permit signature — the inner permit fails (value + nonce mismatch),
   swallowed by `try/catch`, and `_pull` drains the 999,900 tokens on the
   leftover allowance.

Net: the victim's legit 100-token sale settles normally (buyer gets 100
tokens, victim gets 0.1 ETH minus fee) and the MCP reports
`"deposited_gasless"` success — while the victim silently loses the other
999,900 tokens for ~0 ETH.

Is this a separate finding from B-03 (SDK `fund()`, 2965389dfb)? Yes, by the
same standard this audit has applied all along (B-02 vs B-03 vs B-04 vs
B-07 vs B-08): different function/tool (`bull_fund_tokens` vs `fund()`),
different victim flow (gasless-permit seller via the MCP vs SDK seller),
different mechanism (EIP-2612 permit over-approval + leftover-allowance
reuse vs approve+fundTokens step swap), different fix location
(`bull-mcp.mjs` — verify the permit value against the agreed sell amount).
Fixing the SDK does not touch the MCP. The honest counter-consideration —
the theft still needs an attacker deal, as in B-03 — is stated in the draft
so the team can grade it.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start a fresh Anvil (Foundry) on port 8551
anvil --port 8551 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockERC20Permit` (minimal EIP-2612 token, in
   `chain/src/Mocks.sol`) and the **real** `BullEscrow` source (verbatim,
   verified on Sourcify chain 4663), etched at its production address
   `0xd685d39E…` because the MCP hardcodes the escrow allowlist; storage
   (`nextId = 1`, `_lock = 1`) restored with `anvil_setStorageAt`.
2. Victim (seller, MCP agent wallet) holds 1,000,000 tokens. Legit deal #1
   (sell 100 for 0.1 ETH) is created and the buyer pays 0.1 ETH.
3. The agent calls `bull_fund_tokens({ quoteId: "q1" })` through the **real**
   MCP, verbatim, over stdio JSON-RPC. The mock returns a permit with
   `value = 1,000,000`. The MCP signs it (all its checks pass) and calls
   `bull_deposit` with `v/r/s`.
4. The mock (malicious relayer) submits the permit directly to the token,
   settles deal #1, creates attacker deal #2, funds 0.001 ETH, and settles
   it with the reused permit signature.

## Result (verified 16 Nov 2026, reproduced twice on fresh Anvil)

```
MCP tools/call result: {"status":"deposited_gasless","dealId":"1","settled":true}
victim tokens after: 0 (agreed sale was 100)
attacker tokens after: 999900
buyer tokens after: 100 (legit deal #1: 100)
deal #2 on-chain: seller==victim? true | sellAmount: 999900 | status: Settled | buyerReceive==attacker? true
EXPLOITED
```

Diagnostic evidence in the mock log: the permit signature recovers to the
victim exactly (`permit recovered signer == victim`), i.e. the MCP really
signed a 1,000,000-token permit for a 100-token sale.

## Files

- `bull-mcp.mjs` — verbatim copy of https://www.bull.family/mcp/bull-mcp.mjs
  (sha256 `29110f7cd283c2adc2d60c09da2338eea0ebf40bcf8dc89231ce75c52a275b18`)
- `mock-mcp.mjs` — malicious mock Bull API + remote MCP + relayer (localhost
  only); signs fee quotes with the PoC-controlled feeSigner
- `run-poc.mjs` — the PoC driver (real MCP over stdio + real BullEscrow on Anvil)
- `chain/src/BullEscrow.sol` — verbatim BullEscrow source (Sourcify, 4663)
- `chain/src/Mocks.sol` — MockERC20 + MockERC20Permit (minimal EIP-2612) +
  AttackerLocker (unused here, carried over from the shared chain dir)
- `poc-result.json` — machine-readable result of the last run
- `chain/` is a real copy (verbatim BullEscrow source + mocks, with compiled
  artifacts under `chain/out/`, including `MockERC20Permit.json`);
  `node_modules/` is a symlink to `../open-buyerreceive-tamper/node_modules`
  (viem). Replace the symlink with a real `npm install` when publishing the
  PoC repo.

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (gist/repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
