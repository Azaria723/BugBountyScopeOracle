import { createClient } from "../../OpenSourceMicroBounty/frontend/node_modules/genlayer-js/dist/index.js";
import { studionet } from "../../OpenSourceMicroBounty/frontend/node_modules/genlayer-js/dist/chains/index.js";
import { TransactionStatus } from "../../OpenSourceMicroBounty/frontend/node_modules/genlayer-js/dist/types/index.js";
import { privateKeyToAccount } from "../../OpenSourceMicroBounty/frontend/node_modules/viem/_esm/accounts/index.js";

const contract = process.env.CONTRACT_ADDRESS;
const ownerKey = process.env.OWNER_PRIVATE_KEY;
const requesterKey = process.env.REQUESTER_PRIVATE_KEY || ownerKey;
if (!/^0x[0-9a-fA-F]{40}$/.test(contract || "")) throw new Error("Set CONTRACT_ADDRESS");
if (!ownerKey) throw new Error("Set OWNER_PRIVATE_KEY to the wallet that deployed the contract");

const account = (key) => privateKeyToAccount(key.startsWith("0x") ? key : `0x${key}`);
const owner = account(ownerKey);
const requester = account(requesterKey);
const reader = createClient({ chain: studionet });
const writer = (signer) => createClient({ chain: studionet, account: signer });
const transactions = [];

const read = async (functionName, args = []) => reader.readContract({ address: contract, functionName, args });
const parse = async (functionName, args = []) => JSON.parse(await read(functionName, args));
const write = async (signer, functionName, args = []) => {
  const hash = await writer(signer).writeContract({ address: contract, functionName, args });
  console.log(`${functionName}_tx=${hash}`);
  let receipt;
  for (let attempt = 1; attempt <= 18; attempt++) {
    try {
      receipt = await reader.waitForTransactionReceipt({ hash, status: TransactionStatus.FINALIZED });
      break;
    } catch (error) {
      if (attempt === 18) throw error;
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
  console.log(`${functionName}_status=${receipt.status_name || receipt.status}`);
  transactions.push({ functionName, hash });
  return hash;
};

const policyPath = "/Azaria723/BugBountyScopeOracle/247669210e425bd68858752665948170105a0354/evidence/demo-policy.txt";
const policyDigest = "8f881213721cdafc92386c50d8e364c699df74494ddc8c3d77575e8fe4d89c82";
const cases = [
  { asset: "api.example.com", expected: "IN_SCOPE" },
  { asset: "status.example.com", expected: "OUT_OF_SCOPE" },
  { asset: "example.com.attacker.org", expected: "OUT_OF_SCOPE" },
];

console.log(`contract=${contract}`);
console.log(`owner=${owner.address}`);
console.log(`requester=${requester.address}`);
let counts = await parse("get_counts");
console.log(`counts_before=${JSON.stringify(counts)}`);

if (counts.program_count === 0) {
  await write(owner, "register_program", [
    "BB-DEMO",
    "example.com",
    "raw.githubusercontent.com",
    policyPath,
    policyDigest,
  ]);
}

const program = await parse("get_program", [0n]);
if (program.program_key !== "BB-DEMO" || program.active !== 1 || program.policy_sha256 !== policyDigest) {
  throw new Error(`Unexpected program state: ${JSON.stringify(program)}`);
}
console.log(`program=${JSON.stringify(program)}`);

for (let index = 0; index < cases.length; index++) {
  const testCase = cases[index];
  counts = await parse("get_counts");
  if (counts.check_count <= index) {
    await write(requester, "request_scope_check", [0n, testCase.asset]);
  }
  let check = await parse("get_check", [BigInt(index)]);
  if (check.asset_host !== testCase.asset) throw new Error(`Unexpected asset at check ${index}: ${JSON.stringify(check)}`);
  if (check.status === 0) await write(requester, "assess_scope", [BigInt(index)]);
  check = await parse("get_check", [BigInt(index)]);
  console.log(`check_${index}=${JSON.stringify(check)}`);
  if (check.status !== 1 || check.verdict !== testCase.expected) {
    throw new Error(`Check ${index} expected ${testCase.expected}: ${JSON.stringify(check)}`);
  }
  const diagnostics = JSON.parse(check.diagnostics);
  if (diagnostics.policy_digest !== "MATCH" || diagnostics.identity !== "MATCH") {
    throw new Error(`Check ${index} evidence binding failed: ${check.diagnostics}`);
  }
}

console.log(`counts_after=${await read("get_counts")}`);
console.log(`transactions=${JSON.stringify(transactions)}`);

