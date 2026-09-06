import { createClient } from "../../OpenSourceMicroBounty/frontend/node_modules/genlayer-js/dist/index.js";
import { studionet } from "../../OpenSourceMicroBounty/frontend/node_modules/genlayer-js/dist/chains/index.js";
import { createHash } from "node:crypto";

const contract = process.env.CONTRACT_ADDRESS;
const expectedHash = "937c2a5bbe5a32dc7bd0c6e9a38dd591f3b0e3fbf37b9e647e3eda8e0fcb2040";
if (!/^0x[0-9a-fA-F]{40}$/.test(contract || "")) throw new Error("Set CONTRACT_ADDRESS");

const client = createClient({ chain: studionet });
const schema = await client.getContractSchema(contract);
const code = await client.getContractCode(contract);
const sourceHash = createHash("sha256").update(code, "utf8").digest("hex");

console.log(`contract=${contract}`);
console.log(`chain_id=${studionet.id}`);
console.log(`schema_methods=${JSON.stringify(Object.keys(schema || {}).sort())}`);
console.log(`deployed_source_sha256=${sourceHash}`);
console.log(`expected_source_sha256=${expectedHash}`);
console.log(`source_parity=${sourceHash === expectedHash}`);
console.log(`counts=${await client.readContract({ address: contract, functionName: "get_counts", args: [] })}`);

