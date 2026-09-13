import assert from "node:assert/strict";
import test from "node:test";
import { SOLANA_DEVNET_NETWORK, requireLoopbackEndpoint } from "../src/constants.mjs";
import { settlementToTibaEvidence } from "../src/evidence.mjs";

const signature = "5".repeat(88);

test("turns a settled Solana-devnet response into Tiba evidence", () => {
  const evidence = settlementToTibaEvidence({
    success: true,
    network: SOLANA_DEVNET_NETWORK,
    transaction: signature,
  });

  assert.deepEqual(evidence, {
    type: "solana_transaction",
    network: "solana-devnet",
    reference: signature,
    url: `https://explorer.solana.com/tx/${signature}?cluster=devnet`,
  });
});

test("refuses a settlement outside Solana devnet", () => {
  assert.throws(
    () => settlementToTibaEvidence({ success: true, network: "solana:mainnet", transaction: signature }),
    /not on Solana devnet/,
  );
});

test("refuses a missing or fabricated transaction reference", () => {
  assert.throws(
    () => settlementToTibaEvidence({ success: true, network: SOLANA_DEVNET_NETWORK, transaction: "not-a-signature" }),
    /usable Solana transaction signature/,
  );
});

test("client endpoint is restricted to loopback", () => {
  assert.equal(requireLoopbackEndpoint("http://127.0.0.1:4021/paid").hostname, "127.0.0.1");
  assert.equal(requireLoopbackEndpoint("http://localhost:4021/paid").hostname, "localhost");
  assert.throws(() => requireLoopbackEndpoint("https://example.com/paid"), /local loopback/);
});
