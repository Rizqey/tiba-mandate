import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import {
  DEFAULT_PORT,
  FACILITATOR_URL,
  LOCAL_HOST,
  PAID_PATH,
  PRICE,
  SOLANA_DEVNET_NETWORK,
  SOLANA_DEVNET_RPC,
  requireRuntimeEnv,
} from "./constants.mjs";

const payTo = requireRuntimeEnv("TIBA_X402_PAY_TO");
const port = Number.parseInt(process.env.TIBA_X402_PORT ?? String(DEFAULT_PORT), 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("TIBA_X402_PORT must be a valid local TCP port");
}

// The network and facilitator are deliberately constants: this proof must not
// become a mainnet or paid-facilitator integration through an environment typo.
const facilitator = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
const resourceServer = new x402ResourceServer(facilitator).register(
  SOLANA_DEVNET_NETWORK,
  // No environment override: this proof may only query the public Solana
  // devnet RPC and cannot be pointed at a mainnet endpoint.
  new ExactSvmScheme({ rpcUrl: SOLANA_DEVNET_RPC }),
);

const app = express();
app.disable("x-powered-by");

app.get("/health", (_request, response) => {
  response.json({ ok: true, network: SOLANA_DEVNET_NETWORK, facilitator: FACILITATOR_URL });
});

app.use(
  paymentMiddleware(
    {
      [`GET ${PAID_PATH}`]: {
        accepts: [
          {
            scheme: "exact",
            price: PRICE,
            network: SOLANA_DEVNET_NETWORK,
            payTo,
          },
        ],
        description: "Tiba local x402 devnet proof",
        mimeType: "application/json",
      },
    },
    resourceServer,
  ),
);

app.get(PAID_PATH, (_request, response) => {
  response.json({
    delivered: true,
    proof: "Tiba local x402 devnet endpoint",
    network: SOLANA_DEVNET_NETWORK,
  });
});

app.listen(port, LOCAL_HOST, () => {
  console.log(`x402 proof endpoint listening on http://${LOCAL_HOST}:${port}${PAID_PATH}`);
});
