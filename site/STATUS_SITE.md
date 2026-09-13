# Tiba public site

## What is on the page

- Plain-language hero: permission slip first, signed receipt after.
- Three-step permission → guarded action → verifiable receipt flow.
- The verified six-step public run from 13 September 2026, including four collapsible signed receipt artifacts and the real Solana devnet transaction link.
- A local browser check for a receipt’s Ed25519 signatures and did:key signer. It starts with a real receipt and includes a tampered example that fails.
- Developer quickstart, TypeScript and Python verifier references, a rendered v0.1 specification, and the three JSON schemas.
- How Tiba sits next to AP2, x402, Visa TAP, MCP, and A2A.
- Honest v0.1 / test-network limits, light and dark themes, and the requested footer.

## Preview

From the repository root:

~~~powershell
npx serve site
~~~

Then open the URL it prints. You can also open site/index.html directly in a current browser.

## Validation

- site/shots/index-1280.png — headless Chrome desktop capture.
- site/shots/index-400.png — headless Chrome 400 px device-emulated capture.
- The pre-filled real receipt verified successfully in Chrome at both widths. A changed signed field failed verification.
