(() => {
  "use strict";

  const run = window.TIBA_RUN;
  const root = document.documentElement;
  const themeButton = document.querySelector("#theme-toggle");
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  const receiptInput = document.querySelector("#receipt-input");
  const verifyForm = document.querySelector("#verify-form");
  const verifyButton = document.querySelector("#verify-button");
  const tamperButton = document.querySelector("#tamper-button");
  const verifyResult = document.querySelector("#verify-result");

  const viewerMap = {
    allowed: "#receipt-allowed",
    blocked: "#receipt-blocked",
    payment: "#receipt-payment",
    revoked: "#receipt-revoked"
  };

  function pretty(value) {
    return JSON.stringify(value, null, 2);
  }

  function populateRunArtifacts() {
    if (!run || !run.receipts) {
      document.querySelectorAll(".receipt-json").forEach((node) => {
        node.textContent = "The public run artifacts could not be loaded.";
      });
      return false;
    }

    Object.entries(viewerMap).forEach(([key, selector]) => {
      const node = document.querySelector(selector);
      if (node && run.receipts[key]) node.textContent = pretty(run.receipts[key]);
    });

    const verificationNode = document.querySelector("#independent-verification");
    if (verificationNode && run.independentVerification) {
      verificationNode.textContent = pretty(run.independentVerification);
    }

    receiptInput.value = pretty(run.receipts.allowed);
    return true;
  }

  function getResolvedTheme() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function syncThemeButton() {
    const isDark = getResolvedTheme() === "dark";
    themeButton.setAttribute("aria-pressed", String(isDark));
    themeButton.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
    if (themeMeta) themeMeta.setAttribute("content", isDark ? "#081514" : "#f4f8f7");
  }

  function setTheme(theme) {
    root.dataset.theme = theme;
    try {
      localStorage.setItem("tiba-theme", theme);
    } catch {
      // Theme preference is optional; the page still works if storage is unavailable.
    }
    syncThemeButton();
  }

  function initTheme() {
    try {
      const saved = localStorage.getItem("tiba-theme");
      if (saved === "light" || saved === "dark") root.dataset.theme = saved;
    } catch {
      // Fall back to the visitor's system preference.
    }
    syncThemeButton();
    themeButton.addEventListener("click", () => {
      setTheme(getResolvedTheme() === "dark" ? "light" : "dark");
    });
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (!root.dataset.theme) syncThemeButton();
    });
  }

  function setResult(state, title, message) {
    verifyResult.dataset.state = state;
    verifyResult.querySelector(".verify-result-icon").textContent =
      state === "success" ? "✓" : state === "error" ? "!" : "•";
    verifyResult.querySelector("strong").textContent = title;
    verifyResult.querySelector("p").textContent = message;
  }

  function isRecord(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
  }

  // JCS-compatible for the finite JSON values accepted by Tiba v0.1.
  function canonicalize(value) {
    if (value === null) return "null";
    if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error("The JSON has a non-finite number, which cannot be signed.");
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return "[" + value.map((item) => canonicalize(item)).join(",") + "]";
    if (!isRecord(value)) throw new Error("The JSON contains a value that cannot be canonicalized.");

    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonicalize(value[key])).join(",") + "}";
  }

  function base58Decode(input) {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (!input) throw new Error("The did:key is empty.");

    let number = 0n;
    for (const character of input) {
      const index = alphabet.indexOf(character);
      if (index < 0) throw new Error("The did:key is not base58btc.");
      number = number * 58n + BigInt(index);
    }

    const body = [];
    while (number > 0n) {
      body.unshift(Number(number & 255n));
      number >>= 8n;
    }

    let leadingZeroes = 0;
    while (leadingZeroes < input.length && input[leadingZeroes] === "1") leadingZeroes += 1;
    return new Uint8Array([...Array(leadingZeroes).fill(0), ...body]);
  }

  function publicKeyFromDid(did) {
    if (typeof did !== "string" || !did.startsWith("did:key:z")) {
      throw new Error("Tiba requires an Ed25519 did:key signer.");
    }
    const decoded = base58Decode(did.slice("did:key:z".length));
    if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Error("The did:key is not an Ed25519 public key.");
    }
    return decoded.slice(2);
  }

  function base64urlDecode(input) {
    if (typeof input !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(input)) {
      throw new Error("The receipt has no valid unpadded Ed25519 signature.");
    }
    const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "==";
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (bytes.length !== 64) throw new Error("The receipt signature is not 64 bytes.");
    return bytes;
  }

  function objectWithoutSignature(value) {
    return Object.fromEntries(Object.entries(value).filter(([key]) => key !== "signature"));
  }

  async function verifySignedObject(value, expectedDid, label) {
    if (!isRecord(value)) throw new Error(label + " is not a JSON object.");
    if (!isRecord(value.signature)) throw new Error(label + " is missing its signature.");
    const { alg, kid, value: signatureValue } = value.signature;

    if (alg !== "Ed25519") throw new Error(label + " does not declare Ed25519.");
    if (kid !== expectedDid) throw new Error(label + " signer does not match its required did:key.");

    const keyBytes = publicKeyFromDid(kid);
    const signatureBytes = base64urlDecode(signatureValue);
    const preimage = new TextEncoder().encode(canonicalize(objectWithoutSignature(value)));

    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("This browser does not expose Web Crypto. Try a current Chromium, Firefox, or Safari release.");
    }

    let key;
    try {
      key = await window.crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
    } catch {
      throw new Error("This browser does not support Ed25519 verification in Web Crypto.");
    }

    const verified = await window.crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, preimage);
    if (!verified) throw new Error(label + " signature did not verify.");
  }

  async function verifyReceipt(receipt) {
    if (!isRecord(receipt) || receipt.type !== "tiba.receipt" || receipt.version !== "0.1") {
      throw new Error("Paste a complete Tiba v0.1 receipt JSON object.");
    }
    if (typeof receipt.actor !== "string") throw new Error("The receipt is missing its actor did:key.");
    if (!Array.isArray(receipt.mandate_chain) || receipt.mandate_chain.length === 0) {
      throw new Error("The receipt has no mandate chain to check.");
    }

    for (let index = 0; index < receipt.mandate_chain.length; index += 1) {
      const mandate = receipt.mandate_chain[index];
      if (!isRecord(mandate) || typeof mandate.issuer !== "string") {
        throw new Error("Mandate " + (index + 1) + " is missing its issuer did:key.");
      }
      await verifySignedObject(mandate, mandate.issuer, "Mandate " + (index + 1));
    }

    const leaf = receipt.mandate_chain[receipt.mandate_chain.length - 1];
    if (!isRecord(leaf) || leaf.subject !== receipt.actor) {
      throw new Error("The receipt actor does not match the final mandate subject.");
    }

    await verifySignedObject(receipt, receipt.actor, "Receipt");
    return receipt.mandate_chain.length;
  }

  async function runVerification() {
    const value = receiptInput.value.trim();
    receiptInput.removeAttribute("aria-invalid");
    verifyButton.disabled = true;
    tamperButton.disabled = true;
    verifyForm.setAttribute("aria-busy", "true");
    setResult("loading", "Verifying locally…", "Checking Ed25519 signatures and embedded did:key signers in this browser.");

    try {
      const receipt = JSON.parse(value);
      const chainLength = await verifyReceipt(receipt);
      setResult(
        "success",
        "Signature valid",
        "The receipt and its " + chainLength + " embedded mandate " + (chainLength === 1 ? "signature" : "signatures") + " verify against their Ed25519 did:key signers. This confirms signature integrity only; it does not establish signer identity, trust, or current authorization."
      );
    } catch (error) {
      receiptInput.setAttribute("aria-invalid", "true");
      const message = error instanceof SyntaxError
        ? "That is not valid JSON. Fix the JSON and try again."
        : error instanceof Error
          ? error.message
          : "The receipt could not be verified.";
      setResult("error", "Verification failed", message);
    } finally {
      verifyButton.disabled = false;
      tamperButton.disabled = false;
      verifyForm.removeAttribute("aria-busy");
    }
  }

  function loadTamperedExample() {
    if (!run || !run.receipts || !run.receipts.allowed) return;
    const tampered = JSON.parse(JSON.stringify(run.receipts.allowed));
    tampered.result = "failure";
    receiptInput.value = pretty(tampered);
    void runVerification();
  }

  initTheme();
  if (populateRunArtifacts()) {
    void runVerification();
  }

  verifyForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void runVerification();
  });
  tamperButton.addEventListener("click", loadTamperedExample);
})();
