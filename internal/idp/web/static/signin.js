"use strict";
// Passkey sign-in: get a challenge, have the browser sign it, post the
// assertion back. The server checks everything; this only moves bytes.

const b64url = {
  encode(buf) {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(s) {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  },
};

async function post(path, body) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `Sign-in failed (${resp.status}).`);
  return data;
}

async function signIn() {
  const begin = await post("/signin/begin", {});
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: b64url.decode(begin.challenge),
      rpId: begin.rpId,
      timeout: begin.timeout,
      userVerification: "required",
    },
  });
  const r = cred.response;
  await post("/signin/finish", {
    id: begin.id,
    credentialId: b64url.encode(cred.rawId),
    authenticatorData: b64url.encode(r.authenticatorData),
    clientDataJSON: b64url.encode(r.clientDataJSON),
    signature: b64url.encode(r.signature),
  });
}

const button = document.getElementById("signin");
const status = document.getElementById("status");

button.addEventListener("click", async () => {
  button.disabled = true;
  status.className = "";
  status.textContent = "Waiting for your passkey…";
  try {
    await signIn();
    // The server rendered next after checking it's a path on this host.
    location.assign(button.dataset.next);
  } catch (e) {
    status.className = "error";
    status.textContent =
      e.name === "NotAllowedError" ? "Cancelled or timed out. Try again." : e.message;
    button.disabled = false;
  }
});
