"use strict";
// Passkey sign-in, device approval and enrollment: get a challenge, have
// the browser sign it (or make a passkey over it), post the result back.
// The server checks everything; this only moves bytes. The button says
// where to post (data-begin, data-finish), whether to make a passkey
// (data-create, with data-token), which request it approves (data-code),
// and where to go after (data-next).

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
  if (!resp.ok) throw new Error(data.error || `Failed (${resp.status}).`);
  return data;
}

async function assert(d) {
  const begin = await post(d.begin, d.code ? { userCode: d.code } : {});
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: b64url.decode(begin.challenge),
      rpId: begin.rpId,
      timeout: begin.timeout,
      userVerification: "required",
    },
  });
  const r = cred.response;
  return post(d.finish, {
    id: begin.id,
    credentialId: b64url.encode(cred.rawId),
    authenticatorData: b64url.encode(r.authenticatorData),
    clientDataJSON: b64url.encode(r.clientDataJSON),
    signature: b64url.encode(r.signature),
  });
}

async function create(d) {
  const name = document.getElementById("name").value;
  const begin = await post(d.begin, { token: d.token, name });
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64url.decode(begin.challenge),
      rp: { id: begin.rpId, name: "sso" },
      user: { id: b64url.decode(begin.userId), name: begin.user, displayName: begin.user },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 only
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
      excludeCredentials: begin.exclude.map((id) => ({ type: "public-key", id: b64url.decode(id) })),
      timeout: begin.timeout,
    },
  });
  return post(d.finish, {
    id: begin.id,
    attestationObject: b64url.encode(cred.response.attestationObject),
    clientDataJSON: b64url.encode(cred.response.clientDataJSON),
  });
}

const button = document.getElementById("passkey");
const status = document.getElementById("status");

button.addEventListener("click", async () => {
  button.disabled = true;
  status.className = "";
  status.textContent = "Waiting for your passkey…";
  try {
    const d = button.dataset;
    const data = await ("create" in d ? create(d) : assert(d));
    if (data.snippet) {
      status.textContent = "Registered.";
      document.getElementById("actions").hidden = true;
      document.getElementById("snippet").textContent = data.snippet;
      document.getElementById("result").hidden = false;
      return;
    }
    if (data.message) {
      status.textContent = data.message;
      document.getElementById("actions").hidden = true;
      return;
    }
    // The server rendered next after checking it's a path on this host.
    location.assign(button.dataset.next);
  } catch (e) {
    status.className = "error";
    status.textContent =
      e.name === "NotAllowedError" ? "Cancelled or timed out. Try again."
      : e.name === "InvalidStateError" ? "This authenticator already has a passkey for you."
      : e.message;
    button.disabled = false;
  }
});
