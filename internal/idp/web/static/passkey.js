"use strict";
// Passkey sign-in and device approval: get a challenge, have the browser
// sign it, post the assertion back. The server checks everything; this only
// moves bytes. The button says where to post (data-begin, data-finish),
// which request it approves (data-code), and where to go after (data-next).

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

const button = document.getElementById("passkey");
const status = document.getElementById("status");

button.addEventListener("click", async () => {
  button.disabled = true;
  status.className = "";
  status.textContent = "Waiting for your passkey…";
  try {
    const data = await assert(button.dataset);
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
      e.name === "NotAllowedError" ? "Cancelled or timed out. Try again." : e.message;
    button.disabled = false;
  }
});
