<script>
async function importPublicKeyFromPem(pem) {
  // convert PEM -> ArrayBuffer SPKI
  const b64 = pem.replace(/-----.*?-----/g, "").replace(/\s+/g, "");
  const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
  return crypto.subtle.importKey("spki", binary, {name:"RSA-OAEP", hash:"SHA-256"}, true, ["encrypt"]);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// send: encrypt plaintext with recipient public key (WebCrypto)
async function sendEncryptedTo(toUserId, plaintext) {
  // fetch recipient public key from server
  const res = await fetch(`/public_key/${encodeURIComponent(toUserId)}`);
  if (res.status !== 200) { alert("Recipient not found"); return; }
  const json = await res.json();
  const public_pem = json.public_key;
  const pubKey = await importPublicKeyFromPem(public_pem);

  // encrypt plaintext (UTF-8)
  const pt = new TextEncoder().encode(plaintext);
  const ct = await crypto.subtle.encrypt({name:"RSA-OAEP"}, pubKey, pt);
  const ct_b64 = arrayBufferToBase64(ct);

  // emit via socket
  socket.emit('send_message', { to: toUserId, message: ct_b64 });

  // show in UI
  appendMsg(`[you -> ${toUserId}] ${plaintext}`, "me");
}

// on receive: decrypt ciphertext with myPrivateCryptoKey
socket.on('receive_message', async data => {
  const from = data.from;
  const ct_b64 = data.ct;
  try {
    if (!myPrivateCryptoKey) {
      appendMsg(`[encrypted] from ${from}: (locked, unlock to read)`, "them");
      return;
    }
    const ct_buf = base64ToArrayBuffer(ct_b64);
    const pt_buf = await crypto.subtle.decrypt({name:"RSA-OAEP"}, myPrivateCryptoKey, ct_buf);
    const plaintext = new TextDecoder().decode(pt_buf);
    appendMsg(`[${from}] ${plaintext}`, "them");
  } catch (e) {
    console.error("Decrypt error", e);
    appendMsg(`[encrypted] from ${from}: (failed to decrypt)`, "them");
  }
});
</script>
