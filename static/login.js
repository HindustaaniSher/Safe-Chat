<script>
let myPrivateCryptoKey = null; // in-memory CryptoKey for decrypting messages

function b64ToUint8Array(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
function uint8ArrayToStr(u8){ return new TextDecoder().decode(u8); }

async function importPrivateKeyFromPKCS8_b64(pkcs8_b64) {
  const pkcs8 = b64ToUint8Array(pkcs8_b64).buffer;
  return crypto.subtle.importKey("pkcs8", pkcs8, {
    name: "RSA-OAEP", hash: "SHA-256"
  }, true, ["decrypt"]);
}

async function decryptPrivateKeyBlobAndImport(enc_json, password) {
  // enc_json is {salt, iv, ct} as base64 strings
  const salt = b64ToUint8Array(enc_json.salt);
  const iv = b64ToUint8Array(enc_json.iv);
  const ct = b64ToUint8Array(enc_json.ct);

  const key = await deriveKeyFromPassword(password, salt); // reuse deriveKeyFromPassword from register.js (copy it into login.js too)
  const pt_bytes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  const pkcs8_b64 = new TextDecoder().decode(pt_bytes);
  const privKey = await importPrivateKeyFromPKCS8_b64(pkcs8_b64);
  myPrivateCryptoKey = privKey;
  return true;
}

// Called on dashboard load — user must enter password again to unlock private key
async function unlockPrivateKey(password) {
  const resp = await fetch("/get_encrypted_private", {method:"POST"});
  if (resp.status !== 200) { alert("Not logged in"); return; }
  const json = await resp.json();
  const enc_blob_str = json.private_key_enc;
  if (!enc_blob_str) { alert("No private key stored."); return; }
  const enc = JSON.parse(enc_blob_str);
  try {
    await decryptPrivateKeyBlobAndImport(enc, password);
    alert("Unlocked private key for this session.");
  } catch (e) {
    console.error(e);
    alert("Failed to decrypt private key. Wrong password?");
  }
}
</script>
