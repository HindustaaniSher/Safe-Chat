<script>
// ---------- helper functions ----------
function ab2str(buf){ return new TextDecoder().decode(buf); }
function str2ab(str){ return new TextEncoder().encode(str); }
function b64enc(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64dec(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }

// export CryptoKey to PEM
async function exportPublicKeyToPEM(pubKey) {
  const spki = await crypto.subtle.exportKey("spki", pubKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return "-----BEGIN PUBLIC KEY-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----\n";
}

async function exportPrivateKeyPKCS8(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
}

// derive AES-GCM key from password using PBKDF2
async function deriveKeyFromPassword(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw", str2ab(password), {name:"PBKDF2"}, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey({
    name: "PBKDF2",
    salt: salt,
    iterations: 200_000,
    hash: "SHA-256"
  }, baseKey, { name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
}

// encrypt private key PKCS8 (base64) with AES-GCM and return JSON blob
async function encryptPrivateKeyWithPassword(pkcs8_b64, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password, salt);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, str2ab(pkcs8_b64));
  return {
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
    ct: btoa(String.fromCharCode(...new Uint8Array(ct)))
  };
}

// main registration flow
async function doRegister(userId, password, inviteCode) {
  // generate RSA keypair (RSA-OAEP 2048)
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash:"SHA-256" },
    true, ["encrypt","decrypt"]
  );

  // export keys
  const publicPem = await exportPublicKeyToPEM(keyPair.publicKey);   // PEM string
  const privatePkcs8_b64 = await exportPrivateKeyPKCS8(keyPair.privateKey); // base64 string

  // encrypt private key with password
  const private_enc = await encryptPrivateKeyWithPassword(privatePkcs8_b64, password);
  // send user_id, password (raw; server will hash), publicPem, private_enc JSON to server
  const payload = {
    user_id: userId,
    password: password,
    public_key: publicPem,
    private_key_enc: JSON.stringify(private_enc),
    invite_code: inviteCode
  };

  const res = await fetch("/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (res.redirected) {
    window.location = res.url; // go to login
  } else {
    const text = await res.text();
    alert("Register failed: " + text);
  }
}
</script>
