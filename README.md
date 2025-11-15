# Safe Chat (Prototype)

Simple Flask + Socket.IO secure chat prototype with client-side end-to-end encryption (E2EE).  
Users register invite-only, generate keys in the browser, and messages are encrypted client-side.

## Features
- Invite-only registration (admin panel)
- Client-side RSA keypair generation (WebCrypto)
- Private keys encrypted with password before upload (AES-GCM via PBKDF2)
- Real end-to-end encryption: messages encrypted with recipient public key in browser and decrypted locally
- Real-time messaging with Socket.IO
- Light / Dark theme

## Run locally
   ```bash
   git clone https://github.com/HindustaaniSher/Safe-Chat.git
   cd Safe-Chat
   python3 -m venv venv
   source venv/bin/activate
   python3 app.py```
   # visit locally on `http://127.0.0.1:5000`
   # admin username and pass are `roxter` and `roxter101` respectively
Now, you can register users and can have two or more active user panels by login in as different users on various ecognito or private tabs.

## Note
- I'll add working GUI based WebApp of this as `LiveApp` button, so there will be no need to run locally.
- I'll add a `requirements.txt` file to download the required resources.
- I'll add some more cool features like a pannel to promote, demote or expel users so either they can generate Invite Code or not.
- I'll commit many changes once I get rid of my `Sem Exam`.
