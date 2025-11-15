# app.py - Safe Chat (clean, fixed version)
import os
import json
import hashlib
import base64
from datetime import datetime
import secrets

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet
eventlet.monkey_patch()

# Optional: import encryption helpers you added earlier
# If you used the encryption.py from earlier messages, it exposes:
# generate_rsa_keypair, serialize_public_key, serialize_private_key, encrypt_private_key_pem, encrypt_with_public_key_bytes
from encryption import (
    generate_rsa_keypair,
    serialize_public_key,
    serialize_private_key,
    encrypt_private_key_pem,
    encrypt_with_public_key_bytes
)

# ---------- Configuration ----------
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
INVITES_FILE = os.path.join(DATA_DIR, "invites.json")
ADMIN_USERNAME = "roxter"
ADMIN_PASSWORD = "roxter101"   # change before deploying

# ---------- Ensure data files exist ----------
os.makedirs(DATA_DIR, exist_ok=True)
for path, default in [(USERS_FILE, {}), (INVITES_FILE, {"codes": {}})]:
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f, indent=2)

# ---------- Helpers ----------
def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ---------- Flask & SocketIO ----------
app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret"
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True)

# map user_id -> sid for connected users
connected_users = {}

# ---------- Routes: Home / Register / Login / Dashboard ----------
@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # If client submits via JSON (AJAX) allow that as well as form
        if request.is_json:
            data = request.get_json()
            user_id = data.get("user_id", "").strip()
            password = data.get("password", "")
            public_pem = data.get("public_key", "")
            private_enc_b64 = data.get("private_key_enc", "")
        else:
            user_id = request.form.get("user_id", "").strip()
            password = request.form.get("password", "")
            public_pem = request.form.get("public_key", "")
            private_enc_b64 = request.form.get("private_key_enc", "")

        if not user_id or not password:
            flash("Missing fields.", "danger")
            return redirect(url_for("register"))

        users = load_json(USERS_FILE) or {}
        invites_raw = load_json(INVITES_FILE) or {}
        codes = invites_raw.get("codes", invites_raw)

        invite_code = request.form.get("invite_code", "") if not request.is_json else data.get("invite_code", "")
        if not invite_code or invite_code not in codes or codes[invite_code].get("used", True):
            flash("Invalid or expired invite code!", "danger")
            return redirect(url_for("register"))

        if user_id in users:
            flash("User ID already exists.", "danger")
            return redirect(url_for("register"))

        # store password hash (sha256) for authentication
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        # store public key and encrypted private key (as base64 string) — server never decrypts
        users[user_id] = {
            "password": pw_hash,
            "public_key": public_pem,
            "private_key_enc": private_enc_b64,
            "inbox": []
        }

        # mark invite used
        codes[invite_code]["used"] = True
        if "codes" in invites_raw:
            invites_raw["codes"] = codes
        else:
            invites_raw = codes

        save_json(USERS_FILE, users)
        save_json(INVITES_FILE, invites_raw)

        flash("Registration successful. Now login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")

        users = load_json(USERS_FILE) or {}
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        if user_id in users and users[user_id].get("password") == pw_hash:
            session["user_id"] = user_id
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    users = load_json(USERS_FILE) or {}
    # peers: list of other users and their public keys (do not include private info)
    peers = {uid: {"public_key": users[uid].get("public_key")} for uid in users if uid != user_id}
    return render_template("dashboard.html", user_id=user_id, peers=peers)


@app.route("/user/logout", methods=["POST"])
def user_logout():
    session.pop("user_id", None)
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route('/admin/promote/<user_id>', methods=['POST'])
def promote_user(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    users = load_json(USERS_FILE)
    if user_id in users:
        users[user_id]['role'] = 'inviter'
        save_json(USERS_FILE, users)
    return redirect(url_for('admin_panel'))

# Endpoint: return encrypted private key blob for the logged-in user
@app.route("/get_encrypted_private", methods=["POST"])
def get_encrypted_private():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "not logged in"}), 401
    users = load_json(USERS_FILE) or {}
    enc = users.get(user_id, {}).get("private_key_enc")
    return jsonify({"private_key_enc": enc})


# Public key fetch API
@app.route("/public_key/<uid>")
def public_key(uid):
    users = load_json(USERS_FILE) or {}
    if uid in users:
        return jsonify({"public_key": users[uid].get("public_key")})
    return jsonify({"error": "user not found"}), 404

@app.route('/group/create', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = session['user_id']
    users = load_json(USERS_FILE)
    if users[user].get('role') not in ['admin', 'inviter']:
        return "Unauthorized", 403

    data = request.json
    group_name = data['group_name']
    members = data['members']

    groups = load_json('data/groups.json')
    gid = f"group-{len(groups)+1}"
    groups[gid] = {
        "name": group_name,
        "members": members,
        "created_by": user,
        "messages": []
    }
    save_json('data/groups.json', groups)
    return jsonify({"status": "created", "group_id": gid})

# ---------- Socket.IO handlers ----------
@socketio.on("connect")
def on_connect():
    # Register connection with user_id from session
    try:
        uid = session.get("user_id")
        if uid:
            sid = request.sid if hasattr(request, "sid") else None
            connected_users[uid] = request.sid
            join_room(uid)
            print(f"{uid} connected (sid {request.sid})")
    except Exception as e:
        print("connect error:", e)


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    for uid, s in list(connected_users.items()):
        if s == sid:
            del connected_users[uid]
            leave_room(uid)
            print(f"{uid} disconnected")
            break


@socketio.on("send_message")
def handle_send_message(data):
    sender = session.get("user_id")
    if not sender:
        emit("error", {"error":"Not authenticated"})
        return

    recipient = data.get("to")
    ct_b64 = data.get("message")  # now ciphertext
    if not recipient or not ct_b64:
        emit("error", {"error":"invalid payload"})
        return

    users = load_json(USERS_FILE) or {}
    if recipient not in users:
        emit("error", {"error":"Recipient not found"})
        return

    # store ciphertext in inbox
    users[recipient].setdefault("inbox", []).append({"from": sender, "ct": ct_b64})
    save_json(USERS_FILE, users)

    # forward to recipient room
    socketio.emit("receive_message", {"from": sender, "ct": ct_b64}, room=recipient)
    emit("sent", {"to": recipient})

    socketio.emit('user_expelled', {'user_id': user_id})
    
# ---------- Admin routes ----------
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'roxter' and password == 'roxter101':
            session['admin'] = True
            flash("Welcome, Admin!", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid admin credentials!", "error")
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin/panel', methods=['GET', 'POST'])
def admin_panel():
    if not session.get('admin'):
        flash("You must log in as admin first.", "error")
        return redirect(url_for('admin_login'))

    with open(INVITES_FILE, 'r') as f:
        invites = json.load(f)

    if request.method == 'POST':
        code = "INVITE-" + os.urandom(4).hex().upper()
        invites.setdefault("codes", {})
        invites["codes"][code] = {
            "created_by": "admin",
            "used": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        with open(INVITES_FILE, 'w') as f:
            json.dump(invites, f, indent=2)
        flash(f"New invite code {code} generated!", "success")

    return render_template('admin_panel.html', invites=invites.get("codes", invites))

@app.route('/admin/expel/<user_id>', methods=['POST'])
def expel_user(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    users = load_json(USERS_FILE)
    if user_id in users:
        del users[user_id]
        save_json(USERS_FILE, users)
    return redirect(url_for('admin_panel'))

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session.pop('admin', None)
    flash("Admin logged out successfully!", "info")
    return redirect(url_for('admin_login'))


# ---------- Run ----------
if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
