import os
import datetime
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
from functools import wraps

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")
db_url = os.getenv("DATABASE_URL", "")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

ADMIN_USER = os.getenv("ADMIN_USER", "admin")

frontend_url = os.getenv("FRONTEND_URL", "*")
CORS(app, origins=[frontend_url] if frontend_url != "*" else "*")

db = SQLAlchemy(app)

# ── Models (prefixed to avoid conflicts with other apps on same DB) ──
class User(db.Model):
    __tablename__ = "unstuck_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    progress = db.relationship("UserProgress", backref="user", uselist=False, cascade="all, delete-orphan")

class UserProgress(db.Model):
    __tablename__ = "unstuck_progress"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("unstuck_users.id"), unique=True, nullable=False, index=True)
    data = db.Column(db.JSON, nullable=False, default=dict)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Card(db.Model):
    __tablename__ = "unstuck_cards"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, unique=True, nullable=False, index=True)
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ── Auth helpers ──
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_pw(pw, hashed):
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))

def make_token(uid, is_admin=False):
    return jwt.encode(
        {"user_id": uid, "is_admin": is_admin, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=90)},
        app.config["SECRET_KEY"], algorithm="HS256"
    )

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token required"}), 401
        try:
            data = jwt.decode(auth.split(" ")[1], app.config["SECRET_KEY"], algorithms=["HS256"])
            user = User.query.get(data["user_id"])
            if not user:
                return jsonify({"error": "User not found"}), 401
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token required"}), 401
        try:
            data = jwt.decode(auth.split(" ")[1], app.config["SECRET_KEY"], algorithms=["HS256"])
            user = User.query.get(data["user_id"])
            if not user or not user.is_admin:
                return jsonify({"error": "Admin access required"}), 403
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(user, *args, **kwargs)
    return decorated

# ── Auth routes ──
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "cards": Card.query.count()})

@app.route("/api/auth/register", methods=["POST"])
def register():
    body = request.get_json()
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    if not username or len(username) < 3:
        return jsonify({"error": "Username min 3 characters"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password min 4 characters"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409
    is_admin = (username == ADMIN_USER.lower())
    user = User(username=username, password_hash=hash_pw(password), is_admin=is_admin)
    db.session.add(user)
    db.session.flush()
    db.session.add(UserProgress(user_id=user.id, data={}))
    db.session.commit()
    return jsonify({"token": make_token(user.id, is_admin), "username": username, "is_admin": is_admin}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.get_json()
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    user = User.query.filter_by(username=username).first()
    if not user or not check_pw(password, user.password_hash):
        return jsonify({"error": "Invalid username or password"}), 401
    return jsonify({"token": make_token(user.id, user.is_admin), "username": username, "is_admin": user.is_admin})

# ── Progress routes ──
@app.route("/api/progress", methods=["GET"])
@token_required
def get_progress(user):
    if not user.progress or not user.progress.data:
        return jsonify({"data": None})
    return jsonify({"data": user.progress.data})

@app.route("/api/progress", methods=["POST"])
@token_required
def save_progress(user):
    data = (request.get_json() or {}).get("data")
    if data is None:
        return jsonify({"error": "Missing data"}), 400
    if not user.progress:
        db.session.add(UserProgress(user_id=user.id, data=data))
    else:
        db.session.execute(
            db.text("UPDATE unstuck_progress SET data = :data, updated_at = NOW() WHERE user_id = :uid"),
            {"data": json.dumps(data), "uid": user.id}
        )
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/reset", methods=["POST"])
@token_required
def reset_progress(user):
    if user.progress:
        user.progress.data = {}
        db.session.commit()
    return jsonify({"ok": True})

# ── Cards routes (public read) ──
@app.route("/api/cards", methods=["GET"])
def get_cards():
    cards = Card.query.order_by(Card.card_id).all()
    return jsonify({"cards": [{**c.data, "id": c.card_id} for c in cards], "count": len(cards)})

# ── Admin routes ──
@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats(user):
    return jsonify({
        "total_users": User.query.count(),
        "total_cards": Card.query.count(),
        "active_users": UserProgress.query.filter(UserProgress.data != {}).count(),
    })

@app.route("/api/admin/cards", methods=["GET"])
@admin_required
def admin_list_cards(user):
    cards = Card.query.order_by(Card.card_id).all()
    return jsonify({"cards": [{"card_id": c.card_id, "phrase": c.data.get("phrase", ""), "created_at": c.created_at.isoformat() if c.created_at else None} for c in cards], "count": len(cards)})

@app.route("/api/admin/cards/upload", methods=["POST"])
@admin_required
def admin_upload_cards(user):
    body = request.get_json()
    cards_data = body.get("cards", [])
    if not isinstance(cards_data, list) or not cards_data:
        return jsonify({"error": "Expected non-empty 'cards' array"}), 400
    required = ["id", "phrase", "context", "meaning", "meaningEn", "usage", "wrongOptions", "fillBlank", "fillAnswer", "rearrange"]
    errors = []
    for i, c in enumerate(cards_data):
        missing = [f for f in required if f not in c or c[f] is None]
        if missing:
            errors.append(f"Card {i} (id={c.get('id','?')}): missing {', '.join(missing)}")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for c in cards_data:
        cid = c["id"]
        blob = {k: v for k, v in c.items() if k != "id"}
        existing = Card.query.filter_by(card_id=cid).first()
        if existing:
            existing.data = blob
            # Force JSON update detection
            db.session.execute(
                db.text("UPDATE unstuck_cards SET data = :data WHERE card_id = :cid"),
                {"data": json.dumps(blob), "cid": cid}
            )
            updated += 1
        else:
            db.session.add(Card(card_id=cid, data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": Card.query.count()})

@app.route("/api/admin/cards/<int:card_id>", methods=["DELETE"])
@admin_required
def admin_delete_card(user, card_id):
    card = Card.query.filter_by(card_id=card_id).first()
    if not card:
        return jsonify({"error": f"Card {card_id} not found"}), 404
    db.session.delete(card)
    db.session.commit()
    return jsonify({"ok": True, "deleted": card_id})

@app.route("/api/admin/cards/delete-all", methods=["POST"])
@admin_required
def admin_delete_all(user):
    count = Card.query.delete()
    db.session.commit()
    return jsonify({"ok": True, "deleted": count})

# ── Seed ──
def seed_cards():
    if Card.query.count() > 0:
        return
    seed_path = os.path.join(os.path.dirname(__file__), "seed_cards.json")
    if not os.path.exists(seed_path):
        print("No seed_cards.json found — database starts empty. Upload cards via admin.")
        return
    with open(seed_path, "r") as f:
        cards = json.load(f)
    for c in cards:
        cid = c.pop("id")
        db.session.add(Card(card_id=cid, data=c))
    db.session.commit()
    print(f"Seeded {len(cards)} cards")

with app.app_context():
    db.create_all()
    seed_cards()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
