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

# ── Config ──
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

# CORS: allow your Vercel domain (set FRONTEND_URL in Railway env)
frontend_url = os.getenv("FRONTEND_URL", "*")
CORS(app, origins=[frontend_url] if frontend_url != "*" else "*")

db = SQLAlchemy(app)

# ── Models ──
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    progress = db.relationship("UserProgress", backref="user", uselist=False, cascade="all, delete-orphan")

class UserProgress(db.Model):
    __tablename__ = "user_progress"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False, index=True)
    data = db.Column(db.JSON, nullable=False, default=dict)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

# ── Auth ──
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_pw(pw, hashed):
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))

def make_token(uid):
    return jwt.encode(
        {"user_id": uid, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=90)},
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
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(user, *args, **kwargs)
    return decorated

# ── Routes ──
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/auth/register", methods=["POST"])
def register():
    body = request.get_json()
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409
    user = User(username=username, password_hash=hash_pw(password))
    db.session.add(user)
    db.session.flush()
    db.session.add(UserProgress(user_id=user.id, data={}))
    db.session.commit()
    return jsonify({"token": make_token(user.id), "username": username}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.get_json()
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    user = User.query.filter_by(username=username).first()
    if not user or not check_pw(password, user.password_hash):
        return jsonify({"error": "Invalid username or password"}), 401
    return jsonify({"token": make_token(user.id), "username": username})

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
            db.text("UPDATE user_progress SET data = :data, updated_at = NOW() WHERE user_id = :uid"),
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

# ── Init ──
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
