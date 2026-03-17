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

class Passage(db.Model):
    __tablename__ = "unstuck_passages"
    id = db.Column(db.Integer, primary_key=True)
    passage_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    level = db.Column(db.String(5), nullable=False, index=True)
    topic = db.Column(db.String(100))
    title = db.Column(db.String(200))
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ExercisePool(db.Model):
    __tablename__ = "unstuck_exercise_pool"
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, nullable=False, index=True)
    exercise_type = db.Column(db.String(30), nullable=False)
    exercise_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class EncounterLog(db.Model):
    __tablename__ = "unstuck_encounter_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("unstuck_users.id"), nullable=False)
    card_id = db.Column(db.Integer, nullable=False)
    exercise_id = db.Column(db.String(50))
    passage_id = db.Column(db.String(50))
    encounter_type = db.Column(db.String(30), nullable=False)
    result = db.Column(db.String(20))
    response_time_ms = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    __table_args__ = (
        db.Index("idx_encounter_user_card", "user_id", "card_id"),
        db.Index("idx_encounter_user_passage", "user_id", "passage_id"),
    )

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

# ── Passages routes (public) ──
@app.route("/api/passages", methods=["GET"])
def list_passages():
    level = request.args.get("level")
    q = Passage.query
    if level:
        q = q.filter_by(level=level.upper())
    passages = q.order_by(Passage.id).all()
    return jsonify({"passages": [{"passage_id": p.passage_id, "title": p.title, "level": p.level, "topic": p.topic} for p in passages], "count": len(passages)})

# ── Encounter routes (auth required) ──
@app.route("/api/encounter", methods=["POST"])
@token_required
def log_encounter(user):
    body = request.get_json() or {}
    card_id = body.get("card_id")
    encounter_type = body.get("encounter_type")
    if card_id is None or not encounter_type:
        return jsonify({"error": "card_id and encounter_type required"}), 400
    entry = EncounterLog(
        user_id=user.id,
        card_id=card_id,
        exercise_id=body.get("exercise_id"),
        passage_id=body.get("passage_id"),
        encounter_type=encounter_type,
        result=body.get("result"),
        response_time_ms=body.get("response_time_ms"),
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify({"ok": True, "id": entry.id}), 201

@app.route("/api/encounters/<int:card_id>", methods=["GET"])
@token_required
def get_encounters(user, card_id):
    entries = EncounterLog.query.filter_by(user_id=user.id, card_id=card_id).order_by(EncounterLog.created_at.desc()).all()
    return jsonify({"encounters": [{"id": e.id, "exercise_id": e.exercise_id, "passage_id": e.passage_id, "encounter_type": e.encounter_type, "result": e.result, "response_time_ms": e.response_time_ms, "created_at": e.created_at.isoformat() if e.created_at else None} for e in entries]})

# ── Session composer ──
def compose_session(user):
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    card_stats = progress_data.get("cardStats", {})

    # Check if any passages exist at all
    if Passage.query.count() == 0:
        return {"type": "flashcard_only"}

    now = datetime.datetime.utcnow()

    # 1. Find phrases due for review (SRS interval expired)
    due_phrases = []
    for cid, stats in card_stats.items():
        interval = stats.get("interval", 1)
        last = stats.get("lastReview")
        if last:
            try:
                last_dt = datetime.datetime.fromisoformat(last.replace("Z", "+00:00")).replace(tzinfo=None)
                if (now - last_dt).days >= interval:
                    due_phrases.append(int(cid))
            except (ValueError, TypeError):
                due_phrases.append(int(cid))
        elif stats.get("mastery", 0) > 0:
            due_phrases.append(int(cid))

    # 2. Find suspect phrases (high mastery but few unique contexts)
    seen_passages_ids = [r[0] for r in db.session.query(EncounterLog.passage_id).filter(
        EncounterLog.user_id == user.id,
        EncounterLog.passage_id.isnot(None)
    ).distinct().all()]

    suspect = []
    for cid, stats in card_stats.items():
        if stats.get("mastery", 0) >= 3:
            unique_ctx = db.session.query(EncounterLog.passage_id).filter(
                EncounterLog.user_id == user.id,
                EncounterLog.card_id == int(cid),
                EncounterLog.passage_id.isnot(None)
            ).distinct().count()
            if unique_ctx < 2:
                suspect.append(int(cid))

    # 3. Pick target phrases (due first, then suspect, max 4)
    targets = []
    for cid in due_phrases:
        if cid not in targets and len(targets) < 4:
            targets.append(cid)
    for cid in suspect:
        if cid not in targets and len(targets) < 4:
            targets.append(cid)

    # 4. Find a passage at user's level containing target phrases, not yet read
    passage = None
    if targets:
        all_passages = Passage.query.filter_by(level=user_level.upper()).all()
        for p in all_passages:
            if p.passage_id in seen_passages_ids:
                continue
            phrase_card_ids = [tp["card_id"] for tp in (p.data.get("target_phrases") or [])]
            overlap = [cid for cid in targets if cid in phrase_card_ids]
            if overlap:
                passage = p
                targets = phrase_card_ids
                break

    # 5. If no passage matches targets, pick any unseen passage at user's level
    if not passage:
        all_passages = Passage.query.filter_by(level=user_level.upper()).all()
        for p in all_passages:
            if p.passage_id not in seen_passages_ids:
                passage = p
                targets = [tp["card_id"] for tp in (p.data.get("target_phrases") or [])]
                break

    # 6. If still no passage (all read or none at level), try any level
    if not passage:
        all_passages = Passage.query.all()
        for p in all_passages:
            if p.passage_id not in seen_passages_ids:
                passage = p
                targets = [tp["card_id"] for tp in (p.data.get("target_phrases") or [])]
                break

    # 7. Fallback: no unread passages at all
    if not passage:
        return {"type": "flashcard_only"}

    # 8. Pick exercise variations user hasn't seen for each target phrase
    seen_exercise_ids = [r[0] for r in db.session.query(EncounterLog.exercise_id).filter(
        EncounterLog.user_id == user.id,
        EncounterLog.exercise_id.isnot(None)
    ).distinct().all()]

    exercises = []
    for cid in targets:
        mastery = card_stats.get(str(cid), {}).get("mastery", 0)
        ex_type = exercise_type_for_mastery(mastery)
        # Try preferred type first, then any type, excluding seen exercises
        q = ExercisePool.query.filter(ExercisePool.card_id == cid, ExercisePool.exercise_type == ex_type)
        if seen_exercise_ids:
            q = q.filter(~ExercisePool.exercise_id.in_(seen_exercise_ids))
        ex = q.first()
        if not ex:
            q = ExercisePool.query.filter(ExercisePool.card_id == cid)
            if seen_exercise_ids:
                q = q.filter(~ExercisePool.exercise_id.in_(seen_exercise_ids))
            ex = q.first()
        if not ex:
            ex = ExercisePool.query.filter_by(card_id=cid).first()
        if ex:
            exercises.append({"exercise_id": ex.exercise_id, "card_id": ex.card_id, "exercise_type": ex.exercise_type, "data": ex.data})

    passage_out = {
        "passage_id": passage.passage_id,
        "level": passage.level,
        "topic": passage.topic,
        "title": passage.title,
        "data": passage.data,
    }

    return {
        "type": "mixed",
        "passage": passage_out,
        "exercises": exercises,
        "target_phrases": targets,
    }

def exercise_type_for_mastery(mastery):
    if mastery <= 1:
        return "fill_blank"
    elif mastery == 2:
        return "discrimination"
    elif mastery == 3:
        return "usage_boundary"
    elif mastery == 4:
        return "situation"
    else:
        return "verification"

@app.route("/api/session/compose", methods=["GET"])
@token_required
def session_compose(user):
    return jsonify(compose_session(user))

# ── Admin: Passages ──
@app.route("/api/admin/passages/upload", methods=["POST"])
@admin_required
def admin_upload_passages(user):
    body = request.get_json()
    passages_data = body.get("passages", [])
    if not isinstance(passages_data, list) or not passages_data:
        return jsonify({"error": "Expected non-empty 'passages' array"}), 400
    required = ["id", "level", "title", "text"]
    errors = []
    for i, p in enumerate(passages_data):
        missing = [f for f in required if f not in p or p[f] is None]
        if missing:
            errors.append(f"Passage {i} (id={p.get('id','?')}): missing {', '.join(missing)}")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for p in passages_data:
        pid = p["id"]
        blob = {k: v for k, v in p.items() if k not in ("id",)}
        existing = Passage.query.filter_by(passage_id=pid).first()
        if existing:
            existing.level = blob.get("level", existing.level)
            existing.topic = blob.get("topic", existing.topic)
            existing.title = blob.get("title", existing.title)
            existing.data = blob
            db.session.execute(
                db.text("UPDATE unstuck_passages SET data = :data, level = :level, topic = :topic, title = :title WHERE passage_id = :pid"),
                {"data": json.dumps(blob), "level": blob.get("level", ""), "topic": blob.get("topic", ""), "title": blob.get("title", ""), "pid": pid}
            )
            updated += 1
        else:
            db.session.add(Passage(passage_id=pid, level=blob.get("level", "B1"), topic=blob.get("topic"), title=blob.get("title"), data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": Passage.query.count()})

@app.route("/api/admin/passages", methods=["GET"])
@admin_required
def admin_list_passages(user):
    passages = Passage.query.order_by(Passage.id).all()
    return jsonify({"passages": [{
        "passage_id": p.passage_id, "title": p.title, "level": p.level, "topic": p.topic,
        "phrase_count": len(p.data.get("target_phrases", []) if p.data else []),
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in passages], "count": len(passages)})

@app.route("/api/admin/passages/<passage_id>", methods=["DELETE"])
@admin_required
def admin_delete_passage(user, passage_id):
    p = Passage.query.filter_by(passage_id=passage_id).first()
    if not p:
        return jsonify({"error": f"Passage {passage_id} not found"}), 404
    db.session.delete(p)
    db.session.commit()
    return jsonify({"ok": True, "deleted": passage_id})

# ── Admin: Exercise Pool ──
@app.route("/api/admin/exercises/upload", methods=["POST"])
@admin_required
def admin_upload_exercises(user):
    body = request.get_json()
    exercises_data = body.get("exercises", [])
    if not isinstance(exercises_data, list) or not exercises_data:
        return jsonify({"error": "Expected non-empty 'exercises' array"}), 400
    required = ["exercise_id", "card_id", "exercise_type"]
    errors = []
    for i, ex in enumerate(exercises_data):
        missing = [f for f in required if f not in ex or ex[f] is None]
        if missing:
            errors.append(f"Exercise {i} (id={ex.get('exercise_id','?')}): missing {', '.join(missing)}")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for ex in exercises_data:
        eid = ex["exercise_id"]
        existing = ExercisePool.query.filter_by(exercise_id=eid).first()
        blob = {k: v for k, v in ex.items() if k not in ("exercise_id", "card_id", "exercise_type")}
        if existing:
            existing.card_id = ex["card_id"]
            existing.exercise_type = ex["exercise_type"]
            existing.data = blob
            db.session.execute(
                db.text("UPDATE unstuck_exercise_pool SET card_id = :cid, exercise_type = :etype, data = :data WHERE exercise_id = :eid"),
                {"cid": ex["card_id"], "etype": ex["exercise_type"], "data": json.dumps(blob), "eid": eid}
            )
            updated += 1
        else:
            db.session.add(ExercisePool(exercise_id=eid, card_id=ex["card_id"], exercise_type=ex["exercise_type"], data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": ExercisePool.query.count()})

# ── Admin: Content Stats ──
@app.route("/api/admin/content-stats", methods=["GET"])
@admin_required
def admin_content_stats(user):
    return jsonify({
        "total_passages": Passage.query.count(),
        "total_exercises": ExercisePool.query.count(),
        "total_encounters": EncounterLog.query.count(),
        "passages_by_level": {level: count for level, count in db.session.query(Passage.level, db.func.count(Passage.id)).group_by(Passage.level).all()},
    })

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

def seed_passages():
    if Passage.query.count() > 0:
        return
    seed_path = os.path.join(os.path.dirname(__file__), "seed_passages.json")
    if not os.path.exists(seed_path):
        print("No seed_passages.json found — database starts empty. Upload passages via admin.")
        return
    with open(seed_path, "r") as f:
        passages = json.load(f)
    for p in passages:
        pid = p.pop("id")
        db.session.add(Passage(passage_id=pid, level=p.get("level", "B1"), topic=p.get("topic"), title=p.get("title"), data=p))
    db.session.commit()
    print(f"Seeded {len(passages)} passages")

with app.app_context():
    db.create_all()
    seed_cards()
    seed_passages()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
