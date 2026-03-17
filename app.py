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

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

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

class ListeningExercise(db.Model):
    __tablename__ = "unstuck_listening"
    id = db.Column(db.Integer, primary_key=True)
    exercise_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    level = db.Column(db.String(5), nullable=False, index=True)
    exercise_type = db.Column(db.String(30), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class WritingPrompt(db.Model):
    __tablename__ = "unstuck_writing_prompts"
    id = db.Column(db.Integer, primary_key=True)
    prompt_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    level = db.Column(db.String(5), nullable=False, index=True)
    prompt_type = db.Column(db.String(30), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class WritingSubmission(db.Model):
    __tablename__ = "unstuck_writing_submissions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("unstuck_users.id"), nullable=False, index=True)
    prompt_id = db.Column(db.String(50), nullable=False)
    user_text = db.Column(db.Text, nullable=False)
    ai_feedback = db.Column(db.JSON)
    score = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ConversationScenario(db.Model):
    __tablename__ = "unstuck_scenarios"
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    level = db.Column(db.String(5), nullable=False, index=True)
    title = db.Column(db.String(200))
    data = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ConversationLog(db.Model):
    __tablename__ = "unstuck_conversations"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("unstuck_users.id"), nullable=False, index=True)
    scenario_id = db.Column(db.String(50))
    messages = db.Column(db.JSON, nullable=False, default=list)
    analysis = db.Column(db.JSON)
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
        "active_users": UserProgress.query.filter(db.cast(UserProgress.data, db.String) != '{}').count(),
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

    # Count completed reading sessions for unlock checks
    reading_session_count = db.session.query(EncounterLog.passage_id).filter(
        EncounterLog.user_id == user.id,
        EncounterLog.passage_id.isnot(None)
    ).distinct().count()

    result = {
        "type": "mixed",
        "passage": passage_out,
        "exercises": exercises,
        "target_phrases": targets,
    }

    # Mix in listening after 3+ reading sessions
    if reading_session_count >= 3 and ListeningExercise.query.count() > 0:
        seen_listening_ids = [r[0] for r in db.session.query(EncounterLog.exercise_id).filter(
            EncounterLog.user_id == user.id,
            EncounterLog.encounter_type == "listening",
            EncounterLog.exercise_id.isnot(None)
        ).distinct().all()]
        q = ListeningExercise.query.filter_by(level=user_level.upper())
        if seen_listening_ids:
            q = q.filter(~ListeningExercise.exercise_id.in_(seen_listening_ids))
        listening_ex = q.order_by(ListeningExercise.id).first()
        if not listening_ex:
            listening_ex = ListeningExercise.query.filter(
                ~ListeningExercise.exercise_id.in_(seen_listening_ids) if seen_listening_ids else db.true()
            ).order_by(ListeningExercise.id).first()
        if listening_ex:
            result["type"] = "mixed_with_listening"
            result["listening_exercise"] = {
                "exercise_id": listening_ex.exercise_id,
                "level": listening_ex.level,
                "exercise_type": listening_ex.exercise_type,
                "data": listening_ex.data,
            }

    # Mix in a short writing prompt after 5+ reading sessions (email_completion or rewrite only)
    if reading_session_count >= 5 and WritingPrompt.query.count() > 0:
        submitted_ids = [r[0] for r in db.session.query(WritingSubmission.prompt_id).filter(
            WritingSubmission.user_id == user.id
        ).distinct().all()]
        q = WritingPrompt.query.filter(
            WritingPrompt.level == user_level.upper(),
            WritingPrompt.prompt_type.in_(["email_completion", "rewrite"])
        )
        if submitted_ids:
            q = q.filter(~WritingPrompt.prompt_id.in_(submitted_ids))
        writing_prompt = q.order_by(WritingPrompt.id).first()
        if not writing_prompt:
            writing_prompt = WritingPrompt.query.filter(
                WritingPrompt.prompt_type.in_(["email_completion", "rewrite"]),
                ~WritingPrompt.prompt_id.in_(submitted_ids) if submitted_ids else db.true()
            ).order_by(WritingPrompt.id).first()
        if writing_prompt:
            result["writing_prompt"] = {
                "prompt_id": writing_prompt.prompt_id,
                "level": writing_prompt.level,
                "prompt_type": writing_prompt.prompt_type,
                "data": writing_prompt.data,
            }

    return result

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

@app.route("/api/admin/exercises", methods=["GET"])
@admin_required
def admin_list_exercises(user):
    exercises = ExercisePool.query.order_by(ExercisePool.card_id).all()
    return jsonify({
        "exercises": [{"exercise_id": e.exercise_id, "card_id": e.card_id, "exercise_type": e.exercise_type} for e in exercises],
        "count": len(exercises)
    })

# ── Admin: Listening ──
@app.route("/api/admin/listening/upload", methods=["POST"])
@admin_required
def admin_upload_listening(user):
    body = request.get_json()
    exercises_data = body.get("exercises", [])
    if not isinstance(exercises_data, list) or not exercises_data:
        return jsonify({"error": "Expected non-empty 'exercises' array"}), 400
    valid_types = {"dictation", "listen_comprehension", "connected_speech", "speed_drill"}
    required = ["exercise_id", "level", "exercise_type"]
    errors = []
    for i, ex in enumerate(exercises_data):
        missing = [f for f in required if f not in ex or ex[f] is None]
        if missing:
            errors.append(f"Exercise {i} (id={ex.get('exercise_id','?')}): missing {', '.join(missing)}")
        elif ex.get("exercise_type") not in valid_types:
            errors.append(f"Exercise {i} (id={ex.get('exercise_id','?')}): invalid exercise_type '{ex.get('exercise_type')}'")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for ex in exercises_data:
        eid = ex["exercise_id"]
        blob = {k: v for k, v in ex.items() if k not in ("exercise_id", "level", "exercise_type")}
        existing = ListeningExercise.query.filter_by(exercise_id=eid).first()
        if existing:
            existing.level = ex["level"]
            existing.exercise_type = ex["exercise_type"]
            existing.data = blob
            db.session.execute(
                db.text("UPDATE unstuck_listening SET level = :level, exercise_type = :etype, data = :data WHERE exercise_id = :eid"),
                {"level": ex["level"], "etype": ex["exercise_type"], "data": json.dumps(blob), "eid": eid}
            )
            updated += 1
        else:
            db.session.add(ListeningExercise(exercise_id=eid, level=ex["level"], exercise_type=ex["exercise_type"], data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": ListeningExercise.query.count()})

@app.route("/api/admin/listening", methods=["GET"])
@admin_required
def admin_list_listening(user):
    exercises = ListeningExercise.query.order_by(ListeningExercise.id).all()
    return jsonify({
        "exercises": [{"exercise_id": e.exercise_id, "level": e.level, "exercise_type": e.exercise_type, "created_at": e.created_at.isoformat() if e.created_at else None} for e in exercises],
        "count": len(exercises)
    })

@app.route("/api/admin/listening/<exercise_id>", methods=["DELETE"])
@admin_required
def admin_delete_listening(user, exercise_id):
    ex = ListeningExercise.query.filter_by(exercise_id=exercise_id).first()
    if not ex:
        return jsonify({"error": f"Listening exercise {exercise_id} not found"}), 404
    db.session.delete(ex)
    db.session.commit()
    return jsonify({"ok": True, "deleted": exercise_id})

# ── Listening: next unseen ──
@app.route("/api/listening/next", methods=["GET"])
@token_required
def listening_next(user):
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    seen_ids = [r[0] for r in db.session.query(EncounterLog.exercise_id).filter(
        EncounterLog.user_id == user.id,
        EncounterLog.encounter_type == "listening",
        EncounterLog.exercise_id.isnot(None)
    ).distinct().all()]
    q = ListeningExercise.query.filter_by(level=user_level.upper())
    if seen_ids:
        q = q.filter(~ListeningExercise.exercise_id.in_(seen_ids))
    ex = q.order_by(ListeningExercise.id).first()
    if not ex:
        ex = ListeningExercise.query.filter(~ListeningExercise.exercise_id.in_(seen_ids) if seen_ids else db.true()).order_by(ListeningExercise.id).first()
    if not ex:
        return jsonify({"exercise": None})
    return jsonify({"exercise": {"exercise_id": ex.exercise_id, "level": ex.level, "exercise_type": ex.exercise_type, "data": ex.data}})

# ── Admin: Writing Prompts ──
@app.route("/api/admin/writing/upload", methods=["POST"])
@admin_required
def admin_upload_writing(user):
    body = request.get_json()
    prompts_data = body.get("prompts", [])
    if not isinstance(prompts_data, list) or not prompts_data:
        return jsonify({"error": "Expected non-empty 'prompts' array"}), 400
    valid_types = {"email_completion", "rewrite", "free_write", "summary", "argument"}
    required = ["prompt_id", "level", "prompt_type"]
    errors = []
    for i, p in enumerate(prompts_data):
        missing = [f for f in required if f not in p or p[f] is None]
        if missing:
            errors.append(f"Prompt {i} (id={p.get('prompt_id','?')}): missing {', '.join(missing)}")
        elif p.get("prompt_type") not in valid_types:
            errors.append(f"Prompt {i} (id={p.get('prompt_id','?')}): invalid prompt_type '{p.get('prompt_type')}'")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for p in prompts_data:
        pid = p["prompt_id"]
        blob = {k: v for k, v in p.items() if k not in ("prompt_id", "level", "prompt_type")}
        existing = WritingPrompt.query.filter_by(prompt_id=pid).first()
        if existing:
            existing.level = p["level"]
            existing.prompt_type = p["prompt_type"]
            existing.data = blob
            db.session.execute(
                db.text("UPDATE unstuck_writing_prompts SET level = :level, prompt_type = :ptype, data = :data WHERE prompt_id = :pid"),
                {"level": p["level"], "ptype": p["prompt_type"], "data": json.dumps(blob), "pid": pid}
            )
            updated += 1
        else:
            db.session.add(WritingPrompt(prompt_id=pid, level=p["level"], prompt_type=p["prompt_type"], data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": WritingPrompt.query.count()})

@app.route("/api/admin/writing", methods=["GET"])
@admin_required
def admin_list_writing(user):
    prompts = WritingPrompt.query.order_by(WritingPrompt.id).all()
    return jsonify({
        "prompts": [{"prompt_id": p.prompt_id, "level": p.level, "prompt_type": p.prompt_type, "title": (p.data or {}).get("title", ""), "created_at": p.created_at.isoformat() if p.created_at else None} for p in prompts],
        "count": len(prompts)
    })

# ── Writing: user endpoints ──
@app.route("/api/writing/next", methods=["GET"])
@token_required
def writing_next(user):
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    submitted_ids = [r[0] for r in db.session.query(WritingSubmission.prompt_id).filter(
        WritingSubmission.user_id == user.id
    ).distinct().all()]
    q = WritingPrompt.query.filter_by(level=user_level.upper())
    if submitted_ids:
        q = q.filter(~WritingPrompt.prompt_id.in_(submitted_ids))
    prompt = q.order_by(WritingPrompt.id).first()
    if not prompt:
        prompt = WritingPrompt.query.filter(
            ~WritingPrompt.prompt_id.in_(submitted_ids) if submitted_ids else db.true()
        ).order_by(WritingPrompt.id).first()
    if not prompt:
        return jsonify({"prompt": None})
    return jsonify({"prompt": {"prompt_id": prompt.prompt_id, "level": prompt.level, "prompt_type": prompt.prompt_type, "data": prompt.data}})

@app.route("/api/writing/submit", methods=["POST"])
@token_required
def writing_submit(user):
    body = request.get_json() or {}
    prompt_id = body.get("prompt_id")
    user_text = (body.get("user_text") or "").strip()
    if not prompt_id or not user_text:
        return jsonify({"error": "prompt_id and user_text required"}), 400
    prompt = WritingPrompt.query.filter_by(prompt_id=prompt_id).first()
    if not prompt:
        return jsonify({"error": f"Prompt {prompt_id} not found"}), 404
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "Writing evaluation not configured (missing API key)"}), 503
    prompt_description = (prompt.data or {}).get("title", prompt.prompt_type)
    situation = (prompt.data or {}).get("situation", "")
    starter = (prompt.data or {}).get("starter_text", "")
    prompt_context = f"Type: {prompt.prompt_type}. Title: {prompt_description}."
    if situation:
        prompt_context += f" Situation: {situation}."
    if starter:
        prompt_context += f" Starter text: {starter}."
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    system_prompt = (
        f"Evaluate this English writing by a {user_level} learner. "
        f"The prompt was: {prompt_context} The user wrote: {user_text}. "
        "Rate 1-10 on: grammar, naturalness, vocabulary_range, coherence. "
        "List specific errors with corrections. "
        "Give one positive comment and one improvement suggestion. "
        'Respond in JSON only: { "scores": {"grammar": N, "naturalness": N, "vocabulary": N, "coherence": N}, '
        '"overall": N, "errors": [{"original": "...", "corrected": "...", "explanation": "..."}], '
        '"positive": "...", "suggestion": "..." }'
    )
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_text}],
        )
        raw = response.content[0].text
        ai_feedback = json.loads(raw)
    except json.JSONDecodeError:
        ai_feedback = {"raw_response": raw, "error": "Failed to parse AI response as JSON"}
    except Exception as e:
        return jsonify({"error": f"AI evaluation failed: {str(e)}"}), 502
    overall_score = ai_feedback.get("overall")
    if isinstance(overall_score, (int, float)):
        overall_score = int(overall_score)
    else:
        overall_score = None
    submission = WritingSubmission(
        user_id=user.id,
        prompt_id=prompt_id,
        user_text=user_text,
        ai_feedback=ai_feedback,
        score=overall_score,
    )
    db.session.add(submission)
    db.session.commit()
    return jsonify({"ok": True, "submission_id": submission.id, "feedback": ai_feedback, "score": overall_score}), 201

@app.route("/api/writing/history", methods=["GET"])
@token_required
def writing_history(user):
    submissions = WritingSubmission.query.filter_by(user_id=user.id).order_by(WritingSubmission.created_at.desc()).all()
    return jsonify({"submissions": [{
        "id": s.id,
        "prompt_id": s.prompt_id,
        "user_text": s.user_text,
        "ai_feedback": s.ai_feedback,
        "score": s.score,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    } for s in submissions], "count": len(submissions)})

# ── Admin: Scenarios ──
@app.route("/api/admin/scenarios/upload", methods=["POST"])
@admin_required
def admin_upload_scenarios(user):
    body = request.get_json()
    scenarios_data = body.get("scenarios", [])
    if not isinstance(scenarios_data, list) or not scenarios_data:
        return jsonify({"error": "Expected non-empty 'scenarios' array"}), 400
    required = ["scenario_id", "level"]
    errors = []
    for i, s in enumerate(scenarios_data):
        missing = [f for f in required if f not in s or s[f] is None]
        if missing:
            errors.append(f"Scenario {i} (id={s.get('scenario_id','?')}): missing {', '.join(missing)}")
    if errors:
        return jsonify({"error": "Validation failed", "details": errors[:10]}), 400
    inserted = updated = 0
    for s in scenarios_data:
        sid = s["scenario_id"]
        blob = {k: v for k, v in s.items() if k not in ("scenario_id", "level", "title")}
        existing = ConversationScenario.query.filter_by(scenario_id=sid).first()
        if existing:
            existing.level = s["level"]
            existing.title = s.get("title", existing.title)
            existing.data = blob
            db.session.execute(
                db.text("UPDATE unstuck_scenarios SET level = :level, title = :title, data = :data WHERE scenario_id = :sid"),
                {"level": s["level"], "title": s.get("title", ""), "data": json.dumps(blob), "sid": sid}
            )
            updated += 1
        else:
            db.session.add(ConversationScenario(scenario_id=sid, level=s["level"], title=s.get("title"), data=blob))
            inserted += 1
    db.session.commit()
    return jsonify({"ok": True, "inserted": inserted, "updated": updated, "total": ConversationScenario.query.count()})

# ── Conversation: helpers ──
CONVERSATION_DAILY_LIMIT = 30

def check_conversation_rate_limit(user):
    """Check if user has exceeded daily message limit. Returns (ok, messages_today)."""
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    conv_tracking = progress_data.get("conversationTracking", {})
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    if conv_tracking.get("date") == today:
        return conv_tracking.get("count", 0) < CONVERSATION_DAILY_LIMIT, conv_tracking.get("count", 0)
    return True, 0

def increment_conversation_count(user):
    """Increment daily message count in progress data."""
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    conv_tracking = progress_data.get("conversationTracking", {})
    if conv_tracking.get("date") == today:
        conv_tracking["count"] = conv_tracking.get("count", 0) + 1
    else:
        conv_tracking = {"date": today, "count": 1}
    progress_data["conversationTracking"] = conv_tracking
    db.session.execute(
        db.text("UPDATE unstuck_progress SET data = :data, updated_at = NOW() WHERE user_id = :uid"),
        {"data": json.dumps(progress_data), "uid": user.id}
    )

def build_conversation_system_prompt(scenario, user_level):
    data = scenario.data or {}
    situation = data.get("situation", "a casual conversation")
    ai_role = data.get("ai_role", "a friendly conversation partner")
    ai_personality = data.get("ai_personality", "warm and encouraging")
    target_phrases = data.get("target_phrases", [])
    phrases_hint = ""
    if target_phrases:
        phrases_hint = f"\n- Try to naturally use or elicit these phrases: {', '.join(target_phrases)}"
    return (
        f"You are a friendly English conversation partner for a {user_level} learner.\n"
        f"Scenario: {situation}. Your role: {ai_role}. Personality: {ai_personality}.\n\n"
        f"Rules:\n"
        f"- Match complexity to {user_level}\n"
        f"- If user makes a grammar error, gently correct ONCE inline:\n"
        f"  'Great point! (small note: \"I am agree\" → \"I agree\")'\n"
        f"- Don't correct every error — max 1 correction per response\n"
        f"- Introduce 1 new useful phrase per 3-4 messages{phrases_hint}\n"
        f"- Stay in character as {ai_role}\n"
        f"- Keep responses 2-4 sentences (natural conversation length)\n"
        f"- If user seems stuck, ask an easier follow-up question\n"
        f"- Use contractions and natural speech patterns"
    )

# ── Conversation: user endpoints ──
@app.route("/api/conversation/scenarios", methods=["GET"])
@token_required
def conversation_scenarios(user):
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    scenarios = ConversationScenario.query.filter_by(level=user_level.upper()).order_by(ConversationScenario.id).all()
    if not scenarios:
        scenarios = ConversationScenario.query.order_by(ConversationScenario.id).all()
    return jsonify({"scenarios": [{
        "scenario_id": s.scenario_id,
        "level": s.level,
        "title": s.title,
        "situation": (s.data or {}).get("situation", ""),
        "ai_role": (s.data or {}).get("ai_role", ""),
    } for s in scenarios], "count": len(scenarios)})

@app.route("/api/conversation/start", methods=["POST"])
@token_required
def conversation_start(user):
    body = request.get_json() or {}
    scenario_id = body.get("scenario_id")
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    scenario = ConversationScenario.query.filter_by(scenario_id=scenario_id).first()
    if not scenario:
        return jsonify({"error": f"Scenario {scenario_id} not found"}), 404
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "Conversation not configured (missing API key)"}), 503
    ok, count = check_conversation_rate_limit(user)
    if not ok:
        return jsonify({"error": "Daily message limit reached (30/day)", "messages_today": count}), 429
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    system_prompt = build_conversation_system_prompt(scenario, user_level)
    starter = (scenario.data or {}).get("starter_message")
    if starter:
        first_message = starter
    else:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=256,
                system=system_prompt,
                messages=[{"role": "user", "content": "Please start the conversation with your opening message."}],
            )
            first_message = response.content[0].text
        except Exception as e:
            return jsonify({"error": f"AI conversation failed: {str(e)}"}), 502
    messages = [{"role": "assistant", "content": first_message}]
    conv = ConversationLog(user_id=user.id, scenario_id=scenario_id, messages=messages)
    db.session.add(conv)
    increment_conversation_count(user)
    db.session.commit()
    return jsonify({"conversation_id": conv.id, "first_message": first_message}), 201

@app.route("/api/conversation/message", methods=["POST"])
@token_required
def conversation_message(user):
    body = request.get_json() or {}
    conversation_id = body.get("conversation_id")
    user_message = (body.get("message") or "").strip()
    if not conversation_id or not user_message:
        return jsonify({"error": "conversation_id and message required"}), 400
    conv = ConversationLog.query.filter_by(id=conversation_id, user_id=user.id).first()
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    if conv.analysis:
        return jsonify({"error": "Conversation has ended"}), 400
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "Conversation not configured (missing API key)"}), 503
    ok, count = check_conversation_rate_limit(user)
    if not ok:
        return jsonify({"error": "Daily message limit reached (30/day)", "messages_today": count}), 429
    scenario = ConversationScenario.query.filter_by(scenario_id=conv.scenario_id).first()
    if not scenario:
        return jsonify({"error": "Scenario not found"}), 404
    progress_data = user.progress.data if user.progress and user.progress.data else {}
    user_level = progress_data.get("userLevel", "B1")
    system_prompt = build_conversation_system_prompt(scenario, user_level)
    messages = list(conv.messages or [])
    messages.append({"role": "user", "content": user_message})
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            system=system_prompt,
            messages=messages,
        )
        ai_response = response.content[0].text
    except Exception as e:
        return jsonify({"error": f"AI conversation failed: {str(e)}"}), 502
    messages.append({"role": "assistant", "content": ai_response})
    db.session.execute(
        db.text("UPDATE unstuck_conversations SET messages = :msgs WHERE id = :cid"),
        {"msgs": json.dumps(messages), "cid": conv.id}
    )
    increment_conversation_count(user)
    db.session.commit()
    return jsonify({"response": ai_response, "message_count": len(messages)})

@app.route("/api/conversation/end", methods=["POST"])
@token_required
def conversation_end(user):
    body = request.get_json() or {}
    conversation_id = body.get("conversation_id")
    if not conversation_id:
        return jsonify({"error": "conversation_id required"}), 400
    conv = ConversationLog.query.filter_by(id=conversation_id, user_id=user.id).first()
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404
    if conv.analysis:
        return jsonify({"analysis": conv.analysis})
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "Conversation not configured (missing API key)"}), 503
    messages = conv.messages or []
    user_messages = [m["content"] for m in messages if m["role"] == "user"]
    if not user_messages:
        return jsonify({"error": "No user messages to analyze"}), 400
    scenario = ConversationScenario.query.filter_by(scenario_id=conv.scenario_id).first()
    target_phrases = (scenario.data or {}).get("target_phrases", []) if scenario else []
    analysis_prompt = (
        "Analyze this English conversation by a language learner. "
        "The full conversation:\n\n"
        + "\n".join([f"{m['role'].upper()}: {m['content']}" for m in messages])
        + "\n\n"
    )
    if target_phrases:
        analysis_prompt += f"Target phrases the learner should try to use: {', '.join(target_phrases)}\n\n"
    analysis_prompt += (
        "Respond in JSON only: {\n"
        '  "fluency_score": 1-10,\n'
        '  "vocabulary_used": ["list", "of", "notable", "words/phrases"],\n'
        '  "grammar_errors": [{"error": "...", "correction": "...", "explanation": "..."}],\n'
        '  "phrases_from_app": ["phrases from target list that were used"],\n'
        '  "strengths": "one sentence about what they did well",\n'
        '  "improvement": "one sentence about what to work on"\n'
        "}"
    )
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": analysis_prompt}],
        )
        raw = response.content[0].text
        analysis = json.loads(raw)
    except json.JSONDecodeError:
        analysis = {"raw_response": raw, "error": "Failed to parse AI analysis as JSON"}
    except Exception as e:
        return jsonify({"error": f"AI analysis failed: {str(e)}"}), 502
    db.session.execute(
        db.text("UPDATE unstuck_conversations SET analysis = :analysis WHERE id = :cid"),
        {"analysis": json.dumps(analysis), "cid": conv.id}
    )
    db.session.commit()
    return jsonify({"analysis": analysis})

@app.route("/api/conversation/history", methods=["GET"])
@token_required
def conversation_history(user):
    convs = ConversationLog.query.filter_by(user_id=user.id).order_by(ConversationLog.created_at.desc()).all()
    return jsonify({"conversations": [{
        "id": c.id,
        "scenario_id": c.scenario_id,
        "message_count": len(c.messages or []),
        "analysis": c.analysis,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    } for c in convs], "count": len(convs)})

# ── Admin: Content Stats ──
@app.route("/api/admin/content-stats", methods=["GET"])
@admin_required
def admin_content_stats(user):
    return jsonify({
        "total_passages": Passage.query.count(),
        "total_exercises": ExercisePool.query.count(),
        "total_listening": ListeningExercise.query.count(),
        "total_writing_prompts": WritingPrompt.query.count(),
        "total_writing_submissions": WritingSubmission.query.count(),
        "total_scenarios": ConversationScenario.query.count(),
        "total_conversations": ConversationLog.query.count(),
        "total_encounters": EncounterLog.query.count(),
        "passages_by_level": {level: count for level, count in db.session.query(Passage.level, db.func.count(Passage.id)).group_by(Passage.level).all()},
        "listening_by_level": {level: count for level, count in db.session.query(ListeningExercise.level, db.func.count(ListeningExercise.id)).group_by(ListeningExercise.level).all()},
        "writing_by_level": {level: count for level, count in db.session.query(WritingPrompt.level, db.func.count(WritingPrompt.id)).group_by(WritingPrompt.level).all()},
        "scenarios_by_level": {level: count for level, count in db.session.query(ConversationScenario.level, db.func.count(ConversationScenario.id)).group_by(ConversationScenario.level).all()},
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
