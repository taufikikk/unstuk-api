
# CLAUDE.md — Unstuck App Complete Implementation Spec

## Project Overview

Unstuck is an English learning app that makes users "immersion-ready" — able to watch Netflix, join meetings, read articles, and hold conversations in English without freezing.

**Deployed as:**
- **Frontend**: Vercel (repo: `unstuck-web`) — static HTML + React via Babel Standalone
- **Backend**: Railway (repo: `unstuck-api`) — Flask + SQLAlchemy + PostgreSQL on Neon
- **Two separate repos, two separate codespaces.**

---

## Current Architecture (WHAT EXISTS NOW)

### Backend (`app.py`)

Flask app. Single file. All tables prefixed `unstuck_`.

**Existing Models:**
- `unstuck_users` (id, username, password_hash, is_admin, created_at)
- `unstuck_progress` (id, user_id FK, data JSONB, updated_at)
- `unstuck_cards` (id, card_id UNIQUE, data JSONB, created_at)
- `unstuck_passages` (id, passage_id UNIQUE, level, topic, title, data JSONB, created_at)
- `unstuck_exercise_pool` (id, card_id, exercise_type, exercise_id UNIQUE, data JSONB, created_at)
- `unstuck_encounter_log` (id, user_id FK, card_id, exercise_id, passage_id, encounter_type, result, response_time_ms, created_at)

**Card data JSONB:** phrase, context, meaning, meaningEn, usage, wrongOptions, fillBlank, fillAnswer, rearrange

**Passage data JSONB:** text, word_count, target_phrases [{phrase, card_id, sentence_index}], bonus_phrases, comprehension [{question, options, correct, type}], vocabulary

**Existing Endpoints:**
- POST /api/auth/register, /api/auth/login
- GET/POST /api/progress, POST /api/reset
- GET /api/cards (public)
- GET /api/passages?level= (public)
- GET /api/session/compose (auth — returns mixed or flashcard_only session)
- POST /api/encounter (auth — logs encounter)
- GET /api/admin/cards, POST /api/admin/cards/upload, DELETE /api/admin/cards/:id
- POST /api/admin/cards/delete-all
- GET /api/admin/passages, POST /api/admin/passages/upload, DELETE /api/admin/passages/:id
- POST /api/admin/exercises/upload, GET /api/admin/exercises
- GET /api/admin/stats, GET /api/admin/content-stats
- GET /api/health

**Auth:** JWT (90-day), bcrypt. Admin auto-assigned if username matches ADMIN_USER env var.

**DB URL fix:** `postgres://` auto-replaced to `postgresql://` for Neon.

**Environment Variables:**
- DATABASE_URL — Neon connection string
- SECRET_KEY — JWT signing key
- ADMIN_USER — username that gets auto-admin on register
- FRONTEND_URL — Vercel URL for CORS
- ANTHROPIC_API_KEY — needed for Phase 3+ (writing evaluation, conversation)

### Frontend (`public/index.html`)

Single HTML file with inline React (Babel Standalone). No build step.

**Libraries:** React 18 (CDN), no external component libraries.

**Styling:** All inline `style={{}}`. Font variables: `Fd` (Fraunces display), `Fb` (DM Sans body). Theme object `T` with: bg (#FBF7F0), card (#FFFFFF), text (#1A1A2E), muted (#6B6B80), accent (#D4613E), accentSoft, ok (#4A8B6F), okSoft, hi (#F2CC8F), hiSoft, navy (#3D405B), navySoft, purple (#7B68A8), purpleSoft, teal (#4A90A4), tealSoft, border (#E8E4DC), shadow.

**Icons:** Inline SVG components (Icon, ChevronRight, ArrowRight, Check, Zap, BookOpen, Trophy, Heart, RotateCcw, Flame, RefreshCw, HelpCircle, Shuffle, Sparkles, Brain, Shield).

**Shared Components:** FadeIn, Bar, Btn, Badge, Confetti, HelpOverlay, FrustrationBanner.

**Auth:** localStorage keys: eng_token, eng_user, eng_admin. API calls use `window.API_URL` from `/config.js`.

**Existing Screens:** AuthScreen, WelcomeScreen, WelcomeBackScreen, GoalScreen, PlacementScreen, LevelRevealScreen, LessonScreen (flashcard), ReadingScreen, CelebrationScreen, TomorrowScreen, AdminPanel.

**Current Session Flow:**
- New user: welcome → goal → placement → level-reveal → lesson → celebration → tomorrow
- Returning (with passages): welcome-back → reading session (passage → comprehension → highlight → exercises → recall check → celebration) → tomorrow
- Returning (no passages): welcome-back → flashcard lesson → celebration → tomorrow
- Admin: admin panel accessible from welcome/welcome-back screens

**SRS:** Modified SM-2 with mastery 0-5, stored in progress.data.cardStats.

**LPP:** 4 archetypes (scorekeeper, explorer, witness, pragmatist) with per-archetype messaging.

**Exercise Types:** learn, quiz, fill, rearrange, recall — selected by exerciseForMastery(mastery).

---

## ALL NEW FEATURES TO BUILD (Phases 2-8)

Each phase adds new models, endpoints, and frontend components. Everything is ADDITIVE — never remove or break existing features.

---

### PHASE 2: LISTENING

**New Model: ListeningExercise**
```sql
CREATE TABLE unstuck_listening (
    id SERIAL PRIMARY KEY,
    exercise_id VARCHAR(50) UNIQUE NOT NULL,
    level VARCHAR(5) NOT NULL,
    exercise_type VARCHAR(30) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```
exercise_type values: "dictation", "listen_comprehension", "connected_speech", "speed_drill"

dictation data: { text, word_count }
listen_comprehension data: { text, questions: [{question, options, correct}], target_phrases }
connected_speech data: { reduced, full, sentence, options, correct, example, difficulty }
speed_drill data: { text, speeds: [0.75, 1.0, 1.25], questions }

**New Endpoints:**
- POST /api/admin/listening/upload — admin bulk upload
- GET /api/admin/listening — admin list all
- DELETE /api/admin/listening/<exercise_id> — admin delete
- GET /api/listening/next — auth, returns next unseen listening exercise

**Session Composer Update:** After 3+ reading sessions, mix in 1 listening exercise per session. New session type: "mixed_with_listening".

**Frontend:** ListeningScreen using Web Speech API (window.speechSynthesis) for TTS. Exercise types: dictation (type what you hear), listen-comprehension (listen → questions → reveal text), connected-speech (identify reduced forms), speed-drill (increasing speeds). Optional "Real World Mode" with background noise via Web Audio API.

---

### PHASE 3: WRITING

**New Models:**
```sql
CREATE TABLE unstuck_writing_prompts (
    id SERIAL PRIMARY KEY,
    prompt_id VARCHAR(50) UNIQUE NOT NULL,
    level VARCHAR(5) NOT NULL,
    prompt_type VARCHAR(30) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE unstuck_writing_submissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES unstuck_users(id),
    prompt_id VARCHAR(50) NOT NULL,
    user_text TEXT NOT NULL,
    ai_feedback JSONB,
    score INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
```
prompt_type: "email_completion", "rewrite", "free_write", "summary", "argument"

**New Endpoints:**
- POST /api/admin/writing/upload — admin bulk upload prompts
- GET /api/admin/writing — admin list
- GET /api/writing/next — auth, next unseen prompt for user
- POST /api/writing/submit — auth, user text → Claude API evaluation → store + return feedback
- GET /api/writing/history — auth, past submissions

**Claude API Integration:** Uses `anthropic` Python package (add to requirements.txt). Calls claude-sonnet-4-20250514 for evaluation. System prompt evaluates: grammar, naturalness, vocabulary_range, coherence (1-10 each). Returns: scores, errors with corrections, positive comment, suggestion. Needs ANTHROPIC_API_KEY env var.

**Frontend:** WritingScreen with email_completion (situation + starter + textarea), rewrite (awkward sentence → rewrite), free_write (topic + textarea). WritingFeedback shows score circle, inline error highlights (red = grammar, yellow = unnatural), positive comment, suggestion.

---

### PHASE 4: CONVERSATION

**New Models:**
```sql
CREATE TABLE unstuck_scenarios (
    id SERIAL PRIMARY KEY,
    scenario_id VARCHAR(50) UNIQUE NOT NULL,
    level VARCHAR(5) NOT NULL,
    title VARCHAR(200),
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE unstuck_conversations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES unstuck_users(id),
    scenario_id VARCHAR(50),
    messages JSONB NOT NULL DEFAULT '[]',
    analysis JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
```
scenario data: { situation, ai_role, ai_personality, starter_message, target_phrases, success_criteria, curveball }

**New Endpoints:**
- POST /api/admin/scenarios/upload — admin bulk upload
- GET /api/conversation/scenarios — auth, list for user level
- POST /api/conversation/start — auth, start with scenario_id → returns conversation_id + first message
- POST /api/conversation/message — auth, send message → Claude API → return response
- POST /api/conversation/end — auth, end → Claude API analysis → return report
- GET /api/conversation/history — auth, past conversations

**Rate Limiting:** 30 messages/day per user. Track in progress data.

**Frontend:** ConversationScreen with scenario picker, chat interface (bubbles, typing indicator, correction highlights in #FFF3CD bg), post-conversation analysis (fluency score, vocabulary, grammar errors, phrases used). Access via button on WelcomeBackScreen.

---

### PHASE 5: GRAMMAR + REAL-WORLD

**New Model:**
```sql
CREATE TABLE unstuck_grammar (
    id SERIAL PRIMARY KEY,
    lesson_id VARCHAR(50) UNIQUE NOT NULL,
    level VARCHAR(5) NOT NULL,
    title VARCHAR(200),
    grammar_point VARCHAR(100),
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```
data: { examples[10], pattern_question, pattern_explanation, exercises[5], production[2], exceptions[3], auto_cards[3] }

**New Endpoints:**
- POST /api/admin/grammar/upload
- GET /api/grammar/next — auth, based on user error patterns
- POST /api/grammar/complete — auth, mark complete

**Grammar Trigger:** Track error categories from writing + conversation. If same error 3+ times → schedule lesson. Categories: articles, prepositions, verb_tense, word_order, subject_verb_agreement, conditionals, passive_voice, reported_speech.

**Frontend:** GrammarLessonScreen (5-step: Notice → Spot Pattern → Practice → Produce → Exceptions), SubtextExercise ("what they say vs mean"), RegisterExercise (same message, 3 formality levels), SarcasmExercise (sincere or sarcastic detection).

---

### PHASE 6: ASSESSMENT + DASHBOARD

**New Models:**
```sql
CREATE TABLE unstuck_assessments (
    id SERIAL PRIMARY KEY,
    question_id VARCHAR(50) UNIQUE NOT NULL,
    skill VARCHAR(30) NOT NULL,
    level VARCHAR(5) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE unstuck_assessment_results (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES unstuck_users(id),
    assessment_type VARCHAR(30),
    scores JSONB NOT NULL,
    overall_level VARCHAR(5),
    created_at TIMESTAMP DEFAULT NOW()
);
```

**New Endpoints:**
- POST /api/admin/assessments/upload
- GET /api/assessment/start — auth, adaptive 20 questions
- POST /api/assessment/submit — auth, return scored results
- GET /api/assessment/history — auth, trends

**Frontend:** ProgressScreen (radar chart SVG, CEFR cards, immersion readiness, streak calendar, stats). AssessmentScreen (adaptive questions, timed, per-skill results).

---

### PHASE 7: ADVANCED FEATURES

**Card Model Update:** Add optional `domain` VARCHAR(50) to unstuck_cards.

**New Endpoints:**
- GET /api/cards/domains — list with counts
- POST /api/user/domains — auth, save selected domains

**Frontend:** Domain selection in onboarding, SlangExercise, ConnectedSpeechScreen (TTS reduced forms, speed ladder).

---

### PHASE 8: TOEFL + MASTERY V2 + POLISH

**New Model:**
```sql
CREATE TABLE unstuck_toefl (
    id SERIAL PRIMARY KEY,
    section_id VARCHAR(50) UNIQUE NOT NULL,
    section_type VARCHAR(30) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

**New Endpoints:**
- POST /api/admin/toefl/upload
- GET /api/toefl/sections, POST /api/toefl/start/:id, POST /api/toefl/submit/:id, GET /api/toefl/history

**Mastery V2:** 7 levels (Unseen → Encountered → Recognized → Discriminated → Produced → Comprehended → Retained → Mastered). Track unique_contexts. Suspect detection (response_time < 1500ms). 14-day retention check. Store mastery_v2 alongside existing mastery.

**Smart Session Composer:** Session preview, multi-skill mixing, weakness targeting, length options (Quick/Standard/Deep).

**Frontend:** TOEFLScreen (timed sections), mastery visualization (7-step bars), session preview, ImmersionScreen (readiness recommendations).

---

## KEY CONSTRAINTS (ALL PHASES)

- Frontend: single HTML, inline React + Babel, no build step, no npm
- Styling: inline `style={{}}`, use Fd/Fb/T
- Backend: single `app.py`, keep simple
- Tables: prefix `unstuck_`
- Everything ADDITIVE — never break existing
- Fallback: if content missing, degrade gracefully
- Claude API: `anthropic` package, model `claude-sonnet-4-20250514`
- New pip packages: add to requirements.txt

---

## ENVIRONMENT VARIABLES (Railway)

| Variable | Phase | Description |
|----------|-------|-------------|
| DATABASE_URL | All | Neon PostgreSQL |
| SECRET_KEY | All | JWT signing |
| ADMIN_USER | All | Auto-admin username |
| FRONTEND_URL | All | Vercel URL for CORS |
| ANTHROPIC_API_KEY | 3+ | Writing eval + conversation |

---

*Unstuck CLAUDE.md v2.0 — Complete Spec — March 2026*
