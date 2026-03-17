# CLAUDE.md — Unstuck App Implementation Spec

## Project Overview

Unstuck is an English learning app deployed as:
- **Frontend**: Vercel (static HTML + React via Babel Standalone)
- **Backend**: Railway (Flask + SQLAlchemy + PostgreSQL on Neon)
- **Repo structure**: `backend/` and `frontend/` folders

## Current Architecture

### Backend (`backend/app.py`)

Flask app with these models:
- `unstuck_users` (id, username, password_hash, is_admin, created_at)
- `unstuck_progress` (id, user_id FK, data JSONB, updated_at)
- `unstuck_cards` (id, card_id UNIQUE, data JSONB, created_at)

Card data JSONB contains: phrase, context, meaning, meaningEn, usage, wrongOptions, fillBlank, fillAnswer, rearrange

Auth: JWT tokens (90-day), bcrypt passwords. Admin auto-assigned if username matches ADMIN_USER env var.

Existing endpoints:
- POST /api/auth/register, /api/auth/login
- GET/POST /api/progress, POST /api/reset
- GET /api/cards (public - returns all cards)
- GET /api/admin/cards, POST /api/admin/cards/upload, DELETE /api/admin/cards/:id
- POST /api/admin/cards/delete-all
- GET /api/admin/stats, GET /api/health

DB URL fix: `postgres://` auto-replaced to `postgresql://` for Neon compatibility.
CORS: FRONTEND_URL env var.

### Frontend (`frontend/public/index.html`)

Single HTML file with inline React (Babel Standalone). No build step. **367 lines.**

**IMPORTANT: The frontend is an OLDER version that does NOT have:**
- Admin panel (no AdminPanel component)
- API-based card loading (cards load from static `/cards.js` file via `window.CARDS`)
- `isAdmin` state or localStorage helpers (`getIsAdmin`, `setIsAdmin`)
- Admin button on any screen
- `apiLoadCards`, `apiUploadCards`, `apiAdminStats`, `apiDeleteCard` functions
- `cards` prop on LessonScreen (it uses `window.CARDS` directly)

**The backend HAS admin endpoints — the frontend just doesn't use them yet.**

What the frontend DOES have:
- Fonts: Fraunces (display, variable `Fd`) + DM Sans (body, variable `Fb`)
- Theme object `T` with colors (bg, card, text, muted, accent, accentSoft, ok, okSoft, hi, hiSoft, navy, navySoft, purple, purpleSoft, teal, tealSoft, border, shadow)
- Inline SVG icon components: Icon, ChevronRight, ArrowRight, Check, Zap, BookOpen, Trophy, Heart, RotateCcw, Flame, RefreshCw, HelpCircle, Shuffle, Sparkles, Brain, Shield
- Shared components: FadeIn, Bar, Btn, Badge, Confetti, HelpOverlay, FrustrationBanner
- Auth: `getToken/setToken/clearToken/getUsername/setUsername` using localStorage keys `eng_token`, `eng_user`
- API helpers: `apiLoad()`, `apiSave(data)`, `apiReset()`, `apiRegister(username,password)`, `apiLogin(username,password)` — all use `window.API_URL` from `/config.js`
- Cards: loaded from `/cards.js` as `window.CARDS` (static file, NOT from API)
- SRS: `newCardStats()`, `updateSRS(stats, wasCorrect)`, `buildLesson(allCards, statsMap)`, `exerciseForMastery(mastery)`
- LPP: 4 archetypes (scorekeeper, explorer, witness, pragmatist) with `getLPP(profile)` returning per-archetype messaging
- Exercise components: RearrangeEx, RecallEx (standalone components with card.id-based useEffect reset)
- Screens: AuthScreen, WelcomeScreen, WelcomeBackScreen, GoalScreen, PlacementScreen, LevelRevealScreen, LessonScreen, CelebrationScreen, TomorrowScreen

Screen flow (state machine in App component):
- New user: welcome → goal → placement → level-reveal → lesson → celebration → tomorrow
- Returning: welcome-back → lesson → celebration → tomorrow
- NO admin screen exists

LessonScreen details:
- `buildLesson(window.CARDS, allStats)` called in `useState(() => ...)` lazy initializer
- 8 cards per session, 70% review + 30% new
- 5 exercise types selected by mastery: learn(0), quiz(1), fill(2), rearrange(3), recall(4+)
- `next()` sets all state synchronously (step, phase, sel, isOk, fillIn, etc.) to avoid flash
- `useEffect(()=>{...},[])` for initial card setup only

App component state:
- `loading`, `authed` — auth flow
- `screen` — current screen name
- `lpp` — learner psychology profile (scorekeeper/explorer/witness/pragmatist)
- `level` — CEFR level (A2/B1/B2/C1)
- `lScore` — last lesson score {s, t}
- `streak`, `lessons`, `lessonCards`, `cardStats` — progress data
- NO `allCards` state (uses window.CARDS)
- NO `isAdmin` state

**When building Sprint 1, Claude Code needs to ALSO add:**
1. Admin panel (AdminPanel component with tabs for Cards, Passages, Exercises)
2. Switch cards from `window.CARDS` static file to `GET /api/cards` API
3. `isAdmin` tracking in localStorage
4. Admin button on WelcomeScreen and WelcomeBackScreen
5. All missing API helper functions (apiLoadCards, apiUploadCards, apiAdminStats, apiDeleteCard)
6. Pass `cards` as prop to LessonScreen instead of using window.CARDS

These are PREREQUISITES before adding the Reading module.

---

## What to Build: Sprint 1 — Admin Panel + Card API + Reading Module + New Session Flow

### Step 0: PREREQUISITES (admin panel + API-based cards)

The deployed frontend is missing admin panel and API-based card loading.
Build these FIRST before adding reading module:

**0a. Add missing API helper functions to frontend:**
```javascript
// Add after existing apiReset function:
function getIsAdmin(){return localStorage.getItem("eng_admin")==="true"}
function setIsAdmin(v){localStorage.setItem("eng_admin",v?"true":"false")}

async function apiLoadCards(){
  try{const r=await fetch(window.API_URL+"/api/cards");const j=await r.json();return j.cards||[]}catch{return[]}
}
async function apiUploadCards(cards){
  const t=getToken();if(!t)throw new Error("Not authenticated");
  const r=await fetch(window.API_URL+"/api/admin/cards/upload",{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+t},body:JSON.stringify({cards})});
  const j=await r.json();if(!r.ok)throw new Error(j.error||"Upload failed");return j;
}
async function apiAdminStats(){
  const t=getToken();if(!t)return null;
  const r=await fetch(window.API_URL+"/api/admin/stats",{headers:{"Authorization":"Bearer "+t}});
  return r.ok?await r.json():null;
}
async function apiDeleteCard(cardId){
  const t=getToken();
  const r=await fetch(window.API_URL+"/api/admin/cards/"+cardId,{method:"DELETE",headers:{"Authorization":"Bearer "+t}});
  return r.ok;
}
```

**0b. Update apiRegister and apiLogin to save is_admin:**
The backend already returns `is_admin` in the response — frontend needs to store it.

**0c. Build AdminPanel component:**
Tabs: Cards (upload JSON + list + delete), Passages (same), Exercises (same), Stats dashboard.
Same visual style as rest of app.

**0d. Switch cards from window.CARDS to API:**
- Remove `<script src="/cards.js"></script>` from HTML
- Add `allCards` state to App component
- Fetch cards via `apiLoadCards()` on auth
- Pass `cards` prop to LessonScreen instead of using window.CARDS
- LessonScreen: change `buildLesson(window.CARDS, allStats)` to `buildLesson(cards, allStats)`

**0e. Add admin button to WelcomeScreen and WelcomeBackScreen:**
- WelcomeScreen: add `isAdmin` and `onAdmin` props, show "Admin Panel" button top-right if admin
- WelcomeBackScreen: add `isAdmin` and `onAdmin` props, show "Admin" button next to "Sign out"
- App: add `screen==="admin"` rendering AdminPanel

**0f. Add `screen==="admin"` to App's screen rendering.**

### Step 1: New Database Tables (AFTER prerequisites)

```sql
-- Reading passages with embedded target phrases
CREATE TABLE unstuck_passages (
    id SERIAL PRIMARY KEY,
    passage_id VARCHAR(50) UNIQUE NOT NULL,
    level VARCHAR(5) NOT NULL,  -- B1, B2, C1, C2
    topic VARCHAR(100),
    title VARCHAR(200),
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
-- data JSONB: { text, word_count, target_phrases: [{phrase, card_id, sentence_index}], 
--   bonus_phrases, comprehension: [{question, options, correct, type}], vocabulary }

-- Exercise variation pool (multiple exercises per phrase)
CREATE TABLE unstuck_exercise_pool (
    id SERIAL PRIMARY KEY,
    card_id INTEGER NOT NULL,
    exercise_type VARCHAR(30) NOT NULL,
    exercise_id VARCHAR(50) UNIQUE NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
-- exercise_type: fill_blank, discrimination, usage_boundary, situation, verification
-- data varies by type (see generation plan doc)

-- Track which exercises/passages each user has seen
CREATE TABLE unstuck_encounter_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES unstuck_users(id),
    card_id INTEGER NOT NULL,
    exercise_id VARCHAR(50),
    passage_id VARCHAR(50),
    encounter_type VARCHAR(30) NOT NULL,
    result VARCHAR(20),
    response_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_encounter_user_card ON unstuck_encounter_log(user_id, card_id);
CREATE INDEX idx_encounter_user_passage ON unstuck_encounter_log(user_id, passage_id);
```

### New Backend Endpoints

```
# Public
GET /api/passages?level={level}     → list passages by level (id, title, level only)

# Auth required
GET /api/session/compose            → returns a composed session for the user
POST /api/encounter                 → log an encounter (user saw/answered an exercise)
GET /api/encounters/:card_id        → get user's encounter history for a card

# Admin
POST /api/admin/passages/upload     → bulk upload passages (same pattern as cards)
GET  /api/admin/passages            → list all passages with metadata
DELETE /api/admin/passages/:id      → delete a passage
POST /api/admin/exercises/upload    → bulk upload exercise variations
GET  /api/admin/content-stats       → counts of passages, exercises, encounters
```

### Session Composer Logic (Backend)

```python
def compose_session(user):
    """Compose a mixed session: reading + exercises"""
    user_level = user.progress.data.get("userLevel", "B1")
    card_stats = user.progress.data.get("cardStats", {})
    
    # 1. Find phrases due for review (SRS)
    due_phrases = get_due_phrases(card_stats)  # returns card_ids
    
    # 2. Find phrases with suspect mastery (high mastery but few unique contexts)
    suspect = get_suspect_phrases(card_stats, user.id)
    
    # 3. Pick target phrases for this session (3-5)
    targets = pick_targets(due_phrases, suspect, max=4)
    
    # 4. Find a passage containing some of these phrases that user hasn't read
    seen_passages = get_seen_passage_ids(user.id)
    passage = find_passage(targets, user_level, exclude=seen_passages)
    
    # 5. For each target phrase, pick an exercise variation user hasn't seen
    exercises = []
    for card_id in targets:
        seen_exercises = get_seen_exercise_ids(user.id, card_id)
        mastery = get_mastery_level(card_stats, card_id)
        ex_type = exercise_type_for_mastery(mastery)
        exercise = pick_exercise(card_id, ex_type, exclude=seen_exercises)
        if exercise:
            exercises.append(exercise)
    
    # 6. If no passage found with these phrases, pick any unseen passage at user's level
    #    and use its embedded phrases as targets instead
    if not passage:
        passage = find_any_unseen_passage(user_level, seen_passages)
        if passage:
            targets = passage.data["target_phrases"]
            exercises = [pick_any_exercise(t["card_id"]) for t in targets]
    
    # 7. Fallback: if no passages at all, serve classic flashcard session
    if not passage:
        return {"type": "flashcard_only", "cards": build_classic_lesson(cards, card_stats)}
    
    return {
        "type": "mixed",
        "passage": passage,
        "exercises": exercises,
        "target_phrases": targets
    }
```

### Frontend Changes

#### New Screen: ReadingScreen

```
Flow:
1. Show passage title + estimated reading time
2. User reads passage (plain text, no highlights)
3. "Done reading" button
4. Comprehension questions (one at a time, like quiz)
5. After all questions answered:
   - Show passage again WITH target phrases highlighted
   - Brief explanation for each phrase
6. Transition to exercise screens for target phrases
7. Celebration / session summary
```

#### Modified App Flow

```
OLD: welcome-back → lesson (8 flashcards) → celebration → tomorrow

NEW: welcome-back → session (composed by backend):
  If mixed: reading → comprehension → phrase notice → exercises → summary
  If flashcard_only (no passages yet): classic 8-card lesson (existing code)
  
Button text: "Today's Session" (not "Today's lesson")
```

#### Admin Panel: New Tabs

Add "Passages" tab in AdminPanel:
- Upload JSON (same UX as card upload)
- List passages with title, level, phrase count
- Delete per passage

Add "Exercises" tab:
- Upload exercise variations JSON
- List by card_id with count of variations

Add "Content Stats" card on admin dashboard:
- Total passages, exercises, encounters logged

### Mastery V2 (stored alongside V1)

For now, ADD mastery_v2 to cardStats WITHOUT removing old mastery. This allows:
- Old flashcard flow still works (fallback)
- New reading flow uses mastery_v2
- Gradual migration

```javascript
// In cardStats[card_id]:
{
  // V1 (keep for backward compat)
  mastery: 3,
  interval: 7,
  ease: 2.5,
  // ... existing SRS fields
  
  // V2 (new)
  mastery_v2: 2,  // 0-7 scale
  unique_contexts: 3,  // how many different contexts encountered
  last_reading: "2026-03-20",
  last_production: null,
  retention_due: null,
  suspect: false
}
```

Mastery V2 levels:
- 0: Unseen
- 1: Encountered (seen in reading)
- 2: Recognized (correct in new context, 2x)
- 3: Discriminated (passed discrimination + usage boundary)
- 4: Produced (wrote correctly in 2 new situations)
- 5: Comprehended naturally (understood in passage without highlight)
- 6: Retained (passed check after 14-day gap)
- 7: Mastered (final)

### Key Constraints

- Frontend is single HTML file with inline React + Babel Standalone (currently 367 lines)
- No npm, no build step, no webpack
- Libraries available: React 18 (CDN), no external component libraries
- All styling is inline `style={{}}` objects
- Keep existing visual design: Fraunces headings, DM Sans body, warm cream bg (#FBF7F0), accent #D4613E
- Backend is single `app.py` file (currently 258 lines, keep it that way for simplicity)
- Tables prefixed with `unstuck_` (shared Neon database)
- All new features should degrade gracefully: if no passages uploaded, app works like before
- **CRITICAL: Cards currently load from static `/cards.js` file. Step 0d MUST migrate this to API before building reading module.**
- **CRITICAL: Frontend currently has NO admin panel. Step 0c MUST build this before passages can be uploaded.**
- Font variables: `Fd` = Fraunces (display/headings), `Fb` = DM Sans (body text)
- Theme object: `T` with properties: bg, card, text, muted, accent, accentSoft, ok, okSoft, hi, hiSoft, navy, navySoft, purple, purpleSoft, teal, tealSoft, border, shadow
