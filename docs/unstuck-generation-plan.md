# Unstuck Mass Content Generation Plan

### "Stockpile 1000 Generations While Bonus Active"

---

## What to Generate (Priority Order)

### Batch A: Reading Passages (200 passages)
**Paling penting — ini yang mengubah app dari drill tool ke acquisition platform.**

```
50 passages × B1 level (120-180 kata)
60 passages × B2 level (200-300 kata)  
50 passages × C1 level (350-500 kata)
40 passages × C2 level (450-700 kata)
```

Setiap passage mengandung 3-4 phrases dari card database (450 kartu).
Setiap passage punya 3-5 comprehension questions.
Setiap passage punya vocabulary highlight (kata-kata yang mungkin baru).

**200 passages = ~200 generations dari Opus.**

### Batch B: Exercise Variations per Phrase (2250 exercises)
**Anti-pattern-memorization — setiap phrase punya banyak variasi.**

Untuk 450 phrases, generate per phrase:
```
3 × fill-in-the-blank BERBEDA (kalimat baru, situasi baru)
1 × discrimination test (bedakan dari phrase mirip)
1 × production situation (situasi baru untuk user menulis)
= 5 variasi per phrase
= 450 × 5 = 2250 exercises
```

Bisa di-batch: 10 phrases per generation = **~225 generations dari Opus.**

### Batch C: Passage-Phrase Mapping (0 extra generations)
**Gratis — ini cuma data mapping.**

Setelah Batch A selesai, buat mapping:
- Passage #1 mengandung phrases: [15, 42, 88]
- Passage #2 mengandung phrases: [3, 27, 91, 120]
- dst.

App pakai mapping ini untuk: "User perlu review phrase #42 → 
serve passage yang mengandung phrase #42 yang user belum pernah baca."

### Batch D: Situation Pools for Production Exercises (450 situations)
**Untuk mastery Level 4 — user harus PRODUCE phrase di situasi baru.**

Untuk 450 phrases, generate per phrase:
```
3 × situasi unik untuk production exercise
= 450 × 3 = 1350 situations
```

Bisa di-batch: 15 phrases per generation = **~90 generations dari Opus.**

### Batch E: Natural Comprehension Passages (100 passages)
**Untuk mastery Level 5 — phrase TIDAK di-highlight, user harus paham dari konteks.**

```
100 passages khusus untuk verification:
- Phrase target tersembunyi di dalam teks
- Comprehension question yang HANYA bisa dijawab jika paham phrase
- Lebih pendek (100-150 kata) — focused test, bukan bacaan panjang
```

**100 generations dari Opus.**

### Batch F: Grammar Pattern Passages (60 passages)
**Untuk Phase 8 — grammar dipelajari lewat contoh, bukan rules.**

```
20 grammar points × 3 passages each = 60 passages
Setiap passage: 8-10 kalimat yang menggunakan grammar pattern
User baca → notice pattern → app jelaskan
```

**60 generations dari Opus.**

### Batch G: Conversation Scenarios (50 scenarios)
**Untuk Phase 6 nanti — pre-generate conversation starters + expected flows.**

```
50 scenarios dengan:
- Situation description
- AI's role and personality
- Conversation starter (first message)
- 5 expected user responses + AI follow-ups for each
- Key phrases user should try to use
- 3 possible conversation endings
```

**50 generations dari Opus.**

---

## Total Generation Count

| Batch | Content | Generations |
|-------|---------|-------------|
| A | Reading Passages (200) | 200 |
| B | Exercise Variations (2250) | 225 |
| C | Passage-Phrase Mapping | 0 (derived) |
| D | Production Situations (1350) | 90 |
| E | Comprehension Verification (100) | 100 |
| F | Grammar Passages (60) | 60 |
| G | Conversation Scenarios (50) | 50 |
| **Total** | | **~725 generations** |

Masih ada ~275 budget dari 1000. Reserve untuk:
- Re-generating yang kurang natural (quality fixes)
- Extra passages untuk topics yang kurang ter-cover
- Conversation scenario variations
- Future content needs

---

## Generation Prompts (Copy-Paste Ready)

### PROMPT A: Reading Passages

```
Generate a reading passage for an English learning app.

LEVEL: {B1 / B2 / C1 / C2}
TOPIC: {see topic list below}

The passage MUST naturally contain these English phrases:
1. "{phrase 1}" (meaning: {meaning})
2. "{phrase 2}" (meaning: {meaning})
3. "{phrase 3}" (meaning: {meaning})

RULES:
- {B1: 120-180 words / B2: 200-300 words / C1: 350-500 words / C2: 450-700 words}
- Phrases must feel NATURAL — not forced into the text
- Do NOT bold, highlight, or mark the target phrases
- Write like a real person, not a textbook:
  * Use contractions (it's, don't, we're)
  * Vary sentence length
  * Include natural discourse markers ("honestly", "the thing is", "I mean")
  * No "Furthermore", "In conclusion", "It is important to note"
- The passage should tell a story or make an argument — not just be a collection of sentences
- Include 1-2 phrases the learner hasn't studied yet (bonus incidental learning)

COMPREHENSION QUESTIONS:
Generate 4 questions:
- Q1: Main idea (what is this about?)
- Q2: Detail recall (what specific thing happened?)
- Q3: Inference (why did the person do X? what does this imply?)
- Q4: Phrase-dependent (can ONLY be answered if reader understands one of the target phrases)

For Q4, do NOT mention the phrase in the question. The question should test comprehension of the MEANING the phrase conveys.

OUTPUT FORMAT (JSON):
{
  "id": "passage_{number}",
  "level": "{B1/B2/C1/C2}",
  "topic": "{topic}",
  "title": "{catchy title}",
  "text": "{the passage}",
  "word_count": {number},
  "target_phrases": [
    {"phrase": "...", "card_id": {number}, "sentence_index": {which sentence}}
  ],
  "bonus_phrases": ["...", "..."],
  "comprehension": [
    {
      "question": "...",
      "options": ["A", "B", "C", "D"],
      "correct": 0,
      "type": "main_idea | detail | inference | phrase_dependent"
    }
  ],
  "vocabulary": [
    {"word": "...", "meaning_id": "...", "meaning_en": "...", "sentence": "..."}
  ]
}
```

**TOPIC LIST (rotate through these):**

B1 Topics:
- Monday morning commute
- Ordering food when the menu is confusing
- First day at a new job
- Explaining a tech problem to a friend
- Weekend plans that went wrong
- Asking for help at work
- A misunderstanding with a colleague
- Shopping online and getting the wrong item
- Trying a new restaurant
- Morning routine changes

B2 Topics:
- Why meetings waste time (opinion)
- Remote work: freedom or loneliness?
- A production incident post-mortem
- Giving feedback to a senior colleague
- The interview that changed my mind
- Why I switched from [tech A] to [tech B]
- A customer complaint that taught me something
- The project that almost failed
- Working across time zones
- When your boss disagrees with you

C1 Topics:
- The psychology behind procrastination
- Why most code reviews are useless
- Technical debt: pay now or pay later?
- The myth of the 10x engineer
- How language shapes the way you think about code
- When automation makes things worse
- The hidden cost of "moving fast and breaking things"
- Why diverse teams build better products
- The difference between being busy and being productive
- How I learned to say no at work

C2 Topics:
- The ethics of AI-generated content
- Meritocracy: inspiring ideal or harmful myth?
- The paradox of choice in modern software development
- Why the best engineers are often the worst communicators
- The invisible labor of maintaining legacy systems
- Cultural translation: what "yes" means in different countries
- The economic argument for doing nothing
- How survivorship bias distorts our understanding of success
- The tension between innovation and reliability
- Why simple solutions are the hardest to find

---

### PROMPT B: Exercise Variations (batch of 10 phrases)

```
Generate exercise variations for these 10 English phrases. 
For each phrase, create ALL of the following:

PHRASES:
1. "{phrase}" (meaning: {meaning}, usage: {usage})
2. "{phrase}" (meaning: {meaning}, usage: {usage})
... (10 phrases)

FOR EACH PHRASE, GENERATE:

A) 3 FILL-IN-THE-BLANK sentences:
   - Each sentence must be a DIFFERENT situation/context
   - Situations: one work-related, one casual/social, one unexpected/creative
   - Include the correct answer and 3 plausible wrong options
   - Wrong options should be phrases that SOUND similar but mean different things

B) 1 DISCRIMINATION TEST:
   - 4 sentences: exactly 1 uses the phrase correctly
   - The other 3 use similar phrases incorrectly OR use the correct phrase in wrong context
   - Include explanation for why each is right/wrong

C) 1 USAGE BOUNDARY TEST:
   - "In which situation would you NOT use this phrase?"
   - 4 situations: 3 where the phrase fits, 1 where it doesn't
   - Mark which one doesn't fit and explain why

NATURALNESS RULES:
- All sentences must sound like real humans talking/writing
- Use contractions, natural rhythm, real-life situations
- A native speaker reading these should think "yeah, that's how people talk"
- NO textbook English

OUTPUT FORMAT (JSON):
{
  "exercises": [
    {
      "card_id": {number},
      "phrase": "...",
      "fill_blanks": [
        {
          "id": "fb_{card_id}_{1-3}",
          "situation": "work email",
          "sentence": "_____ the client had already approved it.",
          "answer": "It turns out",
          "wrong": ["It comes out", "It shows up", "It goes out"]
        }
      ],
      "discrimination": {
        "id": "disc_{card_id}",
        "question": "Which sentence uses the phrase correctly?",
        "options": [
          {"sentence": "...", "correct": true, "explanation": "..."},
          {"sentence": "...", "correct": false, "explanation": "..."}
        ]
      },
      "usage_boundary": {
        "id": "ub_{card_id}",
        "question": "In which situation would you NOT use this phrase?",
        "options": [
          {"situation": "...", "fits": true},
          {"situation": "...", "fits": true},
          {"situation": "...", "fits": true},
          {"situation": "...", "fits": false, "explanation": "..."}
        ]
      }
    }
  ]
}
```

---

### PROMPT D: Production Situations

```
Generate realistic production exercise situations for these 15 English phrases.
For each phrase, create 3 unique situations where a person would naturally use it.

PHRASES:
1. "{phrase}" (meaning: {meaning})
... (15 phrases)

SITUATION RULES:
- Each situation must be specific and vivid — not generic
- The person in the situation should be an Indonesian professional 
  working in tech/banking (the app's target user)
- Situations should vary: work, social, travel, daily life, online communication
- The situation must NATURALLY call for the target phrase — 
  don't force it
- Include: situation description, instruction to user, one example 
  of a good response

NATURALNESS: The example response must sound like a real person, 
not a textbook. Use contractions, casual tone where appropriate.

OUTPUT FORMAT (JSON):
{
  "situations": [
    {
      "card_id": {number},
      "phrase": "...",
      "variations": [
        {
          "id": "sit_{card_id}_{1-3}",
          "context": "You're in a Slack channel...",
          "instruction": "Write 1-2 sentences using '{phrase}'.",
          "example_response": "...",
          "setting": "work_chat | email | meeting | social | text_message"
        }
      ]
    }
  ]
}
```

---

### PROMPT E: Natural Comprehension Verification Passages

```
Generate a short verification passage (100-150 words) for 
testing NATURAL comprehension of this phrase:

PHRASE: "{phrase}" (meaning: {meaning})

RULES:
- The passage contains the phrase used naturally
- Do NOT highlight, bold, or draw attention to the phrase
- The phrase should be embedded naturally — not the first 
  or last sentence
- Write two comprehension questions:
  Q1: A general question about the passage (answerable without 
      understanding the target phrase)
  Q2: A question that can ONLY be answered correctly if the 
      reader understood what the target phrase means in context
- Q2 should NOT mention the phrase or ask "what does X mean?"
  Instead, ask about the CONSEQUENCE or IMPLICATION of what 
  the phrase communicates

EXAMPLE:
Phrase: "it turns out"
Bad Q2: "What does 'it turns out' mean?" ← too direct
Good Q2: "What surprised the team about the server issue?" 
← requires understanding that "it turns out" signals 
unexpected discovery

OUTPUT FORMAT (JSON):
{
  "id": "verify_{card_id}_{number}",
  "card_id": {number},
  "phrase": "...",
  "passage": "...",
  "questions": [
    {
      "question": "...",
      "options": ["A", "B", "C", "D"],
      "correct": 0,
      "requires_phrase": false
    },
    {
      "question": "...",
      "options": ["A", "B", "C", "D"],
      "correct": 2,
      "requires_phrase": true
    }
  ]
}
```

---

## Execution Plan (How to Generate Efficiently)

### Day 1-2: Reading Passages (Batch A)
```
Session 1: 10 B1 passages (30 phrases covered)
Session 2: 10 B1 passages (30 phrases covered)
Session 3: 10 B1 passages (30 phrases covered)
Session 4: 10 B1 passages (28 phrases covered)
Session 5: 10 B1 passages (30 phrases covered)
→ 50 B1 passages done, ~148 unique phrases encountered

Session 6-11: 60 B2 passages (same pattern)
→ All 450 phrases encountered at least once across B1+B2
```

### Day 3: Reading Passages continued
```
Session 12-16: 50 C1 passages
Session 17-20: 40 C2 passages
→ 200 passages total done
```

### Day 4-5: Exercise Variations (Batch B)
```
Each prompt: 10 phrases × 5 exercise types = 50 exercises
Need 45 prompts to cover all 450 phrases
~15 prompts per session × 3 sessions per day = done in 1.5 days
```

### Day 6: Production Situations (Batch D)
```
Each prompt: 15 phrases × 3 situations = 45 situations
Need 30 prompts
~10 per session × 3 sessions = done in 1 day
```

### Day 7: Comprehension Verification (Batch E)
```
Each prompt: 5 phrases × 1 verification passage = 5 passages
Need 90 prompts (for top 90 most important phrases first)
~15 per session × 6 sessions = done in 1 day
```

### Day 8: Grammar + Conversation (Batch F + G)
```
60 grammar passages + 50 conversation scenarios = 110 generations
~20 per session × 6 sessions = done in 1 day
```

### Day 9-10: Quality Review + Fixes
```
Review all generated content
Flag unnatural sentences
Regenerate with fixes (~50-100 regenerations)
Final JSON assembly + upload to app
```

---

## File Naming Convention

```
/content/
  /passages/
    passages-b1-001-010.json    (passages 1-10, B1 level)
    passages-b1-011-020.json
    passages-b2-001-010.json
    ...
  /exercises/
    exercises-cards-001-010.json (exercises for card IDs 1-10)
    exercises-cards-011-020.json
    ...
  /situations/
    situations-cards-001-015.json
    situations-cards-016-030.json
    ...
  /verification/
    verify-cards-001-005.json
    verify-cards-006-010.json
    ...
  /grammar/
    grammar-present-perfect.json
    grammar-articles.json
    ...
  /conversations/
    conv-b1-ordering-food.json
    conv-b2-job-interview.json
    ...
```

---

## Database Schema Updates Needed

### New table: unstuck_passages
```sql
CREATE TABLE unstuck_passages (
  id SERIAL PRIMARY KEY,
  passage_id VARCHAR(50) UNIQUE NOT NULL,
  level VARCHAR(5) NOT NULL,  -- B1, B2, C1, C2
  topic VARCHAR(100),
  title VARCHAR(200),
  data JSONB NOT NULL,  -- { text, comprehension, vocabulary, target_phrases }
  created_at TIMESTAMP DEFAULT NOW()
);
```

### New table: unstuck_exercise_pool
```sql
CREATE TABLE unstuck_exercise_pool (
  id SERIAL PRIMARY KEY,
  card_id INTEGER NOT NULL,
  exercise_type VARCHAR(30) NOT NULL,  -- fill_blank, discrimination, usage_boundary, situation, verification
  exercise_id VARCHAR(50) UNIQUE NOT NULL,
  data JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

### New table: unstuck_encounter_log
```sql
CREATE TABLE unstuck_encounter_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES unstuck_users(id),
  card_id INTEGER NOT NULL,
  exercise_id VARCHAR(50) NOT NULL,  -- which specific exercise was shown
  passage_id VARCHAR(50),  -- which passage (if reading-based encounter)
  encounter_type VARCHAR(30) NOT NULL,  -- reading, fill_blank, discrimination, production, verification
  result VARCHAR(20),  -- correct, incorrect, seen
  response_time_ms INTEGER,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_encounter_user_card ON unstuck_encounter_log(user_id, card_id);
```

### Updated: unstuck_progress.data adds mastery_v2
```json
{
  "cardStats": {
    "15": {
      "mastery_v2": 3,
      "encounters_count": 8,
      "unique_contexts": 5,
      "last_reading_encounter": "2026-03-20",
      "last_production": "2026-03-22",
      "retention_check_due": "2026-04-05",
      "suspect": false
    }
  }
}
```

---

## Admin Upload: New Endpoints Needed

```
POST /api/admin/passages/upload     → bulk upload passages
POST /api/admin/exercises/upload    → bulk upload exercise variations  
POST /api/admin/situations/upload   → bulk upload production situations
POST /api/admin/verification/upload → bulk upload verification passages
GET  /api/admin/content-stats       → how many passages, exercises, etc.
```

---

## Summary

Total content to generate NOW:
- 200 reading passages
- 2250 exercise variations (5 per phrase × 450 phrases)
- 1350 production situations (3 per phrase × 450 phrases)
- 100 verification passages
- 60 grammar passages
- 50 conversation scenarios
= **~4000 pieces of content**
= **~725 Opus generations** (batched efficiently)
= **~8-10 days of focused generation**

After upload, app has enough content for:
- 200+ unique reading sessions
- 10+ exercise variations per phrase (nggak pernah lihat soal yang sama)
- 3+ production situations per phrase (nggak pernah diminta nulis di situasi yang sama)
- Verification passages untuk confirm real mastery
- Content untuk 6+ bulan usage tanpa repetisi

---

*Unstuck Mass Content Generation Plan v1.0 — March 2026*
