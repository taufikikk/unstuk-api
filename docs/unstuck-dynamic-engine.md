# Unstuck Dynamic Exercise Engine

### "1 Juta Variasi" via AI-Generated Exercises at Runtime

---

## The Insight

450 kartu × 1 template per exercise = 450 kemungkinan soal. User hafal semua dalam 2 minggu.

450 kartu × AI-generated exercise setiap encounter = **variasi tak terbatas**. User TIDAK BISA hafal karena soal yang sama tidak pernah muncul dua kali.

---

## Architecture

```
SEKARANG (Static):
Card DB → Fixed exercise → User → Same exercise next time

BARU (Dynamic):
Card DB → Claude API generates FRESH exercise → User → DIFFERENT exercise next time
         ↑                                         |
         |                                         ↓
         ← User's history (jangan repeat context) ←
```

### Per Session Flow:

1. Session Composer pilih 3-5 phrases untuk hari ini (SRS + suspect mastery)
2. Session Composer pilih/generate reading passage yang mengandung phrases itu
3. User baca passage, jawab comprehension
4. Untuk setiap phrase yang perlu di-test:
   a. Check user's encounter_log: konteks apa saja yang SUDAH pernah dilihat?
   b. Kirim ke Claude API: "Generate exercise untuk phrase X, level Y. JANGAN gunakan konteks-konteks ini: [list previous contexts]"
   c. Claude return exercise baru yang fresh
   d. User jawab
   e. Log konteks baru ke encounter_log

---

## Claude API Prompts for Each Exercise Type

### Type 1: Reading Passage Generation

```
System: You are a content generator for an English learning app. 
Generate a short reading passage (150-200 words for B1, 250-350 
for B2, 400-500 for C1).

Rules:
- Topic: {topic from pool: workplace, daily life, tech, culture, opinion}
- Must naturally contain these phrases: {list of 2-4 target phrases}
- Phrases must feel NATURAL in context, not forced
- Include 1-2 phrases the user hasn't learned yet (incidental learning)
- Tone: {casual/professional/narrative} (vary each time)
- Do NOT bold, highlight, or mark the target phrases in any way

The user's level is {CEFR level}.
Previously seen passages covered these topics: {list}. 
Pick a DIFFERENT topic.

Return JSON:
{
  "title": "...",
  "text": "...",
  "comprehension_questions": [
    {"question": "...", "options": ["a","b","c","d"], "correct": 0}
  ],
  "target_phrase_locations": [
    {"phrase": "it turns out", "sentence_index": 3}
  ]
}
```

### Type 2: Meaning Match (Recognition Test)

```
System: Generate a meaning-match exercise for the English phrase 
"{phrase}" (meaning: {meaning}).

Create a NEW sentence using this phrase that the user has NEVER seen.
Do NOT use any of these previously shown sentences:
{list of all previous sentences for this phrase}

Then create 4 paraphrase options — one correct, three wrong.
The wrong options should be plausible but subtly different in meaning.

User level: {CEFR}

Return JSON:
{
  "sentence": "It turns out the deadline was moved to Monday.",
  "question": "What does the highlighted part mean in this sentence?",
  "options": [
    "Ternyata (informasi baru yang mengejutkan)",
    "Mungkin (kemungkinan yang belum pasti)",
    "Sayangnya (berita buruk yang disesali)",
    "Seharusnya (harapan yang tidak terjadi)"
  ],
  "correct": 0
}
```

### Type 3: Discrimination Test

```
System: Generate a discrimination exercise for "{phrase}".

Create 4 sentences. Exactly ONE uses the phrase correctly.
The other 3 use similar-sounding or easily confused phrases 
INCORRECTLY (or use the correct phrase in wrong context).

Common confusions for this phrase: {confused_with list}
User level: {CEFR}

Do NOT reuse any of these previous test sentences:
{list}

Return JSON:
{
  "question": "Which sentence uses the phrase correctly?",
  "options": [
    {"sentence": "...", "correct": true, "explanation": "..."},
    {"sentence": "...", "correct": false, "explanation": "..."},
    ...
  ]
}
```

### Type 4: Dynamic Fill-in-the-Blank

```
System: Generate a fill-in-the-blank exercise for "{phrase}".

Create a NEW sentence with a blank where the phrase should go.
The sentence should be from a DIFFERENT context/situation than 
any of these previously used sentences:
{list of all previous fill-blanks for this phrase}

Provide the correct answer and 3 plausible wrong answers.

Situation pool (pick one NOT yet used): 
{work email, casual chat, meeting, presentation, social media post,
 text message, job interview, code review comment, customer support,
 news article, blog post, restaurant, airport, doctor visit}

User level: {CEFR}

Return JSON:
{
  "situation": "work email",
  "sentence": "_____ the client had already approved the design last week.",
  "correct": "It turns out",
  "wrong": ["It comes out", "It shows up", "It looks like"]
}
```

### Type 5: Situation-Based Production

```
System: Generate a production exercise for "{phrase}" 
(meaning: {meaning}, usage: {usage}).

Create a REALISTIC situation that would naturally prompt someone 
to use this phrase. The situation should be:
- Specific and vivid (not generic)
- Different from all previous situations:
  {list of previous situations}
- Appropriate for the user's context: {Indonesian professional, 
  works in banking/tech}

Return JSON:
{
  "situation": "You just found out that the migration your team 
    spent 3 days debugging wasn't necessary — someone had already 
    fixed the root cause in a different branch but forgot to tell 
    anyone. You're writing a message in Slack to your team.",
  "instruction": "Write 1-2 sentences using 'it turns out'.",
  "example_good": "It turns out someone already fixed the issue 
    in another branch. We spent 3 days on something that was 
    already solved.",
  "evaluation_criteria": {
    "phrase_used": true,
    "grammar_correct": true,
    "context_appropriate": true
  }
}
```

### Type 6: Comprehension Verification (Natural)

```
System: Generate a reading passage (200-300 words) that contains 
the phrase "{phrase}" used naturally. 

The passage should be about: {random topic NOT previously used}

Create 2 comprehension questions where:
- Question 1: can be answered WITHOUT understanding the target phrase
- Question 2: can ONLY be answered correctly if the reader 
  understands what "{phrase}" means in this context

Do NOT highlight or mark the phrase in any way.

User level: {CEFR}

Return JSON:
{
  "passage": "...",
  "questions": [
    {
      "question": "What was the main topic discussed?",
      "options": [...],
      "correct": 0,
      "requires_phrase_understanding": false
    },
    {
      "question": "What surprised the team about the results?",
      "options": [...],
      "correct": 2,
      "requires_phrase_understanding": true
    }
  ]
}
```

---

## Encounter Log (prevents repetition)

Setiap kali user encounter sebuah phrase, log:

```json
{
  "user_id": 123,
  "card_id": 15,
  "phrase": "it turns out",
  "encounters": [
    {
      "date": "2026-03-17",
      "type": "reading",
      "context": "debugging story about config file bug",
      "sentence": "It turns out the bug was in the config file.",
      "result": "seen"
    },
    {
      "date": "2026-03-18",
      "type": "meaning_match",
      "context": "she had already finished the report",
      "sentence": "It turns out she had already finished the report.",
      "result": "correct"
    },
    {
      "date": "2026-03-19",
      "type": "fill_blank",
      "context": "work email about deadline change",
      "sentence": "_____ the deadline was moved to Monday.",
      "result": "correct"
    },
    {
      "date": "2026-03-22",
      "type": "production",
      "context": "slack message about unnecessary migration",
      "user_response": "It turns out someone already fixed it in another branch.",
      "result": "correct"
    }
  ]
}
```

Saat generate exercise baru, SEMUA previous contexts dikirim ke Claude API dengan instruksi "JANGAN gunakan konteks-konteks ini." Ini menjamin variasi infinite.

---

## Backend Implementation

### New API Endpoint:

```
POST /api/exercise/generate
Authorization: Bearer {token}
Body: {
  "card_id": 15,
  "exercise_type": "fill_blank",
  "user_level": "B2"
}

→ Backend:
  1. Load card data (phrase, meaning, usage)
  2. Load encounter_log for this user + card
  3. Extract all previous contexts
  4. Call Claude API with appropriate prompt + exclusion list
  5. Parse response
  6. Return fresh exercise to frontend
  7. After user answers, log new encounter
```

### New API Endpoint for Passages:

```
POST /api/passage/generate
Authorization: Bearer {token}
Body: {
  "target_phrases": ["it turns out", "the thing is", "I was wondering if"],
  "user_level": "B2",
  "exclude_topics": ["debugging", "remote work"]
}

→ Backend:
  1. Load card data for all target phrases
  2. Load user's passage history (topics already covered)
  3. Call Claude API to generate fresh passage
  4. Parse response
  5. Store passage in cache (bisa dipakai user lain di level sama)
  6. Return to frontend
```

### Caching Strategy:

AI-generated content mahal (API cost + latency). Strategy:

```
Layer 1: Pre-generated pool
  - Setiap malam, batch-generate 20 passages + 100 exercises
  - Cover phrases yang paling banyak user butuhkan besok (SRS schedule)
  - Disimpan di database, ditag dengan context
  
Layer 2: User-specific generation
  - Jika pool nggak punya exercise yang belum pernah user lihat → generate real-time
  - Cache hasilnya — user lain yang belum lihat context ini bisa pakai

Layer 3: Fallback static
  - Jika Claude API down → fallback ke static exercises dari card data
  - Lebih baik static exercise daripada no exercise
```

### Cost Estimation:

```
Per exercise generation:
  - ~200 input tokens + ~300 output tokens = ~500 tokens
  - Claude Sonnet: ~$0.0015 per exercise

Per passage generation:
  - ~300 input tokens + ~800 output tokens = ~1100 tokens
  - Claude Sonnet: ~$0.0033 per passage

Per user per day (1 session):
  - 1 passage + 5 exercises = $0.0033 + $0.0075 = ~$0.01/day
  - Per month: ~$0.30/user

100 users: ~$30/month
1000 users: ~$300/month

With caching (reuse passages across users at same level):
  - Effective cost drops 60-70%
  - 1000 users: ~$100/month
```

---

## What Changes from Static Cards

### Card data TETAP di database:
```json
{
  "id": 15,
  "phrase": "it turns out",
  "meaning": "Ternyata",
  "meaningEn": "Discovering something unexpected",
  "usage": "Revealing surprising information that was just learned",
  "confused_with": ["it comes out", "it shows up", "it looks like"],
  "contexts_pool": ["work", "daily life", "tech", "social", "news"]
}
```

### Card data yang DIHAPUS (nggak dipakai lagi):
```
- wrongOptions (generated dynamically)
- fillBlank (generated dynamically)
- fillAnswer (generated dynamically)
- rearrange (generated dynamically)
- context (generated dynamically — satu contoh tetap ada sebagai "seed")
```

### Yang DITAMBAH per card:
```json
{
  "confused_with": ["it comes out", "it shows up"],
  "difficulty_modifiers": {
    "B1": "use in simple daily situations",
    "B2": "use in professional context",
    "C1": "use with nuance — ironic, formal, or emphatic"
  }
}
```

---

## Session Flow (Final)

```
User klik "Today's Session"
        ↓
Session Composer:
  - Check SRS: which phrases due?
  - Check suspect mastery: which phrases need verification?
  - Check encounter_log: which phrases never seen in reading?
  - Pick 3-5 target phrases
        ↓
Generate/Select Reading Passage:
  - Contains target phrases naturally
  - Topic user hasn't read before
  - Level matched to user
        ↓
User reads passage (2-3 min)
        ↓
Comprehension questions (1 min)
  - Tests CONTENT understanding
  - One question requires understanding target phrase
        ↓
Phrase highlight + brief explanation (30 sec)
        ↓
For each target phrase (depending on mastery level):
  Level 1→2: AI-generated meaning match (new context)
  Level 2→3: AI-generated discrimination test
  Level 3→4: AI-generated production situation
  Level 4→5: Reading passage without highlight (natural comprehension)
  Level 5→6: (scheduled after 14 day gap)
        ↓
Session summary + encouragement (30 sec)
        ↓
Total: 5-8 minutes
Every exercise: FRESH, never seen before, impossible to memorize
```

---

## "1 Juta Pola"

Dengan 450 phrases × unlimited AI-generated contexts:
- Setiap phrase bisa muncul di puluhan ribu kalimat berbeda
- Setiap fill-blank, discrimination test, situation — selalu baru
- Encounter log memastikan nggak ada repetisi
- User yang pakai app selama 1 tahun nggak akan pernah lihat exercise yang sama dua kali

Ini bukan 1 juta pola yang ditulis manual.
Ini **mesin yang bisa menghasilkan variasi tak terbatas**, guided oleh data tentang apa yang user sudah tahu dan belum tahu.

---

*Unstuck Dynamic Exercise Engine v1.0 — March 2026*
