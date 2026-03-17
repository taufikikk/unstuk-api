# Unstuck Core Loop Redesign

### The Problem: Users Memorize the UI, Not the Language

---

## What's Broken

User melaporkan: "Saya cuma ingat template. Halaman pertama jawabannya 'I'm on...', jadi besoknya saya jawab itu lagi tanpa benar-benar paham."

Ini bukan edge case — ini **fundamental flaw** di core loop. SRS menandai kartu sebagai "mastered" padahal yang di-master adalah posisi UI, bukan bahasa.

### Root Causes:

1. **Satu kartu = satu cara ditanyakan.** Quiz selalu tanya "Which phrase means X?" dengan 4 opsi yang sama. Setelah 2x lihat, otak cuma pattern-match visual.

2. **Pertanyaan terisolasi dari konteks.** Phrase ditanyakan di vacuum. User nggak pernah diminta memahami phrase di dalam paragraf utuh.

3. **Nggak ada verifikasi di konteks baru.** User "tahu" di dalam app tapi nggak tahu di luar app.

4. **0% acquisition, 100% drilling.** User nggak pernah tenggelam dalam bahasa English — hanya drill butiran kecil.

---

## The New Core Loop: "Encounter → Notice → Understand → Produce → Encounter Again"

### Philosophy Shift:

**OLD:** Teach phrase → drill phrase → drill again → "mastered"
**NEW:** Encounter phrase in context → notice it → understand it → produce it differently → encounter in new context → truly acquired

### Session Structure (5-8 menit):

Setiap session sekarang **bukan kumpulan 8 flashcard**, tapi sebuah **mini-journey** yang berisi campuran activity types:

```
1. ENCOUNTER (Reading)
   User baca passage pendek (100-200 kata) yang mengandung 
   2-3 target phrases. User TIDAK tahu phrase mana yang 
   ditarget. Mereka cuma baca.

2. COMPREHEND (Questions)  
   2-3 pertanyaan tentang ISI passage — bukan tentang 
   grammar atau vocabulary. "Apa yang speaker rasakan?",
   "Kenapa dia bilang itu?"

3. NOTICE (Highlight)
   App highlight 2-3 phrases di passage: "Kamu baru baca 
   'it turns out' di paragraf 2. Ini artinya..."
   Sekarang user lihat phrase itu DI DALAM konteks yang 
   bermakna, bukan di vacuum.

4. UNDERSTAND (Varied Testing)
   Test phrase — tapi BERBEDA setiap kali:
   - Kadang: "Kalimat mana yang maknanya sama?"
   - Kadang: "Isi kalimat BARU ini" (bukan fill-blank yang sama)
   - Kadang: "Susun kalimat BEDA yang pakai phrase ini"
   - Kadang: "Pilih respons yang natural untuk situasi ini"
   PENTING: wrong options, kalimat contoh, dan format 
   exercise berubah SETIAP encounter.

5. PRODUCE (New Context)
   User diminta pakai phrase di konteks yang BARU:
   "Gunakan 'it turns out' untuk menjelaskan situasi ini: 
   [situasi baru yang belum pernah dilihat]"

6. ENCOUNTER AGAIN (Next Session)
   Di session berikutnya, phrase yang sama muncul di 
   passage yang BERBEDA. User encounter secara natural.
   Ini yang memindahkan phrase dari hafalan ke instinct.
```

---

## Detailed Design

### 1. Reading Passages (The Acquisition Engine)

Setiap passage:
- Pendek (100-250 kata, tergantung CEFR level)
- Topik yang relatable (workplace, daily life, opinions)
- Mengandung 2-4 phrases dari card database
- Phrases TIDAK di-highlight saat pertama baca (user baca secara natural dulu)

**Passage dibuat dalam 3 variasi kesulitan:**
- B1: cerita sederhana, kalimat pendek, vocabulary familiar
- B2: opini/argument, kalimat compound, beberapa idiom
- C1: nuanced topic, kalimat complex, implicit meaning

**Passage selection:**
Engine pilih passage berdasarkan:
- User level (dari placement + performance)
- Phrases mana yang due for review (SRS)
- Phrases mana yang baru di-learn tapi belum pernah di-encounter di reading
- Phrases mana yang user jawab benar di quiz tapi belum terbukti di konteks (suspek pattern-memorization)

### 2. Varied Testing (Anti-Pattern-Memorization)

Setiap phrase punya **pool of exercise variations**, bukan 1 exercise yang statis:

**Tipe A: Meaning Match (beda dari quiz biasa)**
- BUKAN "Which phrase means X?" dengan 4 opsi yang sama
- TAPI "Which sentence has the same meaning as the highlighted part?"
  - Kalimat dari passage: "It turns out the meeting was cancelled"
  - Options: 4 kalimat BEDA yang paraphrase / nggak paraphrase
  - Options berubah setiap encounter

**Tipe B: Context Fill (dynamic, bukan template)**
- BUKAN fill blank yang sama setiap kali
- TAPI generate dari pool kalimat baru:
  - Encounter 1: "_____ the server was misconfigured."
  - Encounter 2: "_____ she had already sent the email."  
  - Encounter 3: "_____ nobody told him about the change."
  - Setiap encounter = kalimat baru

**Tipe C: Situation Response**
- "Kamu baru dengar bahwa meeting yang kamu siapkan ternyata sudah dibatalkan kemarin. Bagaimana kamu akan menyampaikan ini ke kolega?"
- User pilih respons yang paling natural dari 4 opsi
- Opsi mengandung target phrase tapi juga distractor yang mirip

**Tipe D: Rearrange (dynamic)**
- Kalimat yang harus disusun BERBEDA setiap encounter
- Bukan kalimat yang sama di-shuffle ulang

**Tipe E: Free Recall with New Situation**
- "Situasi: kamu kira deadline-nya hari Jumat, tapi ternyata hari Rabu. Tulis satu kalimat menggunakan phrase yang kamu pelajari."
- Open-ended, nggak ada 1 jawaban benar
- App check apakah phrase target digunakan dengan benar

### 3. Mastery Redefinition

**OLD Mastery (broken):**
- Mastery 0→5 berdasarkan: jawab benar berapa kali di quiz yang sama
- Masalah: bisa mastery 5 tanpa benar-benar paham

**NEW Mastery (real):**
```
Level 0: Never seen
Level 1: Encountered in reading (saw it in context)
Level 2: Meaning recognized in NEW context (not the original)
Level 3: Produced correctly in fill-blank with NEW sentence
Level 4: Used correctly in free-form response to NEW situation
Level 5: Encountered in 3+ different reading passages AND produced in 2+ different contexts
```

Kunci: **setiap level membutuhkan konteks BARU.** Jawab benar di konteks yang sama nggak naikkan mastery.

### 4. Session Composer (Smart Engine)

Engine compose satu session berdasarkan data user:

```python
def compose_session(user):
    # 1. Pick phrases to work on today
    review_phrases = get_srs_due(user)       # phrases due for review
    new_phrases = get_new_phrases(user, 2)    # 2 new phrases
    suspect_phrases = get_suspect_mastery(user) # high mastery but never tested in new context
    
    target_phrases = review_phrases[:3] + new_phrases + suspect_phrases[:1]
    
    # 2. Find/generate a reading passage containing these phrases
    passage = find_passage_containing(target_phrases, user.level)
    
    # 3. Compose session
    session = [
        ReadingActivity(passage),           # 2 min: read
        ComprehensionQuestions(passage, 3),  # 1 min: understand content
        PhraseNotice(passage, target_phrases), # 30 sec: highlight phrases
        VariedExercise(target_phrases[0], type=random), # 1 min
        VariedExercise(target_phrases[1], type=random), # 1 min
        ProductionExercise(target_phrases[2], new_situation), # 1 min
        WrapUp(summary, next_preview),      # 30 sec
    ]
    
    # Total: ~7 minutes
    return session
```

### 5. "Suspect Mastery" Detection

Sistem baru untuk deteksi apakah user benar-benar paham atau cuma hafal pattern:

```
SUSPECT jika:
- Mastery >= 3 DI SISTEM LAMA (quiz-based)
- TAPI belum pernah encounter phrase di reading passage
- ATAU belum pernah produce di konteks yang berbeda dari template
- ATAU response time < 1.5 detik (terlalu cepat = pattern matching, bukan comprehension)

Jika SUSPECT:
- Jangan hapus mastery (jangan hukum user)
- Tapi JANGAN count sebagai "mastered" 
- Schedule encounter di reading passage berikutnya
- Jika user paham di konteks baru → confirm mastery
- Jika user gagal di konteks baru → downgrade mastery tapi frame positively:
  "You recognized this phrase before! Now let's see it in action..."
```

---

## Migration Plan

### Apa yang TIDAK berubah:
- Auth, database, admin panel, card data structure
- LPP system (tetap ada, tetap personalize messaging)
- SRS algorithm (tetap schedule review, tapi mastery criteria berubah)
- 450 kartu yang sudah ada (tetap di database)

### Apa yang BERUBAH:
- Session bukan lagi "8 flashcards" tapi "mixed activities"
- Mastery bukan dari quiz repetition tapi dari multi-context verification
- Home screen: satu tombol "Today's Session" bukan pilih lesson
- Butuh: reading passages di database (konten baru)
- Butuh: per-phrase exercise variation pools

### Data yang perlu ditambah:
- `unstuck_passages` table (reading passages with embedded phrases)
- `exercise_variations` field per card (multiple fill-blanks, multiple situations)
- `encounter_log` per user per card (track DIMANA dan BAGAIMANA user encounter setiap phrase — reading? quiz? fill? produce?)

---

## What Gets Built

### Sprint 1: Reading + Passage-Embedded Phrases
- Passage model + API
- Reading screen component
- Comprehension questions
- Phrase highlighting post-read
- 20 passages (B1-B2) each containing 2-4 existing phrases
- Session now starts with reading, then exercises on phrases from that reading

### Sprint 2: Varied Testing
- Per-card exercise variation pools (3-5 different fill-blanks, 3-5 different situations)
- Dynamic quiz options (different wrong answers each time)
- Meaning-match exercise type (paraphrase recognition)
- Situation-response exercise type

### Sprint 3: New Mastery + Suspect Detection
- Redefine mastery levels (encounter-based, not repetition-based)
- Encounter log tracking
- Suspect mastery detection
- Graceful downgrade messaging

### Sprint 4: Smart Session Composer
- Mixed-activity session engine
- One-button "Today's Session"
- Session composition based on user data
- Reading + exercises + production in one flow

---

## Success Metric

The redesign succeeds if:

**User CANNOT get mastery 5 by memorizing UI patterns.**

Specifically: if we show a user a phrase they've "mastered" in a brand new reading passage they've never seen, in a sentence they've never encountered, and ask them what it means — they can answer correctly. If they can't, the old system was lying about mastery. The new system should never lie.

---

*Unstuck Core Loop Redesign v1.0 — March 2026*
