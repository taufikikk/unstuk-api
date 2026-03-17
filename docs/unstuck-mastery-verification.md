# Unstuck Mastery Verification System

### "Kamu nggak boleh lulus kalau belum benar-benar paham."

---

## Prinsip

Mastery di Unstuck harus memenuhi SEMUA kriteria ini secara independen:

1. **Bisa mengenali phrase di konteks yang belum pernah dilihat** (recognition in new context)
2. **Bisa menjelaskan KAPAN phrase ini digunakan** (usage understanding)
3. **Bisa membedakan phrase ini dari yang mirip** (discrimination)
4. **Bisa memproduksi phrase di situasi baru** (production)
5. **Bisa memahami phrase saat muncul di bacaan tanpa bantuan** (naturalistic comprehension)
6. **Masih bisa melakukan 1-5 setelah 2 minggu tanpa review** (long-term retention)

Gagal di satu saja = belum mastered. Tidak ada jalan pintas.

---

## 7 Level Mastery (menggantikan 0-5 lama)

```
Level 0: UNSEEN
  Belum pernah ketemu.

Level 1: ENCOUNTERED  
  Pernah lihat di reading passage.
  Test: tidak ada (baru lihat, belum ditanya)
  
Level 2: RECOGNIZED
  Bisa pilih arti yang benar SAAT phrase di-highlight.
  Test: "Apa arti 'it turns out' di kalimat ini?"
  Requirement: benar di 2 kalimat BERBEDA (bukan yang dari passage pertama)

Level 3: DISCRIMINATED
  Bisa bedakan dari phrase yang mirip / sering tertukar.
  Test: "Kalimat mana yang BENAR?"
    a) "It turns out the meeting was cancelled" ✓
    b) "It turns up the meeting was cancelled" ✗
    c) "It comes out the meeting was cancelled" ✗
    d) "It finds out the meeting was cancelled" ✗
  Test 2: "Kapan kamu TIDAK akan pakai 'it turns out'?"
    a) Saat menyampaikan informasi mengejutkan ✗ (ini justru kapan dipake)
    b) Saat minta izin ✓ (ini bukan fungsinya)
  Requirement: benar di kedua test

Level 4: PRODUCED
  Bisa pakai phrase di kalimat sendiri untuk situasi yang diberikan.
  Test: "Kamu baru tahu bahwa proyek ternyata sudah dibatalkan minggu lalu 
         tapi nggak ada yang kasih tahu kamu. Tulis kalimat menggunakan 
         'it turns out'."
  Validation: app check apakah phrase digunakan + grammar benar + konteks tepat
  Requirement: produce di 2 situasi BERBEDA yang belum pernah dilihat

Level 5: COMPREHENDED NATURALLY
  Bisa memahami phrase di reading passage tanpa highlight, tanpa bantuan.
  Test: baca passage baru yang mengandung phrase → jawab comprehension question
        yang jawabannya TERGANTUNG pada pemahaman phrase tersebut.
  Contoh: passage berisi "It turns out the server issue was caused by a 
          misconfigured firewall, not the code changes everyone blamed."
          Question: "What surprised the team?"
          → Jawaban benar membutuhkan pemahaman bahwa "it turns out" = 
            informasi mengejutkan yang baru diketahui
  Requirement: benar di passage yang BELUM pernah dibaca

Level 6: RETAINED
  Masih bisa level 2-5 setelah TIDAK review selama 14 hari.
  Test: setelah 14 hari gap, app jadwalkan "retention check" —
        satu exercise dari Level 3 (discrimination) + satu dari Level 4 (production)
  Jika lulus: MASTERED ✓ (final)
  Jika gagal: turun ke Level 3, review cycle dimulai lagi
  
Level 7: MASTERED
  Semua level terpenuhi. Phrase ini milik kamu.
  Kartu masuk "Mastered Deck" — muncul sangat jarang, hanya untuk maintenance.
```

---

## Verification Gates

Setiap naik level harus melewati "gate" — nggak bisa di-skip, nggak bisa di-cheat:

### Gate 1→2 (Encountered → Recognized)
```
Trigger: user baca passage yang mengandung phrase
Wait: minimal 1 session berikutnya (bukan langsung setelah baca)
Test: tampilkan phrase di kalimat BARU, tanya artinya
Anti-cheat: 
  - Kalimat yang ditampilkan BERBEDA dari yang di passage
  - 4 opsi jawaban berubah setiap attempt
  - Response time di-track (< 2 detik = suspect, schedule retest)
```

### Gate 2→3 (Recognized → Discriminated)
```
Trigger: sudah recognized di 2 konteks berbeda
Test 1: bedakan dari phrase yang mirip
Test 2: identifikasi situasi yang TIDAK tepat untuk phrase ini
Anti-cheat:
  - Wrong options bukan yang sama setiap kali
  - "Kapan TIDAK pakai" test mencegah hafalan "kapan pakai"
  - Harus benar di KEDUA test dalam session BERBEDA
```

### Gate 3→4 (Discriminated → Produced)
```
Trigger: lulus discrimination
Test: tulis kalimat sendiri menggunakan phrase untuk situasi baru
Validation:
  - Phrase digunakan? (string match)
  - Grammar benar? (pattern check)
  - Konteks tepat? (situation relevance — bisa pakai simple heuristics)
Anti-cheat:
  - Situasi yang diberikan SELALU baru (pool of 5+ situations per phrase)
  - Copy-paste dari contoh sebelumnya terdeteksi (similarity check)
  - Harus produce di 2 situasi berbeda di 2 session berbeda
```

### Gate 4→5 (Produced → Comprehended Naturally)
```
Trigger: lulus production 2x
Test: baca passage baru, jawab comprehension question yang membutuhkan 
      pemahaman phrase (TANPA phrase di-highlight, tanpa hint)
Anti-cheat:
  - Phrase tidak di-bold, tidak di-highlight, tidak ditandai
  - Comprehension question bisa dijawab HANYA jika paham phrase
  - Passage belum pernah dibaca sebelumnya
```

### Gate 5→6 (Comprehended → Retained)
```
Trigger: lulus natural comprehension
Wait: 14 HARI tanpa encounter phrase ini
Test: discrimination + production di konteks baru
Anti-cheat:
  - Delay yang real — nggak bisa dipercepat
  - Konteks test belum pernah dilihat
```

### Gate 6→7 (Retained → Mastered)
```
Trigger: lulus retention check
Status: MASTERED
Maintenance: muncul 1x per bulan di reading passage (passive encounter)
             jika gagal comprehension → turun ke Level 5
```

---

## Contoh Journey Satu Phrase: "it turns out"

```
Day 1, Session 1:
  → Baca passage tentang debugging: "...it turns out the bug was in 
    the config file, not the code..."
  → Jawab comprehension questions tentang isi cerita
  → App highlight: "Kamu baca 'it turns out' — artinya 'ternyata'"
  → Status: Level 1 (ENCOUNTERED)

Day 2, Session 2:
  → Quiz: "Apa arti 'it turns out' di kalimat: 'It turns out she had 
    already finished the report'?"
  → Options berbeda dari hari kemarin
  → Benar!
  → Status: masih Level 1 (butuh 1 lagi di konteks beda)

Day 2, Session 2 (lanjut):
  → Quiz lagi di kalimat ketiga: "It turns out the flight was delayed 
    by three hours"
  → Benar!
  → Status: Level 2 (RECOGNIZED) ✓

Day 3, Session 3:
  → Test: "Mana yang BENAR?"
    a) "It turns out..." ✓   b) "It turns up..." ✗
  → Test: "Kapan kamu TIDAK pakai 'it turns out'?"
    a) Menyampaikan berita mengejutkan (INI fungsinya)
    b) Meminta izin ✓ (BUKAN fungsinya)
  → Benar kedua!
  → Status: masih Level 2 (butuh lulus discrimination di session lain juga)

Day 4, Session 4:
  → Discrimination retest (soal beda)
  → Benar!
  → Status: Level 3 (DISCRIMINATED) ✓

Day 5, Session 5:
  → Situasi: "Kamu kirim email ke teman. Kamu baru tahu bahwa 
    restoran favorit kalian ternyata sudah tutup permanen. 
    Tulis satu kalimat."
  → User tulis: "It turns out our favorite restaurant has permanently 
    closed."
  → Validation: phrase used ✓, grammar OK ✓, context appropriate ✓
  → Status: masih Level 3 (butuh produce 1 lagi di situasi beda)

Day 7, Session 7:
  → Situasi baru: "Kamu di meeting. Baru tahu project manager resign 
    minggu lalu tapi nggak ada yang kasih tahu tim. Sampaikan ke kolega."
  → User tulis: "It turns out the PM resigned last week and nobody 
    told us."
  → Validation OK
  → Status: Level 4 (PRODUCED) ✓

Day 9, Session 9:
  → Baca passage baru tentang startup failure (belum pernah baca)
  → Passage mengandung "it turns out" tapi TIDAK di-highlight
  → Comprehension question: "What was the real reason the startup failed?"
  → Jawaban benar membutuhkan pemahaman "it turns out their market 
    research was based on outdated data"
  → User jawab benar
  → Status: Level 5 (COMPREHENDED NATURALLY) ✓

Day 9-23: phrase TIDAK muncul sama sekali (14 hari gap)

Day 23, Session ~20:
  → Retention check muncul
  → Discrimination test (soal baru): benar ✓
  → Production test (situasi baru): benar ✓
  → Status: Level 6 (RETAINED) → Level 7 (MASTERED) ✓✓✓

Total: ~20 hari, ~10 sessions, phrase di-encounter di 5+ konteks berbeda
Ini REAL mastery, bukan hafalan.
```

---

## Handling Failure di Setiap Gate

Prinsip utama: **gagal bukan hukuman, tapi informasi.**

```
Gagal di Gate Recognition (Level 1→2):
  → "Kamu pernah lihat phrase ini di bacaan kemarin. 
     Nggak apa-apa kalau belum nempel — kita akan ketemu 
     lagi di bacaan besok."
  → Schedule encounter di passage baru besok
  → TIDAK turun level (masih Level 1)

Gagal di Gate Discrimination (Level 2→3):
  → "Phrase ini mirip dengan [yang tertukar]. Ini bedanya: [penjelasan]"
  → Tampilkan side-by-side comparison
  → Schedule retest di session berikutnya dengan soal beda
  → TIDAK turun level

Gagal di Gate Production (Level 3→4):
  → "Kamu hampir benar! Ini contoh yang natural: [contoh]"
  → Tampilkan 2-3 contoh kalimat lain
  → Schedule situasi baru di session berikutnya
  → TIDAK turun level

Gagal di Gate Natural Comprehension (Level 4→5):
  → Re-highlight phrase di passage yang baru dibaca
  → "Phrase ini muncul di paragraf 2. Ini yang artinya di konteks ini..."
  → Schedule passage baru yang mengandung phrase
  → TIDAK turun level

Gagal di Retention Check (Level 5→6):
  → "Sudah 2 minggu! Wajar kalau agak lupa. Let's refresh."
  → Turun ke Level 3 (bukan ke 0)
  → Masuk review cycle: discrimination → production → comprehension → retention lagi
  → Messaging: "Kamu dulu pernah menguasai ini. Kita cuma perlu refresh."
```

---

## Anti-Cheat Summary

| Cheat Attempt | Prevention |
|---|---|
| Hafal posisi jawaban di UI | Options berubah setiap attempt |
| Hafal kalimat contoh | Pool 5+ kalimat berbeda per phrase |
| Hafal fill-blank template | Fill blank berubah setiap encounter |
| Response terlalu cepat (pattern match) | Track response time, retest jika < 2 detik |
| Copy-paste dari contoh sebelumnya | Similarity check di production exercise |
| Naik mastery tanpa real comprehension | Gate system: harus lulus di konteks BARU |
| Claim mastery tanpa long-term retention | 14-hari gap sebelum final mastery |
| Skip reading, langsung drill | Session DIMULAI dari reading, exercise tentang phrase dari reading itu |

---

## Angka-Angka

- Minimum encounters sebelum MASTERED: **8-12 encounters** across **5+ konteks berbeda** over **20+ hari**
- Minimum exercise variations per phrase: **5 fill-blanks, 3 situations, 3 discrimination tests**
- Retention gap sebelum final check: **14 hari**
- Maintenance setelah mastered: **1 passive encounter per bulan**
- Estimated time to master 1 phrase: **2-3 minggu** (vs sekarang: 2-3 hari tapi palsu)
- Estimated time to genuinely master 100 phrases: **2-3 bulan**
- Estimated time B1 → genuine B2: **4-6 bulan** (vs marketing hype "30 hari")

Ini lebih lambat dari sistem lama. Tapi yang "mastered" di sistem baru itu **beneran mastered** — bisa dipake di meeting, bisa dipake di email, bisa dipake di percakapan, bukan cuma bisa jawab quiz di app.

---

*Unstuck Mastery Verification System v1.0 — March 2026*
