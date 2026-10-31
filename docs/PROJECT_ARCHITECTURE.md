# ScamShield AI — Current Architecture

## Runtime flow

```text
Browser (HTML/CSS/JavaScript)
  ├─ Sign in / register
  ├─ Submit message, URL, call transcript, or transaction text
  ├─ View explainable assessment and safety steps
  └─ Review cases, analytics, indicators, and printable report drafts
           │ REST + JWT
           ▼
Node.js / Express API
  ├─ Authentication and per-user authorization
  ├─ Rule-based evidence assessment
  ├─ MongoDB analysis and case records
  ├─ Dashboard aggregation
  └─ Per-user search of previously observed indicators
           │
           ▼
MongoDB
  ├─ Users (password hash only)
  ├─ Analyses (no original evidence text)
  └─ Cases (linked analysis, status, unverified clues, feedback)
```

## Agent-aligned responsibilities in this prototype

- **Guardian role:** `backend/src/services/aiService.js` applies explicit phrase rules, selects one possible category, calculates a 0–100 score, and returns reasons. It is a deterministic rules engine, not an LLM or trained model.
- **Victim Safety role:** `frontend/js/detection.js` displays category-specific safety steps. It does not contact banks, authorities, or suspected senders.
- **Decoy role:** `frontend/js/decoy-chat.js` provides a consent-gated, local scripted practice chat. It sends no messages outside the browser and does not connect to a real scammer.
- **Intelligence role:** `backend/src/controllers/intelligenceController.js` searches only the signed-in user's saved, structured clues. Search matches are unverified and are not identity attribution.

## Data and privacy boundary

The submitted evidence is analyzed in memory and is not copied into the Analysis or Case records. Stored fields include a random evidence reference, evidence type, category, risk score/level, short assessment summary, detected rules, extracted indicators, and timestamps. Reports are printable drafts for human review; the application does not submit them to `cybercrime.gov.in`.

## Known scope limits

The Python files under `ai-engine/` are scaffolding and are not called by the current backend. Screenshot OCR, audio transcription, live call interception, external threat feeds, deepfake screening, real-world scam-baiting, and direct government portal submission are not implemented.
