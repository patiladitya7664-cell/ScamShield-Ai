# ScamShield AI — API Reference

Base URL: `http://localhost:5000/api`

Protected routes require `Authorization: Bearer <token>`. Obtain a token from login. Use synthetic evidence while demonstrating.

## Health

| Method | Path | Auth | Purpose |
|---|---|---:|---|
| GET | `/health` | No | Backend and database health |
| GET | `/analysis/health` | No | Confirms the analysis router is mounted |

## Authentication

| Method | Path | Auth | Body |
|---|---|---:|---|
| POST | `/auth/register` | No | `{ "name": "Demo User", "email": "demo@example.test", "password": "StrongPass123" }` |
| POST | `/auth/login` | No | `{ "email": "demo@example.test", "password": "StrongPass123" }` |
| GET | `/auth/me` | Yes | — |

## Analysis and cases

| Method | Path | Auth | Purpose |
|---|---|---:|---|
| POST | `/analysis/analyze` | Yes | Analyze `{ "evidenceType": "message", "evidence": "..." }`; returns explainable risk assessment and unverified indicators |
| POST | `/cases` | Yes | Create a case linked to an analysis using `analysisId`, title, category, risk level, and indicators |
| GET | `/cases?limit=50` | Yes | List the user's cases and linked analysis summary |
| GET | `/cases/:id` | Yes | Read one of the user's cases |
| PATCH | `/cases/:id` | Yes | Update case status or record classification feedback |
| DELETE | `/cases/:id` | Yes | Delete a case owned by the user |
| GET | `/dashboard/overview` | Yes | Counts, risk/category distribution, and recent analysis activity |

Supported evidence text types: `message`, `url`, `call`, `transaction`, `screenshot`, `email`. Current browser UI provides message, URL, call transcript, and transaction text inputs. Screenshot upload/OCR is not implemented.

## Intelligence lookup

`GET /intelligence/health` confirms the lookup router is available. `POST /intelligence/analyze` (JWT required) accepts `{ "indicatorType": "phone", "indicator": "+919876543210" }`. Supported types are `phone`, `url`, `upi`, and `keyword`. The lookup searches the current user's saved assessments only; a match is an unverified clue, and no match does not establish safety.

## Report output

There is no government submission API. The Reports screen presents the user's case records, supports CSV export, and opens a print-friendly draft that the user may save as PDF using the browser.
