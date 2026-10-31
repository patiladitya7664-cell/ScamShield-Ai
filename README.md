# ScamShield AI

ScamShield AI is a hackathon prototype for reviewing suspicious messages, explaining rule-based warning signs, showing victim-safety guidance, and organising case records. Analysis is a risk assessment, not proof of fraud. The prototype does not contact suspected scammers or submit reports to government systems.

## Current working scope

- Node.js/Express API with MongoDB persistence, JWT login, case history, dashboard summaries, and rule-based analysis across five fraud categories.
- Existing HTML/CSS/JavaScript screens for landing, dashboard, detection, agents, intelligence, analytics, reports, settings, and account access.
- Indicator searches are limited to the signed-in user's saved analyses; matches remain unverified clues.
- Report drafts can be printed or saved as PDF through the browser print dialog. No government submission is performed.
- The Python agent files are scaffolding and are not currently part of the running analysis path.

## Local setup

1. Install Node.js and run MongoDB locally.
2. From the project root, create the private environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Generate a unique `JWT_SECRET` in `.env`; do not share or commit `.env`:

   ```powershell
   $bytes = New-Object byte[] 64
   $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
   $rng.GetBytes($bytes)
   $secret = [Convert]::ToBase64String($bytes)
   $envPath = Join-Path (Get-Location) ".env"
   $envText = [IO.File]::ReadAllText($envPath)
   $envText = [regex]::Replace($envText, '(?m)^JWT_SECRET=.*$', "JWT_SECRET=$secret")
   [IO.File]::WriteAllText($envPath, $envText, [Text.UTF8Encoding]::new($false))
   $rng.Dispose()
   ```
4. Start the backend:

   ```powershell
   cd backend
   npm install
   npm run dev
   ```

5. In VS Code, start Live Server on port 5500. If it serves the project root, open `http://127.0.0.1:5500/frontend/index.html`; if it serves the `frontend` folder directly, open `http://127.0.0.1:5500/index.html`. The allowed browser origin must match `FRONTEND_URL` (default `http://127.0.0.1:5500`).
6. Register an account and sign in. Try evidence analysis from Detection, then open **AI Agents** and run the prefilled synthetic message demo. The agent demo calls the authenticated `/api/agents/run` endpoint and does not save a case.

## API routes

- `GET /api/health`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me` (JWT required)
- `GET /api/analysis/health`
- `POST /api/analysis/analyze` (JWT required)
- `GET|POST /api/cases` and `GET|PATCH|DELETE /api/cases/:id` (JWT required)
- `GET /api/dashboard/overview` (JWT required)
- `POST /api/intelligence/analyze` (JWT required)
- `POST /api/agents/run` (JWT required)
- `/api/notifications` (JWT required)

## Privacy and demo limitations

Raw submitted evidence is not stored by the analysis controller. The database stores assessment fields, extracted indicators, and linked case metadata. Use synthetic data for demonstrations. The analyzer is rule-based; audio transcription, screenshot OCR, live-call interception, deepfake screening, external threat feeds, and direct cybercrime portal integration are not implemented.
