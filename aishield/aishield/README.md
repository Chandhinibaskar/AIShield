# 🛡️ AIShield — Think Before You Click.
Personal Digital Safety Copilot (Digital Safety & Cybersecurity track).

## Run
```
cp .env.example .env
docker compose up -d db
cd backend && npm install && npm run seed && npm run dev   # API on :4000
```
Demo account (demo only): `demo@aishield.ai` / `Demo@12345`

## Risk methodology
`backend/src/riskEngine.ts` combines weighted signals (URL reputation 20, domain anomaly 20, keywords 15, credential 15, urgency 10, financial 10, AI 10) into 0–100: SAFE <30, SUSPICIOUS 30–59, HIGH RISK 60–79, CRITICAL 80+. With no API key, results are labelled **AIShield Demo Analysis**; feed an LLM score into `analyze(type, input, aiScore)`.

## API
POST /api/auth/register|login · GET /api/auth/me · POST /api/scan/{url,message,email,screenshot,qr} · GET/DELETE /api/scans(/:id) · GET /api/analytics

Do not submit passwords, OTPs, or private keys to the scanner.
