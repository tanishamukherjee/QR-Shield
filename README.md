# QRShield — Cloud-Based QR Code Threat Detection System

[![Python Tests](https://img.shields.io/badge/Python%20Tests-36%2F36%20Passing-brightgreen)](docs/TESTING.md)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-blue)](frontend/)
[![Architecture](https://img.shields.io/badge/Cloud-AWS%20Lambda%20Serverless-orange)](docs/ARCHITECTURE.md)
[![Live](https://img.shields.io/badge/Live-AWS%20Amplify-success)](https://main.d3pk8ae3axmish.amplifyapp.com)
[![Status](https://img.shields.io/badge/Project-College%20Submission-teal)](docs/PRESENTATION_OUTLINE.md)

**QRShield** is a serverless cybersecurity web application that protects users against malicious QR codes ("quishing") by performing pre-click static heuristic threat analysis on embedded URLs.

### 🌐 Live Demo: **[https://main.d3pk8ae3axmish.amplifyapp.com](https://main.d3pk8ae3axmish.amplifyapp.com)**
Hosted on **AWS Amplify**, with the threat engine running on **AWS Lambda** (Sydney, `ap-southeast-2`). Try the 8 test presets, or upload any image from [`sample_qr_codes/`](sample_qr_codes/).

---

## 🌟 Key Highlights

- **🔒 Client-Side Privacy (Zero-Knowledge Ingestion):** QR code image decoding runs 100% locally in the browser using HTML5 Canvas and `jsQR`. Images are **never** uploaded to servers or stored on disks.
- **⚡ AWS Serverless Backend:** Runs on **AWS Lambda** via a direct **Function URL**, with the frontend on **AWS Amplify Hosting**. Zero EC2 servers, zero idle costs, and automatic scale-to-zero.
- **🛡️ 16 Deterministic Threat Rules:** Inspects unencrypted HTTP, embedded credentials, raw and disguised IP hosts, custom ports, URL shorteners, brand spoofing, look-alike (typosquatted) brand names, international look-alike characters, and excessive subdomain hierarchies.
- **🌐 Browser-Equivalent Parsing:** Reads each URL exactly as a browser would (backslash tricks, decimal/hex IPs, punycode), so the analysis matches the real destination.
- **📊 Transparent Heuristic Scoring:** Generates a deterministic score (0–100) mapped to **Low**, **Medium**, and **High** risk with plain-language explanations and recommended precautions. Any **CRITICAL** deception trick is always High risk.
- **🚫 Safe Navigation Guarantee:** Decoded links are rendered safely in monospace boxes with copy functionality. QRShield **never** automatically navigates to or opens scanned URLs.
- **📜 Bounded Local History:** Stores recent scan results (max 10) in browser `localStorage` with credentials and sensitive query tokens sanitized. Saved results can be viewed again; includes a 1-click clear history action.
- **🧪 Offline Simulation Mode:** Features a built-in client-side simulation engine so the application can be evaluated seamlessly even when offline.

---

## 🏗️ Architecture Overview

```
User Device (Browser) ◄── React app served over HTTPS by AWS Amplify Hosting (CloudFront CDN)
  └─► QR Image Upload 
        └─► HTML5 Canvas + jsQR (Local Client-Side Decoding)
              └─► Extracted URL Payload
                    └─► HTTPS POST ──► AWS Lambda Function URL
                                         ├─► lambda_function.py (CORS & Validation)
                                         ├─► url_analyzer.py (Normalizer & Scorer)
                                         ├─► rules.py (16 Heuristic Rules)
                                         └─► Amazon CloudWatch (Sanitized Logs)
```

For the complete architectural design and Mermaid flowcharts, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
- **Node.js** (v18+) & **npm**
- **Python** (3.10+)

### 2. Run the Automated Backend Tests
Run all 36 automated unit tests covering all rules, scoring boundaries, browser-equivalent parsing, and Lambda event formats:
```bash
python -m unittest discover -s backend/tests -p "test_*.py" -v
```
Check that the offline simulation still matches the Python backend:
```bash
cd frontend && npm install && npm run verify:parity
```

### 3. Start the Local Python Server
To run the serverless backend locally using Python's standard library (no extra packages needed):
```bash
python backend/local_server.py
```
*Server starts on `http://127.0.0.1:8000`.*

### 4. Point the Frontend at the Backend
Create `frontend/.env` from the example file. It already points to the local server (`http://127.0.0.1:8000`):
```bash
cp frontend/.env.example frontend/.env        # macOS / Linux
copy frontend\.env.example frontend\.env      # Windows
```
> **Skip this step and the site still runs, but only in offline simulation:** the badge in the top-right shows *Offline Simulation* and no request ever reaches the Python backend. For a demo of the real backend, the badge must show **Backend Active**.

### 5. Start the React Frontend
In a separate terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser and check that the badge shows **Backend Active**.

---

## 📂 Project Structure

```
qrshield/
├── frontend/                     # React + Vite Client Application
│   ├── src/
│   │   ├── components/           # UI Components (Scanner, Results, History, etc.)
│   │   ├── services/             # API client & offline simulation engine
│   │   ├── utils/                # jsQR decoder & localStorage history manager
│   │   ├── App.jsx               # Application root
│   │   └── App.css               # Cybersecurity design system
│   ├── package.json
│   └── .env.example
├── backend/                      # Python AWS Lambda Backend
│   ├── lambda_function.py        # Lambda handler with CORS & CloudWatch logging
│   ├── url_analyzer.py           # Analysis orchestrator & risk scoring engine
│   ├── rules.py                  # 16 static heuristic security rules
│   ├── local_server.py           # Offline development HTTP server
│   └── tests/
│       ├── test_analyzer.py      # 35 rule, scoring & Lambda handler tests
│       ├── test_parity.py        # Shared parity cases (Python side)
│       └── parity_cases.json     # 48 cases checked against both engines
├── sample_qr_codes/              # 8 sample QR images matching the UI presets
├── docs/                         # Comprehensive Documentation
│   ├── ARCHITECTURE.md                  # System architecture & Mermaid diagrams
│   ├── IMPLEMENTATION.md                # Technical code walkthrough & rule weights
│   ├── SECURITY_AND_CLASSIFICATION.md   # Threat classification model & security engineering
│   ├── TESTING.md                       # Test matrix, results & verification
│   ├── DEPLOYMENT.md                    # AWS Lambda Function URL step-by-step guide
│   └── PRESENTATION_OUTLINE.md          # 7–8 minute college presentation script
├── .gitignore
└── README.md
```

---

## ☁️ AWS Cloud Deployment

QRShield is live on AWS:

| Component | Where |
|---|---|
| Website | **https://main.d3pk8ae3axmish.amplifyapp.com** (AWS Amplify Hosting) |
| Backend API | AWS Lambda `QRShield-URL-Analyzer` (Python 3.12) via its Function URL, region `ap-southeast-2` |
| Logs | Amazon CloudWatch, with credentials and query strings redacted |

The full step-by-step guide is in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). In short:
1. Package the backend (from `backend/`):
   - macOS / Linux: `zip qrshield_backend.zip lambda_function.py url_analyzer.py rules.py`
   - Windows PowerShell: `Compress-Archive -Path lambda_function.py, url_analyzer.py, rules.py -DestinationPath qrshield_backend.zip`
2. Create the Lambda function (Runtime: Python 3.12, Memory: 128 MB, Timeout: 5 s, Handler: `lambda_function.lambda_handler`) and upload the zip.
3. Create a **Function URL** with `Auth type: NONE`. **Leave its CORS option unticked**: the handler already sends CORS headers, and enabling both makes browsers reject every response.
4. Set `VITE_API_BASE_URL` in `frontend/.env` to the Function URL, run `npm run build`, zip the contents of `frontend/dist/`, and deploy it on **AWS Amplify → Deploy without Git**.
5. Set the Lambda environment variable `ALLOWED_ORIGIN` to the Amplify site's address so only the website can call the backend from a browser.

---

## 📑 Academic Prototype Disclaimer

QRShield was developed as an academic engineering prototype. It performs static, non-intrusive URL analysis and does not follow arbitrary redirects or execute dynamic page content. A "Low Risk" result indicates the absence of detected heuristic indicators, not an absolute guarantee of safety.

---

## 📅 Submission Details

- **Project Title:** QRShield — Cloud-Based QR Code Threat Detection System
- **College Submission Deadline:** 25 October 2026
- **Live Demo:** https://main.d3pk8ae3axmish.amplifyapp.com
- **Architecture:** Zero-Server AWS Serverless (Amplify Hosting + Lambda Function URL + CloudWatch)
- **License:** MIT License
