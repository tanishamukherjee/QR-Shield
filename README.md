# QRShield — Cloud-Based QR Code Threat Detection System

[![Python Tests](https://img.shields.io/badge/Python%20Tests-20%2F20%20Passing-brightgreen)](docs/TESTING.md)
[![Frontend](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-blue)](frontend/)
[![Architecture](https://img.shields.io/badge/Cloud-AWS%20Lambda%20Serverless-orange)](docs/ARCHITECTURE.md)
[![Status](https://img.shields.io/badge/Project-College%20Submission-teal)](docs/PRESENTATION_OUTLINE.md)

**QRShield** is a serverless cybersecurity web application that protects users against malicious QR codes ("quishing") by performing pre-click static heuristic threat analysis on embedded URLs.

---

## 🌟 Key Highlights

- **🔒 Client-Side Privacy (Zero-Knowledge Ingestion):** QR code image decoding runs 100% locally in the browser using HTML5 Canvas and `jsQR`. Images are **never** uploaded to servers or stored on disks.
- **⚡ AWS Serverless Backend:** Runs on **AWS Lambda** via a direct **Function URL**. Zero EC2 servers, zero idle costs, and automatic scale-to-zero.
- **🛡️ 12 Deterministic Threat Rules:** Inspects unencrypted HTTP, embedded credentials, raw IP hosts, custom ports, URL shorteners, brand spoofing, and excessive subdomain hierarchies.
- **📊 Transparent Heuristic Scoring:** Generates a deterministic score (0–100) mapped to **Low**, **Medium**, and **High** risk with plain-language explanations and recommended precautions.
- **🚫 Safe Navigation Guarantee:** Decoded links are rendered safely in monospace boxes with copy functionality. QRShield **never** automatically navigates to or opens scanned URLs.
- **📜 Bounded Local History:** Stores recent scans (max 10) in browser `localStorage` with credentials and sensitive query tokens sanitized. Includes a 1-click clear history action.
- **🧪 Offline Simulation Mode:** Features a built-in client-side simulation engine so the application can be evaluated seamlessly even when offline.

---

## 🏗️ Architecture Overview

```
User Device (Browser) 
  └─► QR Image Upload 
        └─► HTML5 Canvas + jsQR (Local Client-Side Decoding)
              └─► Extracted URL Payload
                    └─► HTTPS POST ──► AWS Lambda Function URL
                                         ├─► lambda_function.py (CORS & Validation)
                                         ├─► url_analyzer.py (Normalizer & Scorer)
                                         ├─► rules.py (12 Heuristic Rules)
                                         └─► Amazon CloudWatch (Sanitized Logs)
```

For the complete architectural design and Mermaid flowcharts, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🚀 Quick Start (Local Development)

### 1. Prerequisites
- **Node.js** (v18+) & **npm**
- **Python** (3.10+)

### 2. Run the Automated Backend Tests
Run all 20 automated unit tests covering all rules, scoring boundaries, and Lambda event formats:
```bash
python -m unittest discover -s backend/tests -p "test_*.py" -v
```

### 3. Start the Local Python Server
To run the serverless backend locally using Python's standard library (no extra packages needed):
```bash
python backend/local_server.py
```
*Server starts on `http://127.0.0.1:8000`.*

### 4. Start the React Frontend
In a separate terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

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
│   ├── rules.py                  # 12 static heuristic security rules
│   ├── local_server.py           # Offline development HTTP server
│   └── tests/
│       └── test_analyzer.py      # 20 automated unit tests
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

To deploy QRShield onto AWS Lambda with an HTTPS Function URL:
1. Review the step-by-step instructions in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
2. Package the backend: `Compress-Archive -Path lambda_function.py, url_analyzer.py, rules.py -DestinationPath qrshield_backend.zip`
3. Upload to AWS Lambda (Runtime: Python 3.12, Memory: 128 MB, Handler: `lambda_function.lambda_handler`).
4. Enable **Function URL** with `Auth type: NONE` and configure CORS.
5. Point `VITE_API_BASE_URL` in `frontend/.env` to your new Function URL.

---

## 📑 Academic Prototype Disclaimer

QRShield was developed as an academic engineering prototype. It performs static, non-intrusive URL analysis and does not follow arbitrary redirects or execute dynamic page content. A "Low Risk" result indicates the absence of detected heuristic indicators, not an absolute guarantee of safety.

---

## 📅 Submission Details

- **Project Title:** QRShield — Cloud-Based QR Code Threat Detection System
- **College Submission Deadline:** 25 October 2026
- **Architecture:** Zero-Server AWS Serverless (Lambda Function URL + CloudWatch)
- **License:** MIT License
