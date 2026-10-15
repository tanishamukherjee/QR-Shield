# QRShield — AWS Serverless Deployment Guide

This guide documents how QRShield is deployed on AWS: the Python backend on **AWS Lambda** behind a **Function URL**, and the React frontend on **AWS Amplify Hosting**. Every step below was followed for the live deployment.

---

## 1. Live Deployment

| Component | Value |
|---|---|
| **Live website** | **https://main.d3pk8ae3axmish.amplifyapp.com** |
| **Backend API (Lambda Function URL)** | `https://3ftio4oojnj7qitk7rvfqi6evu0wbvms.lambda-url.ap-southeast-2.on.aws/` |
| **AWS Region** | Asia Pacific (Sydney) `ap-southeast-2` |
| **Lambda function** | `QRShield-URL-Analyzer` (Python 3.12, 128 MB, 5 s timeout) |
| **Amplify app** | `QRShield`, branch `main` (manual deploy, no Git connection) |
| **CORS lock** | `ALLOWED_ORIGIN=https://main.d3pk8ae3axmish.amplifyapp.com` |
| **Logs** | CloudWatch log group `/aws/lambda/QRShield-URL-Analyzer` (1-week retention) |

The Function URL is public by design (the website calls it from the visitor's browser). It only analyzes the URL it receives and stores nothing.

```
Visitor's browser ──HTTPS──► Amplify Hosting (CloudFront CDN) ── serves the React app
       │
       └──HTTPS POST {url}──► Lambda Function URL ──► QRShield-URL-Analyzer (Python 3.12)
                                                          └──► CloudWatch Logs (redacted)
```

---

## 2. AWS Account & Cost

The deployment runs on an AWS account created on the **Free plan**:

- New accounts receive **USD $100 in credits** at sign-up and can earn **up to $100 more** by completing five activities from the **Explore AWS** widget on the Console Home page (AWS Budgets, Amazon Bedrock playground, a Lambda web app, launching and terminating an EC2 instance, and creating an RDS database).
- The **Free plan never charges**. It ends after 6 months or when the credits are used up; the account then closes (content is kept for 90 days unless upgraded to a Paid plan).

| AWS Service | Free usage | QRShield usage | Expected cost |
|---|---|---|---|
| **AWS Lambda** | 1,000,000 requests/month always free | Hundreds of requests for the demo | **$0.00** |
| **Lambda Function URL** | Included with Lambda (no API Gateway fee) | Direct HTTPS calls | **$0.00** |
| **AWS Amplify Hosting** | Free tier: 5 GB storage, 15 GB served/month | ~350 KB site | **$0.00** |
| **Amazon CloudWatch Logs** | 5 GB ingestion/month | A few KB, 1-week retention | **$0.00** |
| **EC2 / Load Balancers / NAT** | *Not used* | *Not used* | **$0.00** |

> Set up a **Monthly cost budget** (e.g. $5 with an email alert) in **AWS Budgets** as an extra safety net. This also earns one of the $20 credit activities.

---

## 3. Package the Backend

The backend uses only the Python standard library, so the package is just three files.

```bash
python3 -m unittest discover -s backend/tests -p "test_*.py"   # must print OK
cd backend
zip qrshield_backend.zip lambda_function.py url_analyzer.py rules.py
unzip -l qrshield_backend.zip      # the 3 files must be at the top level, not in a folder
```
On Windows PowerShell:
```powershell
cd backend
Compress-Archive -Path lambda_function.py, url_analyzer.py, rules.py -DestinationPath qrshield_backend.zip -Force
```

The zip is a build artifact and is ignored by git (`*.zip` in `.gitignore`).

---

## 4. Create the Lambda Function

1. Sign in to the [AWS Management Console](https://console.aws.amazon.com/) and pick the region (top bar). **Use the same region for every service** (this deployment uses `ap-southeast-2`); resources in another region are not visible.
2. Open **Lambda → Create function** (the console may label it **Create Event Function**) → **Author from scratch**:
   - **Function name:** `QRShield-URL-Analyzer`
   - **Runtime:** **Python 3.12** (the default is Node.js; it must be changed)
   - **Architecture:** `x86_64` (default) or `arm64`; both work
   - **Execution role:** leave **Custom execution role** off, so Lambda creates a role with basic permissions (CloudWatch logging only)
   - Leave **Function URL**, VPC, Durable execution and the other toggles **off**
3. Click **Create function**.
4. **Code** tab → **Update ▾ / Upload from → .zip file** → choose `qrshield_backend.zip` → **Save**. This replaces the default "Hello World" file; the editor should then list `lambda_function.py`, `rules.py` and `url_analyzer.py`.
5. **Runtime settings:** handler must be `lambda_function.lambda_handler` (the default).
6. **Configuration → General configuration → Edit:** **Memory 128 MB**, **Timeout 5 seconds** → **Save**.
7. **Test** tab → new event:
   ```json
   { "url": "https://paypal.account-verify.xyz/login" }
   ```
   Expected: `"statusCode": 200`, and the body contains `"risk_score": 70`, `"risk_level": "High"`, findings `SEC-TLD-009` and `SEC-SPOOF-010`. The log output shows `QRShield processing request for target: https://paypal.account-verify.xyz/login`.

---

## 5. Create the Function URL

1. **Configuration → Function URL → Create function URL**.
2. **Auth type:** `NONE` (browsers can call it without AWS signing). Lambda automatically attaches the resource-based policy that allows public invocation **only through the Function URL**.
3. **Invoke mode:** `BUFFERED (default)`.
4. ⚠️ **Leave "Configure cross-origin resource sharing (CORS)" unticked.**
   QRShield's handler already sends its own CORS headers and answers the browser's `OPTIONS` preflight itself. If CORS is *also* configured on the Function URL, Lambda adds a second `Access-Control-Allow-Origin` header to every `POST` response, and browsers reject the response ("header contains multiple values"), so every scan fails.
5. **Save** and copy the Function URL (`https://<url-id>.lambda-url.<region>.on.aws/`).

### Verify from a terminal
```bash
URL="https://<url-id>.lambda-url.<region>.on.aws/"     # no space before the closing quote

curl -s $URL
# {"service": "QRShield", "status": "healthy", "engine_version": "1.3.0", ...}

curl -s -X POST $URL -H "Content-Type: application/json" -d '{"url":"https://paypal.account-verify.xyz/login"}'
# {"status": "success", "risk_score": 70, "risk_level": "High", ...}

curl -si -X POST $URL -H "Origin: https://example.com" -H "Content-Type: application/json" \
     -d '{"url":"https://bit.ly/x"}' | grep -ci "access-control-allow-origin"
# 1   (2 means the Function URL CORS box was ticked: untick it)
```

> The first request after a quiet period takes ~1 s (Lambda cold start); later requests take milliseconds.

---

## 6. Build the Frontend for the Live Backend

The backend address is baked into the frontend at build time from `frontend/.env`.

```bash
cd frontend
cp .env.example .env
```
Set `frontend/.env` to (your own URL, no trailing spaces or quotes):
```env
VITE_API_BASE_URL=https://<url-id>.lambda-url.<region>.on.aws/
VITE_ENABLE_OFFLINE_MOCK=false
```
Build and check locally:
```bash
npm ci
npm run build
npm run preview        # http://localhost:4173 → badge must show "Backend Active"
```
Package the build (the **contents** of `dist/`, so `index.html` is at the top level):
```bash
cd dist && zip -r ../qrshield_frontend.zip . && cd ..
unzip -l qrshield_frontend.zip | head
```

> Do this local preview **before** step 8 (`ALLOWED_ORIGIN`). Once the backend is locked to the Amplify domain, `localhost` can no longer call it.

---

## 7. Host the Frontend on AWS Amplify

1. Open **AWS Amplify** (same region) → **Create new app** → **Deploy without Git** → **Next**.
2. **App name:** `QRShield`, **Branch name:** `main`.
3. **Method:** Drag and drop → upload `frontend/qrshield_frontend.zip` (the zip file, not the `dist` folder) → **Save and deploy**.
4. After about a minute the app shows **Deployed** with a link such as `https://main.<app-id>.amplifyapp.com`. Amplify serves it over HTTPS through CloudFront and redirects `http://` to `https://`.
5. Open the link: the badge must show **Backend Active**, and the **Spoofed Brand** preset must score **70 High** with no "Simulation" banner.

### Redeploying after a code change
- **Backend change:** rebuild `qrshield_backend.zip` (section 3) → Lambda **Code → Upload from → .zip file**.
- **Frontend change:** rebuild `qrshield_frontend.zip` (section 6) → Amplify app → branch `main` → **Deploy updates** → drag and drop the new zip.

---

## 8. Restrict the Backend to the Website (`ALLOWED_ORIGIN`)

By default the handler echoes whichever website calls it. Lock it to the Amplify site:

1. **Lambda → QRShield-URL-Analyzer → Configuration → Environment variables → Edit → Add environment variable**
   - **Key:** `ALLOWED_ORIGIN`
   - **Value:** `https://main.<app-id>.amplifyapp.com` (exact origin: no trailing `/`, no quotes)
2. **Save**.

Every response now carries `Access-Control-Allow-Origin: https://main.<app-id>.amplifyapp.com`, so a browser on any **other** website refuses to read the response. Verify:
```bash
curl -si -X POST $URL -H "Origin: https://evil-site.example" -H "Content-Type: application/json" \
     -d '{"url":"https://bit.ly/x"}' | grep -i "access-control-allow-origin"
# access-control-allow-origin: https://main.<app-id>.amplifyapp.com   (not evil-site.example)
```

> CORS is enforced by browsers only. Tools like `curl` can still call the API, which is acceptable because the API is read-only and stores nothing.
>
> **Local development** keeps using the local Python server: set `VITE_API_BASE_URL=http://127.0.0.1:8000` in `frontend/.env` and run `python backend/local_server.py`.

---

## 9. CloudWatch Logs

1. **Lambda → Monitor → View CloudWatch logs** → newest log stream.
2. Each request logs only a redacted target, e.g. `QRShield processing request for target: https://example.com/login?[REDACTED_QUERY]` (credentials and query strings removed), plus Lambda's own `REPORT … Duration: … ms` line.
3. **Set retention:** log group `/aws/lambda/QRShield-URL-Analyzer` → **Actions → Edit retention setting → 1 week**. The default is "Never expire", which slowly accumulates storage.

---

## 10. Verification of the Live Deployment

The live site was tested end to end in Google Chrome (headless, automated):

| Check | Result |
|---|---|
| HTTPS, `http://` → `https://` redirect, our build served | PASS |
| Badge shows **Backend Active** (health check reaches Lambda) | PASS |
| All 8 presets score as documented, analyzed by Lambda (no simulation banner) | PASS |
| All 8 sample QR images decode and score correctly | PASS |
| Invalid input rejected in the browser before reaching Lambda | PASS |
| Copy button, History (view saved result, reload, clear), Methodology tab | PASS |
| Mobile layout at 390 px and 360 px | PASS |
| No console errors | PASS (31/31 checks) |
| Exactly one `Access-Control-Allow-Origin` header per response | PASS |
| A page on another website calling the backend is blocked by the browser | PASS |

---

## 11. Resource Teardown & Cleanup

When the evaluation is complete, remove the resources (on the Free plan the account also closes automatically after 6 months):

1. **Amplify:** app `QRShield` → **App settings → General settings → Delete app**.
2. **Lambda:** `QRShield-URL-Analyzer` → **Actions → Delete function** (this also removes its Function URL).
3. **CloudWatch:** **Logs → Log groups** → `/aws/lambda/QRShield-URL-Analyzer` → **Actions → Delete log group(s)**.
4. **IAM:** **Roles** → `QRShield-URL-Analyzer-role-…` → **Delete**.
5. Delete any resources created for the credit activities (EC2 instances, RDS databases) if they are still running.
