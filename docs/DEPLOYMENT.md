# QRShield — AWS Serverless Deployment Guide

> **Important Deployment Notice:**  
> In accordance with safety principles, do not execute cloud deployments or create public cloud resources without explicit user approval. This guide provides comprehensive, step-by-step instructions for deploying QRShield to AWS Lambda when ready.

---

## 1. AWS Cost & Free Tier Analysis

QRShield was engineered specifically to adhere to the **AWS Free Tier** and avoid any recurring server charges:

| AWS Service | Free Tier Allowance | QRShield Utilization | Expected Monthly Cost |
|---|---|---|---|
| **AWS Lambda** | 1,000,000 free requests/mo & 3.2M seconds compute | ~100–500 requests for college demo | **$0.00** |
| **Lambda Function URL** | Built into Lambda (No API Gateway fee) | Direct HTTPS invocation | **$0.00** |
| **Amazon CloudWatch** | 5 GB ingestion & 5 GB archive | < 10 MB execution logs | **$0.00** |
| **EC2 / Load Balancers** | *Not used* | *Not used* | **$0.00** |

*Note: Free tier allowances apply to new and standard accounts, but users should always check their AWS Billing Console.*

---

## 2. Pre-Deployment Readiness Checklist

Before initiating any deployment in the AWS Console or CLI, verify each item in this checklist:

- [ ] **1. Python Runtime:** Target `Python 3.12` (or `Python 3.11`). Verified that code uses only standard library (`urllib.parse`, `ipaddress`, `unicodedata`, `json`, `re`, `base64`, `datetime`).
- [ ] **2. Handler Specification:** Explicitly configured as `lambda_function.lambda_handler`.
- [ ] **3. Compute Allocation:** Memory set to `128 MB` (lowest cost tier, <15ms execution); Timeout set to `5 seconds` (prevents lingering compute charges).
- [ ] **4. Function URL Authentication:** Set to `NONE` (enables public browser access without requiring AWS Signature Version 4 signing).
- [ ] **5. CORS Configuration:**
  - Allowed Origins: `*` (or your frontend domain, e.g. `http://localhost:5173`)
  - Allowed Methods: `GET`, `POST`, `OPTIONS` (`GET` is the health check used by the status badge)
  - Allowed Headers: `Content-Type`, `Authorization`, `X-Requested-With`
  - Max Age: `86400` seconds
- [ ] **6. Amazon CloudWatch Logs:** Default execution role has `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`. Verified that URL query parameters and credentials are automatically stripped prior to logging.
- [ ] **7. Account Eligibility & Quotas:** AWS Lambda Free Tier provides 1,000,000 requests/month and 3,200,000 seconds of compute time indefinitely. Even outside the 12-month new-account window, the Lambda Free Tier is permanent for all standard AWS accounts.
- [ ] **8. Zero Cloud Spend Guarantee:** No EC2 instances, no VPC NAT gateways, no Application Load Balancers, and no paid third-party threat API subscriptions are used. Total recurring idle cost is **$0.00**.
- [ ] **9. User Approval Gate:** Confirm user approval before creating AWS resources or generating public endpoints.

---

## 3. Packaging the Backend Code

The QRShield backend relies exclusively on the **Python standard library**. It requires no virtual environments or external pip packages for packaging.

### Step A: Create Deployment Archive
From the project root:
```bash
# On Windows PowerShell:
cd backend
Compress-Archive -Path lambda_function.py, url_analyzer.py, rules.py -DestinationPath qrshield_backend.zip -Force
```
```bash
# On Linux / macOS:
cd backend
zip -r qrshield_backend.zip lambda_function.py url_analyzer.py rules.py
```

This creates a lightweight `qrshield_backend.zip` (~10 KB).

---

## 3. Creating the AWS Lambda Function

You can deploy using the **AWS Management Console** or the **AWS CLI**.

### Option A: AWS Management Console (Recommended for College Project)

1. **Sign in** to the [AWS Management Console](https://console.aws.amazon.com/).
2. Select your desired region (e.g., `us-east-1` or `ap-south-1`).
3. Search for **Lambda** and click **Create function**.
4. Configure basic information:
   - **Function name:** `QRShield-URL-Analyzer`
   - **Runtime:** `Python 3.12` (or `Python 3.11`)
   - **Architecture:** `x86_64` (or `arm64`)
   - **Execution role:** *Create a new role with basic Lambda permissions* (grants CloudWatch logging).
5. Click **Create function**.

### Step B: Upload Code & Set Handler
1. In the **Code source** tab, click **Upload from** -> **.zip file**.
2. Select the `qrshield_backend.zip` created in Step 2.
3. In the **Runtime settings** section, ensure the handler is:
   ```
   lambda_function.lambda_handler
   ```
4. Navigate to the **Configuration** -> **General configuration** tab:
   - **Memory:** `128 MB` (minimal allocation, fast execution)
   - **Timeout:** `5 seconds` (heuristic analysis takes < 5 milliseconds)

---

## 4. Enabling Lambda Function URL & CORS

1. Go to the **Configuration** tab and select **Function URL**.
2. Click **Create function URL**.
3. Configure settings:
   - **Auth type:** `NONE` (allows direct HTTPS invocation from the browser without AWS IAM signing keys).
   - Check **Configure cross-origin resource sharing (CORS)**:
     - **Allow origin:** `*` (or your specific frontend domain, e.g. `http://localhost:5173`)
     - **Allow methods:** `GET`, `POST`, `OPTIONS`
     - **Allow headers:** `content-type`, `authorization`, `x-requested-with`
     - **Max age:** `86400`
4. Click **Save**.
5. Copy the generated **Function URL** (format: `https://<random-id>.lambda-url.<region>.on.aws/`).

---

## 5. Testing the Lambda Function Directly

### In the AWS Lambda Console:
1. Go to the **Test** tab.
2. Create a new test event named `TestHighRiskUrl`:
   ```json
   {
     "url": "https://paypal.account-verify.xyz/login"
   }
   ```
3. Click **Test**.
4. Verify the execution output:
   - Status code: `200`
   - Response includes `risk_score: 70`, `risk_level: "High"`, and the findings `SEC-TLD-009` and `SEC-SPOOF-010` (CRITICAL).

---

## 6. Connecting the React Frontend

1. In `frontend/`, create a `.env` file (or copy `.env.example`):
   ```bash
   cp frontend/.env.example frontend/.env
   ```
2. Set `VITE_API_BASE_URL` to your copied AWS Lambda Function URL:
   ```env
   VITE_API_BASE_URL=https://<your-lambda-url-id>.lambda-url.<region>.on.aws/
   VITE_ENABLE_OFFLINE_MOCK=false
   ```
3. Restart or build the frontend:
   ```bash
   cd frontend
   npm run dev
   ```
4. The status badge in the top right of the application will display **Backend Active**.

---

## 7. Inspecting CloudWatch Execution Logs

1. In the AWS Lambda Console, click the **Monitor** tab.
2. Click **View CloudWatch logs**.
3. Select the latest log stream.
4. Verify that execution logs show sanitized targets (e.g., `QRShield processing request for target: https://example.com/path?[REDACTED_QUERY]`).
5. Confirm that execution duration is typically between **2 ms – 15 ms**, resulting in virtually zero cost.

---

## 8. Resource Teardown & Cleanup

When the evaluation or project presentation is complete, remove the resources to ensure zero ongoing footprint:

1. Open the [AWS Lambda Console](https://console.aws.amazon.com/lambda/).
2. Select `QRShield-URL-Analyzer`.
3. Click **Actions** -> **Delete function**.
4. Open the [Amazon CloudWatch Console](https://console.aws.amazon.com/cloudwatch/).
5. Under **Logs** -> **Log groups**, select `/aws/lambda/QRShield-URL-Analyzer`.
6. Click **Actions** -> **Delete log group(s)**.
