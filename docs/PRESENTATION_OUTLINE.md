# QRShield — College Project Screencast Presentation Guide (7–8 Minutes)

This script is structured for a 7–8 minute recorded demonstration or live viva presentation for the college project submission due on 25 October 2026.

---

## Presentation Breakdown

```
[00:00 - 01:00]  1. Introduction & Problem Statement
[01:00 - 02:15]  2. System Architecture & Privacy Model
[02:15 - 03:45]  3. Live Demo: Safe URL vs. Suspicious URL
[03:45 - 05:00]  4. Live Demo: High-Risk Phishing & Spoofing Indicators
[05:00 - 06:00]  5. AWS Serverless Integration & CloudWatch Logs
[06:00 - 07:00]  6. Bounded History & Zero-Knowledge Safeguards
[07:00 - 07:45]  7. Technical Limitations & Future Work
[07:45 - 08:00]  8. Conclusion & Q&A Readiness
```

---

## Detailed Script & Actions

### 1. Introduction & Problem Statement (0:00 – 1:00)
- **Speaker:**  
  *"Good morning. My name is [Your Name], and today I am presenting **QRShield — a Cloud-Based QR Code Threat Detection System**."*
- **Visual:** Show QRShield homepage with the cybersecurity dark-mode UI.
- **Key Talking Points:**
  - QR codes are ubiquitous on flyers, restaurant menus, and payment counters.
  - Unlike hyperlinks on a desktop, users cannot hover over a physical QR code to inspect the URL destination. Attackers exploit this ("quishing") to route victims to phishing sites or credential harvesting portals.
  - QRShield solves this by giving users a pre-click static heuristic threat analysis before their device opens the browser.

### 2. Architecture & Privacy by Design (1:00 – 2:15)
- **Speaker:**  
  *"Before demonstrating live scans, let’s look at the architectural decisions that prioritize both privacy and cost."*
- **Visual:** Switch to the **Methodology** tab or display the Mermaid diagram from `docs/ARCHITECTURE.md`.
- **Key Talking Points:**
  - **Zero-Knowledge Image Privacy:** The QR code image is parsed locally in the browser using HTML5 Canvas and `jsQR`. The image never leaves the device or gets stored in the cloud.
  - **Serverless Compute:** We use **AWS Lambda** with a Function URL. There are no running EC2 servers, zero idle costs, and execution scales automatically on demand.
  - **Sanitized Logging:** Only clean, credential-redacted endpoints are sent to **Amazon CloudWatch**.

### 3. Live Demo: Safe Link & Moderate Caution (2:15 – 3:45)
- **Action 1 (Safe Link):**
  - Click on the test preset **"Safe HTTPS"** (`https://www.cambridge.org/research`).
  - Explain the score: **0 / 100**, categorized as **Low Risk**.
  - Show the metadata panel: Hostname identified, standard port 443, zero flagged rules.
- **Action 2 (URL Shortener / Plain HTTP):**
  - Click on **"URL Shortener"** (`https://bit.ly/3SecureLogin`).
  - Explain the score: **30 / 100**, categorized as **Medium Risk**.
  - Point out rule `SEC-SHORT-005`: URL shorteners hide the real destination, which is commonly used to mask redirects in QR codes.

### 4. Live Demo: High-Risk Phishing & Brand Spoofing (3:45 – 5:00)
- **Action 1 (Brand Spoofing):**
  - Click on **"Spoofed Brand"** (`https://paypal.account-verify.xyz/login`).
  - Show the alert: **Risk Score 75 / 100**, categorized as **High Risk** with vivid crimson styling.
  - Review the findings:
    - `SEC-SPOOF-010`: Detected the brand keyword "PayPal" in a subdomain where the root domain is registered to an unrelated entity (`account-verify.xyz`).
    - `SEC-TLD-009`: High-risk low-cost generic TLD (`.xyz`).
  - Emphasize the actionable recommendation: *"Do not provide credentials. Navigate directly to the official website."*
- **Action 2 (Raw IP Hostname):**
  - Click **"Raw IP Host"** (`http://192.168.1.100:8080/admin`).
  - Point out `SEC-IP-003` and `SEC-PORT-004`: Legitimate public web services almost never use bare IP addresses and custom ports in QR codes.

### 5. AWS Serverless & CloudWatch Logging (5:00 – 6:00)
- **Visual:** Show the AWS Lambda Console or CloudWatch log stream (or local server logs).
- **Speaker:**  
  *"Here we can observe the serverless execution logs. Notice that the Lambda execution takes approximately 3 to 10 milliseconds. Also, notice that sensitive tokens or query parameters are automatically redacted as `[REDACTED_QUERY]`, ensuring compliance with privacy standards."*

### 6. Bounded History & Client Safeguards (6:00 – 7:00)
- **Visual:** Switch to the **History** tab.
- **Speaker:**  
  *"The user can view their recent scan history directly in the browser. Crucially, we store a maximum of 10 sanitized records in `localStorage`. Uploaded images and credentials are never stored. Users can clear their history at any time with one click."*
- **Action:** Click "Clear History" and confirm the deletion.

### 7. Technical Limitations & Academic Scope (7:00 – 7:45)
- **Speaker:**  
  *"As an academic prototype, QRShield is built on transparent, deterministic heuristic rules. It is not an active web crawler or a paid commercial threat intelligence platform. A 'Low Risk' result indicates the absence of known structural red flags, but does not guarantee the site is immune to zero-day attacks. This transparent disclaimer is explicitly shown to the user on every scan."*

### 8. Conclusion (7:45 – 8:00)
- **Speaker:**  
  *"In conclusion, QRShield demonstrates how client-side privacy combined with lightweight AWS serverless functions can provide immediate, accessible protection against malicious QR codes. Thank you, and I welcome any questions."*
