# URL Security Scanner (v3.5.0)

FastAPI-based **passive** web scanner with a **“zero false positives”** philosophy.  
It detects technologies, flags missing security headers, highlights high-certainty SQL/XSS indicators, inspects cookies, and reports SSL/TLS details — all **without active attacks**.

> **Why?** Get a clean, reliable security signal you can trust in CI, demos, and quick assessments — no noisy false alarms.

---

## ✨ Highlights
- **Passive & safe:** inspects public responses only (no intrusive probing).
- **Tech fingerprinting:** frameworks, CMS, servers, and CDNs.
- **Headers hardening:** groups missing security headers by severity.
- **High-confidence SQL/XSS hints:** conservative to avoid noise.
- **Cookie hygiene:** `Secure`, `HttpOnly`, `SameSite`, expiry.
- **SSL/TLS snapshot:** issuer/subject, protocol, cipher, validity.
- **Structured logs:** timing & summary per scan for quick triage.

---

## 📦 Get the project
You can either **clone** or **download**:

```bash
# Clone (recommended)
git clone https://github.com/<your-user>/Url-Scanner.git
cd Url-Scanner

# Or: Download ZIP from GitHub → Extract → open the folder in your terminal
🚀 Quick Start — Start Here
The shortest path: install → run → test.

Open a terminal in the project folder

Windows: open PowerShell here.

Linux/macOS: open a shell and cd into the folder.

Install dependencies

bash
Copy code
pip install -r requirements.txt
# Windows alt:  py -m pip install -r requirements.txt
# (Optional, recommended) create a virtual env first:
#   Windows:   python -m venv .venv && . .venv\Scripts\Activate.ps1
#   Linux/mac: python3 -m venv .venv && source .venv/bin/activate
Run the server

Windows (PowerShell):

powershell
Copy code
py main.py
Linux/macOS (Bash):

bash
Copy code
python3 main.py
Alternative (recommended for development — auto-reload):

bash
Copy code
uvicorn main:app --host 0.0.0.0 --port 5005 --reload
Open the API docs (Swagger UI)

Go to http://127.0.0.1:5005/docs
From there choose POST /scan → Try it out → paste a URL → Execute.

Quick test with Postman (GUI)

Open Postman → New → HTTP Request

In the URL box enter:

bash
Copy code
http://localhost:5005/scan
(If you changed the port, replace 5005 accordingly.)

Set method to POST

Go to Body → select raw → choose JSON from the dropdown

Paste this JSON:

json
Copy code
{ "url": "https://github.com" }
When JSON is selected, Postman usually adds the header
Content-Type: application/json automatically. If not, add it under Headers.

Click Send → you should see 200 OK with a JSON report below.

Quick test with cURL (optional)

bash
Copy code
curl -X POST http://127.0.0.1:5005/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
Stop the server

Press Ctrl + C in the terminal.

📡 API Overview
POST /scan
Request

json
Copy code
{ "url": "https://example.com" }
Response (example)

json
Copy code
{
  "website": "https://example.com",
  "technologies": ["Cloudflare", "React"],
  "missing_security_headers": {
    "critical": ["Content-Security-Policy"],
    "important": [],
    "optional": []
  },
  "sql_vulnerability": false,
  "xss_vulnerability": { "inline_handlers": [], "script_tags": [] },
  "insecure_cookies": [],
  "ssl_tls_information": {
    "issuer": "Let's Encrypt",
    "protocol": "TLS 1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "valid_from": "2025-01-01",
    "valid_to": "2025-03-31"
  },
  "scan_time_ms": 1200
}
The live schema is always visible at /docs.

🧪 Batch Test (optional)
Scan a few URLs from http_https_urls_list.txt:

bash
Copy code
python - <<'PY'
import requests, json, itertools, pathlib, time
p = pathlib.Path("http_https_urls_list.txt")
urls = [u.strip() for u in p.read_text(encoding="utf-8").splitlines() if u.strip() and not u.startswith("#")]

for url in itertools.islice(urls, 5):  # try first 5
    print("\n==>", url)
    t0 = time.time()
    try:
        r = requests.post("http://127.0.0.1:5005/scan", json={"url": url}, timeout=20)
        r.raise_for_status()
        data = r.json()
        keep = ["website","technologies","missing_security_headers","sql_vulnerability","xss_vulnerability","insecure_cookies","ssl_tls_information"]
        print(json.dumps({k: data.get(k) for k in keep}, ensure_ascii=False, indent=2))
    except Exception as e:
        print("ERROR:", e)
    print("took_ms:", int((time.time()-t0)*1000))
PY
📁 Project Structure
bash
Copy code
Url-Scanner/
├─ main.py                   # FastAPI app
├─ requirements.txt          # dependencies
├─ http_https_urls_list.txt  # optional test corpus (http + https)
├─ scan_results2.xlsx        # sample/report sheet
└─ scanner.log               # runtime logs (created on first run if enabled)
✅ Requirements
Python 3.10+ (3.11/3.12 tested)

Windows / Linux / macOS

Internet access to scan live websites

⚙️ Notes & Best Practices
Default port: 5005 (change with --port 5050 if needed).

If pip/uvicorn isn’t found, ensure your virtual env is activated or use py -m pip / python3 -m pip.

The scanner blocks localhost/private ranges for safety.

Use responsibly — only scan websites you are authorized to test.

🛠 Troubleshooting
ModuleNotFoundError → run pip install -r requirements.txt inside the active venv.

Address already in use → try another port, e.g. --port 5050.

No response / timeouts → some targets block automated clients; test with another URL to verify setup.

CORS/browser calls fail → test via Swagger or Postman first; then align protocol/host/port in your frontend.

📝 License
MIT (or update to your preferred license).

<details> <summary>🇸🇦 دليل مختصر بالعربي (اضغط للعرض)</summary>
ما هو المشروع؟
ماسح أمني سلبي مبني على FastAPI — لا ينفّذ هجمات، بل يقرأ الاستجابات العامة ويعطيك:

التقنيات (إطارات عمل/خوادم/CDN)

الترويسات الأمنية المفقودة حسب الأهمية

مؤشرات عالية الثقة لثغرات SQL/XSS

حالة الكوكيز (Secure/HttpOnly/SameSite)

معلومات SSL/TLS (المُصدر، البروتوكول، الخوارزمية، الصلاحية)

ابدأ بسرعة:

نزّل المتطلبات:

bash
Copy code
pip install -r requirements.txt
شغّل السيرفر:

bash
Copy code
python main.py
# أو للمطورين:
uvicorn main:app --host 0.0.0.0 --port 5005 --reload
Swagger: http://127.0.0.1:5005/docs → جرّب POST /scan

Postman: POST http://localhost:5005/scan مع:

json
Copy code
{ "url": "https://github.com" }
