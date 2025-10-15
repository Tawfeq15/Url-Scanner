# URL Security Scanner (v3.5.0)

FastAPI-based **passive** web scanner with a **“zero false positives”** philosophy.  
It detects technologies, flags missing security headers, highlights high-certainty SQL/XSS indicators, inspects cookies, and reports SSL/TLS details — all **without active attacks**.

> **Why?** Get a clean, reliable security signal you can trust in CI, demos, and quick assessments — no noisy false alarms.

---

## ✨ Highlights
- **Passive & safe**: inspects public responses only (no intrusive probing).
- **Tech fingerprinting**: frameworks, CMS, servers, and CDNs.
- **Headers hardening**: groups missing security headers by severity.
- **High-confidence SQL/XSS hints**: conservative to avoid noise.
- **Cookie hygiene**: `Secure`, `HttpOnly`, `SameSite`, expiry.
- **SSL/TLS snapshot**: issuer/subject, protocol, cipher, validity.
- **Structured logs**: timing & summary per scan for quick triage.

---

## 🚀 Quick Start — Start Here

> The shortest path: **install → run → test**.

1. **Open a terminal in the project folder**
   - **Windows**: open **PowerShell** here.
   - **Linux/macOS**: open a shell and `cd` into the folder.

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   # Windows alt:  py -m pip install -r requirements.txt
   # (Optional, recommended) create a virtual env first:
   #   Windows:  python -m venv .venv && . .venv\Scripts\Activate.ps1
   #   Linux/macOS: python3 -m venv .venv && source .venv/bin/activate
   ```

3. **Run the server**
   - **Windows (PowerShell):**
     ```powershell
     py main.py
     ```
   - **Linux/macOS (Bash):**
     ```bash
     python3 main.py
     ```
   - **Alternative (recommended for development — auto-reload):**
     ```bash
     uvicorn main:app --host 0.0.0.0 --port 5005 --reload
     ```

4. **Open the API docs (Swagger UI)**
   - افتح: **http://127.0.0.1:5005/docs**
   - من هناك اختر **POST /scan** → اضغط **Try it out** → أدخِل رابط الموقع (URL) → ثم **Execute**.

5. **Quick test with Postman**
   i. **Method:** `POST`  
   **URL:** `http://localhost:5005/scan`  
   ii. **Headers:**  
   `Content-Type: application/json`  
   iii. **Body** → **raw** → **JSON**:
   ```json
   { "url": "https://github.com" }
