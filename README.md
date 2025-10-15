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

5. **Quick test with Postman (GUI)**
   1) افتح **Postman** → اضغط **New** → اختر **HTTP Request**.  
   2) في الخانة العلوية للصندوق، ضع هذا العنوان:
      ```
      http://localhost:5005/scan
      ```
      (إذا غيّرت المنفذ، عدّل `5005` حسب تشغيلك.)
   3) غيّر الطريقة إلى **POST**.  
   4) انتقل إلى **Body** → اختر **raw** → من القائمة اليمنى اختر **JSON**.  
   5) ألصق هذا الجسم (JSON):
      ```json
      { "url": "https://github.com" }
      ```
      > ملاحظة: عند اختيار **JSON**، Postman يضيف الهيدر
      `Content-Type: application/json` تلقائيًا. وإن لم يفعل، أضِفه يدويًا من **Headers**.
   6) اضغط **Send** → تظهر نتيجة **200 OK** مع تقرير JSON في الأسفل.

6. **Quick test with cURL (optional)**
   ```bash
   curl -X POST http://127.0.0.1:5005/scan \
     -H "Content-Type: application/json" \
     -d '{"url":"https://example.com"}'

