# 🛡️ IOC Investigation Tool

<<<<<<< HEAD
>A threat intelligence tool that hunts down malicious IPs, domains, and file hashes so analysts don't have to do it manually.
=======
> A threat intelligence tool that hunts down malicious IPs, domains, and file hashes so analysts don't have to do it manually.
>>>>>>> 16e76239c9499c78384ac48567ffaaa43d85a1d4

---

## 🔍 What it does

Give it an IP, domain, or file hash — it tells you if it's dangerous.

- Checks **VirusTotal** + **AlienVault OTX**
- Requests a fresh VirusTotal re-scan before pulling the report, instead of relying purely on a stale cached result
- Gives a **verdict** (Clean / Suspicious / Medium / High risk)
- Shows **why** — full score breakdown per signal
- Saves every lookup to `results.json`

---

## 🚀 Quick start

```bash
pip install requests python-dotenv
```

Add a `.env` file:
VT_API_KEY=your_key
OTX_API_KEY=your_key

Run it:
```bash
python main.py
```

---

## 🧠 How it scores

| Score | Verdict |
|-------|---------|
| 0 | ✅ Clean |
| 1–2 | ⚠️ Suspicious |
| 3–4 | 🟡 Low risk |
| 5–7 | 🟠 Medium risk |
| 8+ | 🔴 High risk |

---

## 🛠️ Built with

`Python` · `VirusTotal API` · `AlienVault OTX`

---

## 📁 Project structure

| File | Responsibility |
|------|------|
| `main.py` | Input loop, ties everything together |
| `detect.py` | Detects whether input is an IP, domain, or hash |
| `vt.py` | VirusTotal lookups + rescan requests |
| `otx.py` | AlienVault OTX lookups |
| `scoring.py` | Combines VT/OTX signals into a verdict |
| `output.py` | Saves results to `results.json` |

---

## 🧭 Roadmap

- Local caching (`cache.py`) so repeat lookups skip the API
- CSV / PDF report export

---

## ⚠️ Disclaimer
For educational and authorized security research only.
