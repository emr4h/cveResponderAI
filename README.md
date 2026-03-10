# cveResponderAI 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/emr4h/cveResponderAI/blob/main/LICENSE)
[![Repo](https://img.shields.io/badge/GitHub-emr4h%2FcveResponderAI-blue)](https://github.com/emr4h/cveResponderAI)

### *Local AI for CVE Triage and Incident Response (IR)*

**cveResponderAI** is a **local-first** security tool. It uses **NVD** (National Vulnerability Database) and **CISA KEV** (Known Exploited Vulnerabilities) data plus a **local LLM** via **Ollama**. You get detection ideas, mitigations, **MITRE ATT&CK** mapping, and PoC (proof-of-concept) code explanation—**without sending your data to the cloud**.

---

## 🎯 The Problem

When a new critical CVE appears, responders often:

- **Lose time** switching between NVD, CISA, GitHub, and news sites to build one clear picture.
- **Struggle with exploit code**—turning raw PoC into Sigma/YARA-style detection needs skill and time you may not have during an incident.
- **Risk leaks** if internal asset lists or exploit code are pasted into public AI chat.
- **Cannot manually check** whether a CVE hits a large asset inventory.

## 🚀 The Solution

**cveResponderAI** runs **on your machine**. One workflow: fetch CVE → optional news/PoC context → MITRE mapping → IR plan. You choose **any Ollama model** (Qwen, Llama, Mistral, Deepseek, etc.).

- **Parsing:** The backend asks the model for **JSON** when possible. If the model returns messy output, a **text recovery layer** still builds a usable report.
- **Privacy:** Data stays local because **Ollama** runs on your computer.

---

## 🏗️ Technical Stack

| Part | Technology |
|------|------------|
| **Backend** | Flask (Python)—API and LLM calls |
| **CVE data** | NVD API v2 + CISA KEV JSON feed |
| **MITRE** | Offline **MITRE ATT&CK** dataset (`data/mitre-attack.json`) |
| **AI** | Ollama (`localhost:11434`) + hybrid JSON/text parsing |
| **Frontend** | Vanilla JavaScript + CSS (no build step) |

---

## 🧠 Recommended Models (Ollama)

Tested and tuned for these local models:

1. **qwen3.5:9b** — Main choice; good at following instructions and JSON.
2. **deepseek-r1:14b** — Strong for **PoC Explainer** (reasoning-style output).
3. **llama3.1:8b** — Good general security and IR planning.

**Hardware:** Larger models need enough **RAM** (and optional **GPU**). If one model is slow, try a smaller tag or a single model only.

---

## 🛠️ Installation & Setup

### 1. Install Ollama
Download from [ollama.com](https://ollama.com).

### 2. Pull models (optional but recommended)
```bash
ollama pull qwen3.5:9b
ollama pull deepseek-r1:14b
ollama pull llama3.1:8b
```

### 3. Clone and install dependencies
```bash
git clone https://github.com/emr4h/cveResponderAI.git
cd cveResponderAI
pip install -r requirements.txt
```

### 4. Start the server
```bash
python3 server.py
```
The app listens on **port 5001**.

### 5. Open in the browser
Open **http://localhost:5001** (not the `index.html` file directly—API calls need the running server).

---

## 💡 Main Features

### 🛡️ IR plan (detection + mitigation)
The LLM returns **8–12** detection items (logs, Event IDs, SIEM/EDR ideas) and **8–12** mitigation steps, based on the CVE and context.

### 🎯 MITRE ATT&CK mapping
Maps the CVE to techniques with **short reasons** (why this CVE fits each technique), validated against the local MITRE library.

### ⚡ PoC Explainer
Paste or upload exploit code. The tool can highlight **important lines** and show an **attack path** (step flow from entry to impact).

### 📦 Affected products & inventory
Uses **NVD CPE** (Common Platform Enumeration) strings and can **correlate** with your **asset inventory** where supported.

### 📰 News search
Searches **9** security news / authority sites (e.g. The Hacker News, BleepingComputer, SecurityWeek, CISA, Dark Reading, Krebs on Security, Threatpost, and others) and groups articles by CVE.

---

## 🚩 Black Hat Arsenal — Docs & Demo

Project folders for the Arsenal submission:

| Folder | Purpose |
|--------|--------|
| **`docs/`** | **Whitepaper** and written material for Black Hat Arsenal (architecture, use cases, methodology). Add or replace the whitepaper here when ready. |
| **`demo/`** | **Demo video(s)** will live here (e.g. screen recording of the full workflow). Place your final cut in this folder and link from the repo or Arsenal page when published. |

Clone the repo and open `docs/` for the paper and `demo/` for the recording—no extra build step required.

---

## 🎬 Black Hat Arsenal — Live Demo Outline

1. **Phase 1 — KEV triage:** Pick a **CISA KEV** CVE and show NVD + KEV banner + workflow.
2. **Phase 2 — Local reasoning:** Run **PoC Explainer** on sample code (e.g. obfuscated script) with a reasoning model.
3. **Phase 3 — Defensive output:** Show generated detection/mitigation list and how it fits into IR workflow.

**Responsible use:** Use PoC analysis and tooling only in **authorized** environments and for **defensive** purposes.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE).

---

## 🤝 Acknowledgments

- **NVD (NIST)** — CVE and CVSS data  
- **MITRE ATT&CK** — technique framework  
- **Ollama** — local LLM runtime  

---

*Presented by **emr4h** at Black Hat Arsenal.*
