# cveResponderAI 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/emr4h/cveResponderAI/blob/main/LICENSE)
[![Repo](https://img.shields.io/badge/GitHub-emr4h%2FcveResponderAI-blue)](https://github.com/emr4h/cveResponderAI)

### *Local AI for CVE Triage and Incident Response (IR)*

**cveResponderAI** is a **local-first** security tool that combines public threat intelligence from **NVD** and **CISA KEV** with the reasoning power of **local LLMs** via **Ollama**. It streamlines the analyst workflow—providing detection ideas, mitigations, **MITRE ATT&CK** mapping, and PoC explanation—**without sensitive data ever leaving your machine**.

---

## 🎯 The Problem

In the high-pressure environment of Incident Response, analysts face three critical hurdles when a new vulnerability drops:

- **Context Switching:** Analysts lose valuable time moving between NVD, CISA, GitHub, vendor advisories, and news sites to build a single usable picture.
- **Analysis Paralysis:** Deciphering complex exploit code and turning raw PoC into actionable Sigma or YARA-style detection requires deep reverse-engineering skills and significant manual effort.
- **Privacy & Compliance Risk:** Utilizing public LLM platforms for triage often requires pasting internal asset lists or log fragments into the cloud, creating unacceptable data leakage risks for many organizations.

## 🚀 The Solution

**cveResponderAI** provides a cohesive, local-first dashboard built to accelerate the path from raw CVE publication to operational response.

- **Local AI execution:** Model reasoning stays entirely on the analyst host through Ollama, protecting sensitive internal data.
- **Unified Analyst Workflow:** A single interface for CVE lookup, OSINT enrichment, behavior mapping, and IR planning.
- **Asset Awareness:** Affected products are automatically parsed from CPE strings and correlated with local inventory to answer the immediate question: *"Does this hit us?"*
- **Resilient Reasoning:** A built-in recovery layer ensures that even if local models return imperfect formatting, the system reconstructs structured, usable reports.

---

## 🚩 Black Hat Arsenal — Docs & Demo

Project resources for the **Black Hat Arsenal** submission:

| Resource | Description |
|--------|--------|
| **[docs/](./docs/)** | Detailed analysis of architecture, methodology, whitepaper and real-world use cases. |
| **[demo/](./demo/)** | Screen recordings and workflow demonstrations. |

### 🎬 Live Demo Outline
1. **KEV Triage:** Ingest a high-impact CISA KEV entry and review integrated risk context.
2. **Local Reasoning:** Use the **PoC Explainer** to analyze obfuscated exploit code locally.
3. **Actionable Output:** Generate a complete IR plan with 10+ detection and mitigation strategies.

---

## 🧠 How it Works: LLM Prompt Context

To generate accurate **MITRE mappings** and **Incident Response Plans**, cveResponderAI builds a rich, structured prompt context for the local model using the following data points:

*   **NVD Metadata:** Full CVE descriptions, CVSS 3.x/4.0 metrics, and associated CWE identifiers.
*   **CISA KEV Catalog:** Exploitation status, "due dates," and specific remediation notes from CISA.
*   **OSINT/News Fragments:** Compressed snippets from recent security advisories and authority news sites to provide "in-the-wild" context.
*   **PoC Metadata:** Details on public exploit availability (from GitHub) and basic structural analysis results of any provided code.
*   **Internal Inventory Data:** Context on matching local assets to help the model prioritize mitigation steps for specific environments.

---

## 🏗️ Technical Stack

| Component | Technology |
|------|------------|
| **Backend** | Python 3.x / Flask |
| **CVE Sources** | NVD API v2 + CISA KEV JSON feed |
| **Intelligence** | Local MITRE ATT&CK dataset (`data/mitre-attack.json`) |
| **AI Runtime** | Ollama (`localhost:11434`) + Hybrid JSON/Text Recovery |
| **Frontend** | Vanilla JavaScript + Modern CSS (Zero Build Chain) |

---

## 🧠 Recommended Models (Ollama)

The tool is dynamically tuned for these local models:

1. **qwen3.5:9b** — General-purpose choice; excellent balance of speed and reliable structured output.
2. **deepseek-r1:14b** — Recommended for **PoC Explainer** due to superior reasoning and code analysis.
3. **llama3.1:8b** — Solid general security model for quick triage and broad mitigation guidance.

*Hardware Note: 16GB RAM is recommended; Apple Silicon or dedicated GPUs significantly improve performance.*

---

## 💡 Main Features

### 🛡️ Automated IR Planning
Aggregates full CVE context to generate **8–12** concrete detection ideas (Event IDs, log patterns, SIEM logic) and **8–12** mitigation steps to bridge the gap between triage and action.

### 🎯 MITRE ATT&CK Mapping
Correlates vulnerability data with the offline ATT&CK library to suggest TTPs. The AI provides a specific **rationale** for each mapping, helping analysts frame the threat behaviorally.

### ⚡ PoC Explainer & Attack Path
Allows analysts to paste exploit code for local analysis. The tool identifies **critical mechanics** and visualizes the **attack path**—a step-by-step flow from initial entry to final impact.

### 📦 Affected Products & Inventory Correlation
Simplifies complex NVD CPE strings into readable cards and performs risk-based matching against the internal asset inventory records.

### 📰 OSINT & News Aggregation
Queries multiple security news sources (e.g., The Hacker News, BleepingComputer) in parallel to provide situational awareness of current exploitation trends.

---

## 🛠️ Installation & Setup

1.  **Install Ollama:** Download from [ollama.com](https://ollama.com).
2.  **Pull & Start Models:**
    *   **Primary (Recommended):**
        ```bash
        ollama pull qwen3.5:9b
        ```
    *   **Optional (Other tested models):**
        ```bash
        ollama pull deepseek-r1:14b
        ollama pull llama3.1:8b
        ```
    *   **Note:** If the Ollama server is not running in the background, start it using:
        ```bash
        ollama serve
        ```
3.  **Clone & Install:**
    ```bash
    git clone https://github.com/emr4h/cveResponderAI.git
    cd cveResponderAI
    pip install -r requirements.txt
    ```
4.  **Start Server:**
    ```bash
    python3 server.py
    ```
5.  **Access App:** Open **http://localhost:5001** in your browser.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE).

---

## 🤝 Acknowledgments

- **NVD (NIST)** — CVE and CVSS data  
- **MITRE ATT&CK** — Tactical framework  
- **Ollama** — Local AI infrastructure  

---

*Presented by **emr4h** at Black Hat Arsenal.*
