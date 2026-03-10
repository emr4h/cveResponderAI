"""
cveResponderAI - Backend Server
Flask API for NVD data fetching and Ollama LLM analysis
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import concurrent.futures
import requests
import json
import os
import time
import re
import string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# CVE format: CVE-YYYY-NNNNN+ (year 4 digits, sequence 4+ digits)
CVE_PATTERN = re.compile(r"^CVE-(1999|20\d{2})-\d{4,}$", re.IGNORECASE)
CVE_PARTIAL = re.compile(r"^(\d{4})-(\d{4,})$")  # 2024-38077


def normalize_cve_id(raw: str) -> str:
    """Normalize user input to CVE-YYYY-NNNNN format."""
    s = (raw or "").strip().upper()
    if not s:
        return ""
    if s.startswith("CVE-"):
        return s
    m = CVE_PARTIAL.match(s)
    if m:
        return f"CVE-{m.group(1)}-{m.group(2)}"
    if s.replace("-", "").replace("_", "").isdigit() and len(s) >= 9:
        parts = re.split(r"[-_\s]+", s)
        if len(parts) >= 2:
            return f"CVE-{parts[0]}-{parts[1]}"
    return f"CVE-{s}"


def validate_cve_format(cve_id: str):
    """Return (is_valid, error_message)."""
    if not cve_id or not cve_id.strip():
        return False, "CVE ID is required."
    normalized = normalize_cve_id(cve_id)
    if not CVE_PATTERN.match(normalized):
        return False, f"Invalid CVE format. Use CVE-YYYY-NNNNN (e.g. CVE-2024-3094). You entered: {cve_id[:50]}"
    return True, normalized


app = Flask(__name__, static_folder=BASE_DIR)
CORS(app)

@app.errorhandler(500)
def handle_500(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    return e

@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Endpoint not found"}), 404
    return e

@app.errorhandler(Exception)
def handle_exception(e):
    if request.path.startswith('/api/'):
        print(f"✗ Unhandled exception on {request.path}: {e}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    return e

# ===================================
# Static file serving routes
# ===================================

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

@app.route('/')
def serve_index():
    return send_file(os.path.join(BASE_DIR, 'index.html'))

@app.route('/workflow')
def serve_workflow():
    return send_file(os.path.join(BASE_DIR, 'workflow.html'))

@app.route('/inventory')
def serve_inventory():
    return send_file(os.path.join(BASE_DIR, 'inventory.html'))

@app.route('/inventory.html')
def serve_inventory_html():
    return send_file(os.path.join(BASE_DIR, 'inventory.html'))

@app.route('/dashboard')
def serve_dashboard():
    return send_file(os.path.join(BASE_DIR, 'dashboard', 'code.html'))

@app.route('/styles.css')
def serve_css():
    return send_from_directory(BASE_DIR, 'styles.css')

@app.route('/app.js')
def serve_js():
    return send_from_directory(BASE_DIR, 'app.js')

@app.route('/workflow.html')
def serve_workflow_html():
    return send_file(os.path.join(BASE_DIR, 'workflow.html'))

@app.route('/index.html')
def serve_index_html():
    return send_file(os.path.join(BASE_DIR, 'index.html'))

@app.route('/dashboard/<path:filename>')
def serve_dashboard_files(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'dashboard'), filename)

@app.route('/workflow/<path:filename>')
def serve_workflow_files(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'workflow'), filename)

@app.route('/data/<path:filename>')
def serve_data_files(filename):
    return send_from_directory(os.path.join(BASE_DIR, 'data'), filename, as_attachment=True)

# Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLLAMA_API_BASE = "http://localhost:11434"
DEFAULT_MODEL = "qwen3.5:9b"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# KEV cache (refreshed every 24 hours)
_kev_cache = {"data": None, "timestamp": 0}
KEV_CACHE_TTL = 86400  # 24 hours

# Model capabilities cache: model_name -> {"supports_think": bool} (persists for process lifetime)
_model_capabilities_cache = {}

# Load MITRE ATT&CK dataset

MITRE_DATA_PATH = os.path.join(os.path.dirname(__file__), 'data', 'mitre-attack.json')
MITRE_TECHNIQUES = {}

def load_mitre_data():
    """Load MITRE ATT&CK techniques from local dataset"""
    global MITRE_TECHNIQUES
    try:
        if not os.path.exists(MITRE_DATA_PATH):
            print(f"⚠ MITRE data not found at {MITRE_DATA_PATH}")
            return
            
        with open(MITRE_DATA_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Parse STIX format
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break
                
                if technique_id:
                    MITRE_TECHNIQUES[technique_id] = {
                        'id': technique_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', '')[:1500],  # Increase limit to avoid truncation mid-sentence
                        'tactics': [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])],
                        'platforms': obj.get('x_mitre_platforms', [])
                    }
        
        print(f"✓ Loaded {len(MITRE_TECHNIQUES)} MITRE ATT&CK techniques")
    except Exception as e:
        print(f"✗ Failed to load MITRE data: {e}")

# Load MITRE data on startup
load_mitre_data()


def fetch_model_capabilities(model: str) -> dict:
    """
    Get capabilities for a model (e.g. supports_think) via Ollama /api/show.
    Falls back to probing with a minimal chat request if show does not return capabilities.
    Result is cached per model for the process lifetime.
    """
    global _model_capabilities_cache
    if not (model or "").strip():
        return {"supports_think": False}
    model = model.strip()
    if model in _model_capabilities_cache:
        return _model_capabilities_cache[model]

    supports_think = False
    try:
        resp = requests.post(
            f"{OLLAMA_API_BASE}/api/show",
            json={"model": model},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            caps = data.get("capabilities") or data.get("details", {}).get("capabilities")
            if isinstance(caps, list) and "thinking" in caps:
                supports_think = True
    except Exception:
        pass

    if not supports_think:
        try:
            probe = requests.post(
                f"{OLLAMA_API_BASE}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "Say OK"}],
                    "stream": False,
                    "think": True,
                },
                timeout=15,
            )
            if probe.status_code == 200:
                supports_think = True
        except Exception:
            pass

    result = {"supports_think": supports_think}
    _model_capabilities_cache[model] = result
    return result


def ollama_chat(model: str, system: str, prompt: str,
                options: dict = None, timeout: int = 120,
                think=None, format=None) -> str:
    """
    Single-request Ollama /api/chat call.
    think: True = use thinking; False = do not; None = auto-detect from model capabilities (recommended).
    When think is True, tries think=True then think="medium" on 400, then fallback without think.
    """
    if think is None:
        caps = fetch_model_capabilities(model)
        think = caps.get("supports_think", False)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": options or {},
        "keep_alive": "5m"
    }
    if format is not None:
        payload["format"] = format
    url = f"{OLLAMA_API_BASE}/api/chat"

    think_values: list
    if think is True:
        # Try think=True, then think="medium", then without think key
        think_values = [True, "medium", None]
    elif think is False:
        # Explicitly disable thinking — send think: false
        think_values = [False]
    else:
        # None = auto-detect
        think_values = [None]
    resp = None
    for think_val in think_values:
        body = {**payload, "think": think_val} if think_val is not None else payload
        resp = requests.post(url, json=body, timeout=timeout)
        if resp.status_code != 400:
            break
    resp.raise_for_status()
    msg = resp.json().get("message", {})
    content = msg.get("content", "")
    # Ollama can return reasoning in message.thinking (e.g. gpt-oss, deepseek-r1)
    thinking = msg.get("thinking", "") or ""
    # Strip <think>...</think> from content so we don't show raw reasoning in UI
    think_blocks = re.findall(r'<think>([\s\S]*?)(?:</think>|$)', content)
    content_no_think = re.sub(r'<think>[\s\S]*?(?:</think>|$)', '', content).strip()
    # If visible content is empty, use in-text <think> blocks or API thinking field
    if not content_no_think and think_blocks:
        content_no_think = "\n\n".join(t.strip() for t in think_blocks if t.strip()).strip()
    if not content_no_think and (thinking or "").strip():
        content_no_think = (thinking or "").strip()
    return content_no_think


def check_cisa_kev(cve_id: str) -> dict:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog"""
    global _kev_cache
    
    try:
        # Check cache validity
        if _kev_cache["data"] and (time.time() - _kev_cache["timestamp"]) < KEV_CACHE_TTL:
            kev_data = _kev_cache["data"]
        else:
            # Fetch fresh KEV catalog
            print(f"📥 Fetching CISA KEV catalog...")
            response = requests.get(CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            kev_data = response.json()
            _kev_cache = {"data": kev_data, "timestamp": time.time()}
            print(f"✓ Cached {len(kev_data.get('vulnerabilities', []))} KEV entries")
        
        # Search for CVE in catalog
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return {
                    "is_in_kev": True,
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                    "required_action": vuln.get("requiredAction"),
                    "cwes": vuln.get("cwes", [])
                }
        
        return {"is_in_kev": False}
    except Exception as e:
        print(f"⚠ CISA KEV check failed: {e}")
        return {"is_in_kev": False, "error": str(e)}





def fetch_cve_from_nvd(cve_id: str) -> dict:
    """Fetch CVE data from NVD API"""
    try:
        url = f"{NVD_API_BASE}?cveId={cve_id}"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data.get("totalResults", 0) == 0:
            return {"error": f"CVE {cve_id} not found in NVD database"}
        
        return data
    except requests.exceptions.Timeout:
        return {"error": "NVD API request timed out. Please try again."}
    except (json.JSONDecodeError, ValueError):
        return {"error": "NVD API returned an invalid response. It may be rate-limited or temporarily unavailable. Please try again in a few seconds."}
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to fetch from NVD: {str(e)}"}


def parse_cpe_string(cpe: str) -> dict:
    """Parse a CPE 2.3 string into readable components.
    Format: cpe:2.3:part:vendor:product:version:update:edition:language:...
    """
    parts = cpe.split(':')
    type_map = {'a': 'Application', 'o': 'Operating System', 'h': 'Hardware'}
    if len(parts) >= 6:
        return {
            "type": type_map.get(parts[2], parts[2]) if len(parts) > 2 else "",
            "vendor": parts[3].replace('_', ' ').title() if len(parts) > 3 else "",
            "product": parts[4].replace('_', ' ').title() if len(parts) > 4 else "",
            "version": parts[5] if len(parts) > 5 and parts[5] != '*' else "All versions",
        }
    return {"type": "", "vendor": "", "product": "", "version": ""}


def extract_cve_summary(nvd_data: dict) -> dict:
    """Extract key information from NVD response for display"""
    try:
        vuln = nvd_data["vulnerabilities"][0]["cve"]
        
        # Get description
        descriptions = vuln.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )
        
        # Get CVSS metrics
        cvss_data = {}
        metrics = vuln.get("metrics", {})
        
        # Try CVSS v3.1 first, then v3.0, then v2
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_info = metrics[version][0].get("cvssData", {})
                cvss_data = {
                    "score": cvss_info.get("baseScore", "N/A"),
                    "severity": cvss_info.get("baseSeverity", "N/A"),
                    "vector": cvss_info.get("attackVector", "N/A"),
                    "complexity": cvss_info.get("attackComplexity", "N/A"),
                    "privileges": cvss_info.get("privilegesRequired", "N/A"),
                    "userInteraction": cvss_info.get("userInteraction", "N/A"),
                    "vectorString": cvss_info.get("vectorString", "N/A")
                }
                break
        
        # Get affected configurations (CPE) with parsed product info
        affected = []
        configurations = vuln.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        criteria = match.get("criteria", "")
                        parsed = parse_cpe_string(criteria)
                        affected.append({
                            "criteria": criteria,
                            "vendor": parsed.get("vendor", ""),
                            "product": parsed.get("product", ""),
                            "version": parsed.get("version", ""),
                            "type": parsed.get("type", ""),
                            "versionStartIncluding": match.get("versionStartIncluding", ""),
                            "versionEndIncluding": match.get("versionEndIncluding", ""),
                            "versionStartExcluding": match.get("versionStartExcluding", ""),
                            "versionEndExcluding": match.get("versionEndExcluding", "")
                        })
        
        # Get references (fetch all available)
        references = [
            {"url": ref.get("url", ""), "tags": ref.get("tags", [])}
            for ref in vuln.get("references", [])  # Get all references
        ]
        
        # Get weaknesses (CWE)
        weaknesses = []
        for weakness in vuln.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
        
        return {
            "id": vuln.get("id", ""),
            "published": vuln.get("published", ""),
            "lastModified": vuln.get("lastModified", ""),
            "status": vuln.get("vulnStatus", ""),
            "description": description,
            "cvss": cvss_data,
            "affected": affected,
            "references": references,
            "weaknesses": weaknesses
        }
    except (KeyError, IndexError) as e:
        return {"error": f"Failed to parse CVE data: {str(e)}"}


# IR Plan — single API call with structured JSON output for reliable formatting.
IR_PLAN_SYSTEM = """You are a Lead Incident Response Analyst. 
Your goal is to provide a highly technical, specific, and actionable IR Plan for a Given CVE.
Focus on:
1. SPECIFIC artifacts (Registry keys, Event IDs, Sysmon tags, specific Log paths).
2. LOGIC for SIEM/EDR: Provide specific logic like "Monitor for specific process parent-child relationships" or specific strings.
3. NETWORK signals: Protocols, ports, or traffic patterns.

Return ONLY a JSON object with two keys: "detection" and "mitigation".
Each key must map to an array of 8-12 detailed, professional, and technically deep strings."""





IR_PLAN_PROMPT = """CVE Context:
- ID: {cve_id}
- Description: {description}
- CVSS: {score} ({severity})
- Affected Products: {affected_section}
- Exploit Status: {poc_section}
- MITRE Techniques: {mitre_section}
- Intelligence: {news_section}

Deliver a comprehensive IR Plan:
1. "detection": 8-12 technical detection methods (Log sources, event IDs, network signatures, EDR queries).
2. "mitigation": 8-12 specific, actionable mitigation steps (Fixes, workarounds, and hardening steps).

Return a JSON object only with "detection" and "mitigation" keys."""






def _strip_think_blocks(raw: str) -> str:
    """Remove in-text think blocks so they are not shown in UI."""
    return re.sub(r'<think>[\s\S]*?(?:</think>|$)', '', raw or '').strip()


def _strip_preamble(text: str) -> str:
    """Strip echoed reasoning / system-prompt content before the actual answer.
    Some models (e.g. Qwen) output 'Thinking Process:', 'Analyze the Request:',
    or echo back the system constraints before delivering the bullet list.
    Strategy: find the LAST contiguous block of '- ' bullets (which is typically
    the actual answer), and discard everything before it.
    """
    if not text:
        return text
    lines = text.split('\n')
    
    # Find contiguous blocks of '- ' bullets
    blocks = []  # list of (start_idx, end_idx) tuples
    current_block_start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        is_bullet = bool(re.match(r'^- .{5,}', stripped))
        if is_bullet:
            if current_block_start is None:
                current_block_start = i
        else:
            if current_block_start is not None:
                blocks.append((current_block_start, i - 1))
                current_block_start = None
    # Close last block
    if current_block_start is not None:
        blocks.append((current_block_start, len(lines) - 1))
    
    if not blocks:
        return text
    
    # Pick the largest contiguous bullet block (most likely the actual answer)
    best_block = max(blocks, key=lambda b: b[1] - b[0])
    return '\n'.join(lines[best_block[0]:best_block[1] + 1])


def _normalize_bullets(text: str) -> str:
    """Normalize various LLM bullet/list formats into standard markdown `- ` bullets.
    Handles: * item, • item, – item, — item, numbered lists (1. 2. etc.),
    **1.** bold-numbered, <br> tags, stray HTML tags.
    """
    if not text:
        return text
    # Replace <br> and <br/> with newlines
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    # Strip common inline HTML tags (b, strong, em, i, code) but keep content
    text = re.sub(r'</?(?:b|strong|em|i|code|u|span)[^>]*>', '', text, flags=re.IGNORECASE)
    lines = text.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            result.append('')
            continue
        # Convert various bullet prefixes to '- '
        # *, •, –, —, ▪, ▸, ►, ➤, ➜
        stripped = re.sub(r'^[\*•–—▪▸►➤➜]\s+', '- ', stripped)
        # Numbered: "1. ", "1) ", "**1.** ", "**1)** "
        stripped = re.sub(r'^\*{0,2}\d+[\.)\]]\*{0,2}\s+', '- ', stripped)
        # Pipe-separated items on single line: "| 1. xxx | 2. yyy |"
        if stripped.startswith('|') and stripped.count('|') >= 3:
            parts = [p.strip() for p in stripped.split('|') if p.strip()]
            for part in parts:
                cleaned = re.sub(r'^\*{0,2}\d+[\.)\]]\*{0,2}\s+', '', part).strip()
                if cleaned:
                    result.append(f'- {cleaned}')
            continue
        result.append(stripped)
    # Collapse multiple blank lines into one
    output = '\n'.join(result)
    output = re.sub(r'\n{3,}', '\n\n', output)
    return output.strip()


def _format_affected_section(affected: list) -> str:
    """Format affected products for IR Plan prompt."""
    if not affected:
        return "Affected Products: None identified."
    lines = ["Affected Products:"]
    for a in affected[:15]:  # cap to avoid token overflow
        v = a.get('version') or ''
        vs = a.get('versionStartIncluding') or a.get('versionStartExcluding') or ''
        ve = a.get('versionEndIncluding') or a.get('versionEndExcluding') or ''
        ver_info = v or (f"{vs} to {ve}" if vs or ve else "various")
        vendor = a.get('vendor', '') or ''
        product = a.get('product', '') or ''
        if vendor or product:
            lines.append(f"- {vendor or '?'} {product or '?'} ({ver_info})")
    return "\n".join(lines) if len(lines) > 1 else lines[0]


# JSON schema for structured output
IR_PLAN_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "detection": {
            "type": "array",
            "items": {"type": "string"}
        },
        "mitigation": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["detection", "mitigation"]
}


def generate_ir_plan(cve_data: dict, model: str, poc_status: dict = None,
                     mitre_techniques: list = None, news_context: str = None) -> dict:
    """Generate IR Plan using Ollama structured JSON output for reliable formatting.
    Enriched with: affected products, PoC status, MITRE techniques, news context.
    """
    try:
        cvss = cve_data.get('cvss', {})
        affected = cve_data.get('affected', [])
        affected_section = _format_affected_section(affected)
        cve_id = cve_data.get('id', 'Unknown')
        score = cvss.get('score', 'N/A')
        severity = cvss.get('severity', 'N/A')

        poc = poc_status or {}
        has_poc = poc.get('hasPublicPoc', False)
        repo_count = poc.get('repoCount', 0)
        if has_poc and repo_count > 0:
            poc_section = f"Public PoC: Yes — {repo_count} repo(s) on GitHub."
        elif has_poc:
            poc_section = "Public PoC: Yes."
        else:
            poc_section = "Public PoC: No."

        # MITRE techniques section
        mitre_section = ""
        if mitre_techniques:
            lines = [f"- {t.get('id','?')}: {t.get('name','?')}" for t in mitre_techniques[:5]]
            mitre_section = "\nMITRE ATT&CK techniques mapped to this CVE:\n" + "\n".join(lines) + "\n"

        # News context section
        news_section = ""
        if news_context and news_context.strip():
            news_section = f"\nRecent threat intelligence from news sources:\n{news_context[:400]}\n"

        desc = (cve_data.get('description') or 'No description')[:600]
        fmt = dict(cve_id=cve_id, description=desc, score=score, severity=severity,
                   affected_section=affected_section, poc_section=poc_section,
                   mitre_section=mitre_section, news_section=news_section)

        prompt = IR_PLAN_PROMPT.format(**fmt)

        # 1. Attempt structured JSON output first (best for high-end models)
        raw = ollama_chat(
            model, IR_PLAN_SYSTEM, prompt,
            options={"temperature": 0.2, "num_predict": 2000},
            timeout=120, think=False,
            format=IR_PLAN_JSON_SCHEMA
        )

        detection_summary = ""
        mitigation_summary = ""
        
        try:
            # 2. Try Standard JSON Parsing
            obj = json.loads(raw)
            if isinstance(obj, dict):
                d = [str(x).strip() for x in obj.get('detection', []) if str(x).strip()]
                m = [str(x).strip() for x in obj.get('mitigation', []) if str(x).strip()]
                
                if d or m:
                    print(f"   ✓ IR Plan JSON parse success ({len(d)} det, {len(m)} mit)")
                    return {
                        "detectionSummary": "\n".join(f"- {i}" for i in d),
                        "mitigationSummary": "\n".join(f"- {i}" for i in m)
                    }
        except (json.JSONDecodeError, TypeError):
            # 3. Fallback: Hybrid Smart Text Splitter for messy/echoing models
            print(f"   ⚠ IR Plan JSON failed; applying deep text cleanup")
            
            raw_clean = _strip_think_blocks(raw or "")
            forbidden = [
                "Return ONLY a JSON object", "Return a JSON object only", "two keys: \"detection\" and \"mitigation\"",
                "You are a Lead Incident Response Analyst", "Your goal is to provide", "Focus on SPECIFIC artifacts",
                "deliver a comprehensive IR Plan", "8-12 technical detection methods", "8-12 specific mitigation steps",
                "detailed, professional, and technically deep strings", "Return a JSON object only",
                "CVE Context:", "Exploit Status:", "We need to produce a JSON object", "Must be highly technical"
            ]
            for f in forbidden:
                raw_clean = re.sub(re.escape(f), '', raw_clean, flags=re.IGNORECASE)
            
            # Smart split for single-paragraph outputs
            if len(raw_clean) > 200 and '\n' not in raw_clean.strip():
                raw_clean = re.sub(r'(?<!\d)(?:\.\s+)(Also|Additionally|Next|Now|Detection|Mitigation|Monitor|Use|Patch|Create|Sigma|YARA)', r'.\n\1', raw_clean)

            sections = {"detection": [], "mitigation": []}
            current_target = sections["detection"]
            
            for line in raw_clean.split('\n'):
                l_strip = line.strip()
                if not l_strip or len(l_strip) < 15: continue
                l_lower = l_strip.lower()
                
                if any(x in l_lower for x in ["mitigation", "remediation", "action", "patch", "fix", "block", "çözüm", "iyileştirme"]):
                    if len(l_lower) < 60: current_target = sections["mitigation"]; continue
                elif any(x in l_lower for x in ["detection", "monitoring", "finding", "sigma", "yara", "tespit", "izleme"]):
                    if len(l_lower) < 60: current_target = sections["detection"]; continue
                
                # Cleanup and deduplicate
                l_val = re.sub(r'^[*\-\d\.\s\>\[\]]+|^\*{0,2}(?:Detection|Mitigation|Action|Step|Also)\*{0,2}\s*[:\-–—]?\s*', '', l_strip, flags=re.IGNORECASE).strip()
                if l_val and len(l_val) > 10 and l_val not in current_target:
                    current_target.append(l_val)

            detection_summary = "\n".join(f"- {i}" for i in sections["detection"][:12])
            mitigation_summary = "\n".join(f"- {i}" for i in sections["mitigation"][:12])
            
        return {
            "detectionSummary": detection_summary or "Monitor relevant logs for vulnerability exploitation indicators.",
            "mitigationSummary": mitigation_summary or "Patch software and apply standard network security controls."
        }

    except Exception as e:
        print(f"   ⚠ IR Plan error: {e}")
        return {"detectionSummary": f"Error: {str(e)}", "mitigationSummary": ""}


@app.route('/api/ir-plan', methods=['POST'])
def ir_plan_endpoint():
    """Generate IR Plan enriched with affected products, PoC, MITRE techniques and news context."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        cve_data = data.get("cveData", {})
        model = data.get("model", DEFAULT_MODEL)
        poc_status = data.get("pocStatus")
        mitre_techniques = data.get("mitreTechniques")  # list of {id, name, ...}
        news_context = data.get("newsContext")           # pre-built string ≤400 chars
        if not cve_data:
            return jsonify({"error": "CVE data is required"}), 400
        print(f"\n📋 IR Plan for {cve_data.get('id', '?')} (model: {model}, "
              f"PoC: {poc_status}, MITRE: {len(mitre_techniques or [])}, news: {bool(news_context)})...")
        result = generate_ir_plan(cve_data, model, poc_status, mitre_techniques, news_context)
        print(f"   Done. Detection: {len(result.get('detectionSummary', ''))} chars, "
              f"Mitigation: {len(result.get('mitigationSummary', ''))} chars")
        return jsonify(result)
    except Exception as e:
        print(f"✗ ir-plan error: {e}")
        return jsonify({"error": str(e), "detectionSummary": f"Error: {str(e)}", "mitigationSummary": ""}), 200


def map_to_mitre_techniques(cve_data: dict, model: str,
                           ir_plan_summary: str = None,
                           poc_status: dict = None,
                           news_context: str = None) -> list:
    """Map CVE to MITRE ATT&CK. Inputs: CVE data, PoC status, Affected Products, News snippets."""
    try:
        system = "You are a cybersecurity expert. Identify MITRE ATT&CK techniques for this CVE. Format: Txxxx: [Reason]"

        desc = (cve_data.get('description') or '')[:500]
        vector = cve_data.get('cvss', {}).get('vector', 'N/A')
        cve_id = cve_data.get('id', 'N/A')

        ctx_parts = [f"CVE: {cve_id}", f"Description: {desc}", f"CVSS Vector: {vector}"]

        poc = poc_status or {}
        if poc.get('hasPublicPoc'):
            ctx_parts.append(f"\nPublic PoC: Yes ({poc.get('repoCount', 0)} repos).")
        else:
            ctx_parts.append("\nPublic PoC: No.")

        affected = cve_data.get('affected', [])
        if affected:
            prods = ", ".join([f"{a.get('vendor','')} {a.get('product','')}".strip() or "?" for a in affected[:8]])
            ctx_parts.append(f"\nAffected products: {prods}")

        # News context — real-world exploit intelligence
        if news_context and news_context.strip():
            ctx_parts.append(f"\nRecent news/threat intelligence:\n{news_context[:400]}")

        prompt = "\n".join(ctx_parts) + """

Identify 3–5 MITRE ATT&CK techniques. One per line. You MUST provide a specific reason related to the CVE data.
Format: Txxxx: [Why is this technique relevant to this specific CVE?]
Example:
T1190: This RCE vulnerability in a web-facing service allows an unauthenticated attacker to execute code.
T1068: The vulnerability allows a low-privileged user to execute code with SYSTEM privileges."""

        print(f"   MITRE prompt context: {prompt[:150]}...")
        llm_response = ollama_chat(
            model, system, prompt,
            options={"temperature": 0.1, "num_predict": 400},
            timeout=50,
            think=False,
        )
        # 1. Strip typical instruction echoes
        forbidden_mitre = [
            "You are a threat intelligence analyst", "Identify MITRE ATT&CK techniques", 
            "provide a 1-sentence analytical justification", "Output format: Txxxx:",
            "Identify 3–5 MITRE ATT&CK techniques", "One per line", "You MUST provide a specific reason"
        ]
        for f in forbidden_mitre:
            llm_response = re.sub(re.escape(f), '', llm_response, flags=re.IGNORECASE)

        # 2. Heuristic: If it's one giant block, split by IDs or common connectors
        if len(llm_response) > 200 and '\n' not in llm_response.strip():
            # Split before Txxxx markers or sentence connectors
            llm_response = re.sub(r'(\.?\s+)(Also|Next|Secondly|Finally|T\d{4})', r'.\n\2', llm_response)

        print(f"   MITRE raw response (cleaned): {repr(llm_response[:100])}...")
        techniques = []
        
        for line in llm_response.split('\n'):
            line = line.strip()
            if not line or len(line) < 5:
                continue
            
            # 3. Flexible search, but non-greedy on the description to avoid swallowing next IDs
            # Pattern: (ID) followed by separator, then (Reason) but STOP if another ID is found
            match = re.search(r'(T\d{4}(?:\.\d{3})?)\b.*?(?:[:\-–—]|\bis\b)\s*(.*?)(?=\s+T\d{4}|$)', line, re.IGNORECASE)
            
            tech_id = None
            reason = ""
            
            if match:
                tech_id = match.group(1).upper()
                reason = match.group(2).strip()
            else:
                # 4. Hard Fallback: Just look for the first Txxxx ID in the line anywhere
                match_id = re.search(r'(T\d{4}(?:\.\d{3})?)', line, re.IGNORECASE)
                if match_id:
                    tech_id = match_id.group(1).upper()
                    # Use the rest of the line as reason, cleaning up common list prefixes
                    reason = line.replace(match_id.group(1), "").strip().lstrip("*: -–—[]()").strip()
            
            # Final cleaning of ID
            if tech_id:
                tech_id = re.sub(r'[^T0-9.]', '', tech_id)

                
                # Check ID against MITRE library
                tech_data = MITRE_TECHNIQUES.get(tech_id)
                if not tech_data and '.' in tech_id:
                    parent_id = tech_id.split('.')[0]
                    tech_data = MITRE_TECHNIQUES.get(parent_id)

                if tech_data:
                    # Prevent duplicates
                    if any(t['id'] == tech_id for t in techniques):
                        continue
                        
                    techniques.append({
                        'id': tech_id,
                        'name': tech_data['name'],
                        'description': tech_data['description'],
                        'tactics': tech_data['tactics'],
                        'platforms': tech_data['platforms'],
                        'reason': reason or "Relationship identified via vulnerability pattern match.",
                        'confidence': 'high' if tech_id in MITRE_TECHNIQUES else 'medium'
                    })
                else:
                    print(f"   ⚠ Unknown technique ID detected: {tech_id}")
                    
        print(f"   ✓ Successfully mapped {len(techniques)} MITRE techniques")
        return techniques[:5]
    except Exception as e:
        print(f"✗ MITRE error: {e}")
        return []


@app.route('/api/fetch-cve', methods=['POST'])
def fetch_cve_endpoint():
    """Fetch CVE data from NVD and check CISA KEV (fast, no LLM)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        raw = data.get("cveId", "").strip()
        valid, result = validate_cve_format(raw)
        if not valid:
            return jsonify({"error": result}), 400
        cve_id = result

        nvd_response = fetch_cve_from_nvd(cve_id)
        if "error" in nvd_response:
            status = 404 if "not found" in nvd_response["error"].lower() else 500
            return jsonify({"error": nvd_response["error"]}), status

        cve_summary = extract_cve_summary(nvd_response)
        if "error" in cve_summary:
            return jsonify({"error": cve_summary["error"]}), 500

        print(f"\n🔍 Checking CISA KEV for {cve_id}...")
        kev_status = check_cisa_kev(cve_id)
        if kev_status.get("is_in_kev"):
            print(f"⚠️  {cve_id} is in CISA KEV!")

        return jsonify({"cveData": cve_summary, "kevStatus": kev_status})
    except Exception as e:
        print(f"✗ fetch-cve error: {e}")
        return jsonify({"error": f"Failed to fetch CVE: {str(e)}"}), 500


@app.route('/api/map-mitre', methods=['POST'])
def map_mitre_endpoint():
    """Map CVE to MITRE ATT&CK. Uses CVE data, PoC, Affected Products, and News context."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        cve_data = data.get("cveData", {})
        model = data.get("model", DEFAULT_MODEL)
        poc_status = data.get("pocStatus")
        news_context = data.get("newsContext")  # pre-built string ≤400 chars
        # ir_plan_summary no longer needed — MITRE now runs before IR Plan

        if not cve_data:
            return jsonify({"error": "CVE data is required"}), 400

        print(f"\n🎯 Mapping MITRE techniques for {cve_data.get('id', 'Unknown')} "
              f"(news: {bool(news_context)}, affected: {len(cve_data.get('affected', []))})...")
        techniques = map_to_mitre_techniques(cve_data, model,
                                              ir_plan_summary=None,
                                              poc_status=poc_status,
                                              news_context=news_context)

        return jsonify({"mitreTechniques": techniques})
    except Exception as e:
        print(f"✗ map-mitre error: {e}")
        return jsonify({"error": f"MITRE mapping failed: {str(e)}"}), 500


@app.route('/api/models', methods=['GET'])
def get_models():
    """Get list of available Ollama models"""
    try:
        response = requests.get(f"{OLLAMA_API_BASE}/api/tags", timeout=10)
        response.raise_for_status()
        data = response.json()
        
        models = [
            {
                "name": model.get("name", ""),
                "size": model.get("size", 0),
                "modified": model.get("modified_at", "")
            }
            for model in data.get("models", [])
        ]
        
        return jsonify({"models": models})
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Cannot connect to Ollama. Please ensure Ollama is running.",
            "models": []
        }), 503
    except Exception as e:
        return jsonify({"error": str(e), "models": []}), 500


@app.route('/api/model-capabilities', methods=['GET'])
def get_model_capabilities():
    """Get capabilities for a model (e.g. supports_think). Used to choose the right strategy for AI calls."""
    model = (request.args.get("model") or "").strip()
    if not model:
        return jsonify({"error": "model query parameter required"}), 400
    try:
        caps = fetch_model_capabilities(model)
        return jsonify(caps)
    except Exception as e:
        return jsonify({"error": str(e), "supports_think": False}), 500


@app.route('/api/warmup', methods=['POST'])
def warmup_endpoint():
    """Pre-load the Ollama model into memory. keep_alive=10m keeps it resident for multiple calls."""
    try:
        data = request.get_json() or {}
        model = data.get("model", DEFAULT_MODEL)
        resp = requests.post(
            f"{OLLAMA_API_BASE}/api/generate",
            json={"model": model, "prompt": "hi", "stream": False,
                  "options": {"num_predict": 1}, "keep_alive": "10m"},
            timeout=60,
        )
        resp.raise_for_status()
        return jsonify({"status": "ok", "model": model})
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@app.route('/api/search-poc', methods=['POST'])
def search_poc_endpoint():
    """Search GitHub for PoC repositories related to a CVE ID"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        raw = data.get("cveId", "").strip()
        valid, result = validate_cve_format(raw)
        if not valid:
            return jsonify({"error": result}), 400
        cve_id = result

        print(f"\n🔍 Searching GitHub PoCs for {cve_id}...")

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CVE-Analyzer/1.0"
        }

        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        search_url = f"https://api.github.com/search/repositories?q={cve_id}&sort=stars&order=desc&per_page=10"
        try:
            resp = requests.get(search_url, headers=headers, timeout=10)
            resp.raise_for_status()
            search_data = resp.json()
            repos = []
            for item in search_data.get("items", []):
                repos.append({
                    "name": item.get("name"),
                    "full_name": item.get("full_name"),
                    "html_url": item.get("html_url"),
                    "description": item.get("description") or "",
                    "language": item.get("language"),
                    "stargazers_count": item.get("stargazers_count", 0),
                    "forks_count": item.get("forks_count", 0),
                    "updated_at": item.get("updated_at"),
                    "topics": item.get("topics", []),
                    "is_fork": item.get("fork", False),
                    "owner_avatar": item.get("owner", {}).get("avatar_url")
                })
            print(f"✓ Found {len(repos)} repos for {cve_id}")
            return jsonify({"repos": repos, "total": search_data.get("total_count", 0)})
        except requests.exceptions.RequestException as e:
            print(f"⚠ GitHub search failed: {e}")
            return jsonify({"repos": [], "total": 0, "error": str(e)})

    except Exception as e:
        print(f"✗ search-poc error: {e}")
        return jsonify({"error": f"PoC search failed: {str(e)}"}), 500


@app.route('/api/search-news', methods=['POST'])
def search_news_endpoint():
    """
    Search popular cybersecurity news sites for articles mentioning a given CVE.
    Uses Google web search (no extra API key) with site: filters for each domain.
    Queries domains in parallel using ThreadPoolExecutor.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        raw = (data.get("cveId") or "").strip()
        if not raw:
            return jsonify({"error": "cveId is required"}), 400

        valid, result = validate_cve_format(raw)
        if not valid:
            return jsonify({"error": result}), 400
        cve_id = result

        limit_per_source = int(data.get("limitPerSource") or 3)
        limit_per_source = max(1, min(limit_per_source, 5))

        print(f"\n📰 Searching news articles for {cve_id} across {len(NEWS_DOMAINS)} domains...")
        
        all_items = []
        articles_per_source = {}

        # Use ThreadPoolExecutor to query domains in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(NEWS_DOMAINS)) as executor:
            future_to_domain = {
                executor.submit(_google_search_cve_news, cve_id, domain, max_results=limit_per_source): domain
                for domain in NEWS_DOMAINS
            }
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    items = future.result()
                    if items:
                        print(f"   {domain}: {len(items)} article(s)")
                    else:
                        print(f"   {domain}: 0 article(s)")
                    all_items.extend(items)
                    articles_per_source[domain] = len(items)
                except Exception as exc:
                    print(f"   ⚠ {domain} generated an exception: {exc}")
                    articles_per_source[domain] = 0

        # Deduplicate by URL
        seen = set()
        deduped = []
        for item in all_items:
            url = item.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            deduped.append(item)

        return jsonify({
            "cveId": cve_id,
            "total": len(deduped),
            "news": deduped,
            "articlesPerSource": articles_per_source
        })
    except Exception as e:
        print(f"✗ search-news error: {e}")
        return jsonify({"error": f"News search failed: {str(e)}", "news": [], "articlesPerSource": {}}), 500


# Preferred names/paths for PoC/exploit files when loading repo code
REPO_CODE_PRIORITY = (
    "poc", "exploit", "poc.py", "exploit.py", "main.py", "exp.", "cve_", "run.",
    "main.", "poc.", "exploit.", "test_", "demo."
)
REPO_CODE_EXTENSIONS = (".py", ".js", ".sh", ".go", ".rb", ".php", ".java", ".c", ".cpp", ".rs", ".ts")


# Popular security news domains to search for CVE-related articles
NEWS_DOMAINS = [
    "thehackernews.com",
    "cybersecuritynews.com",
    "securityonline.info",
    "threatpost.org",
    "darkreading.com",
    "bleepingcomputer.com",
    "securityweek.com",
    "krebsonsecurity.com",
    "cisa.gov",
]


def _strip_html(text: str) -> str:
    """Very simple HTML tag stripper for search result snippets/titles."""
    if not text:
        return ""
    # Remove tags
    text = re.sub(r"<[^>]+>", "", text)
    # Unescape basic named entities
    replacements = {
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": "\"",
        "&#39;": "'",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Unescape numeric entities like &#8211; and &#x2019;
    def _unescape_numeric(m):
        s = m.group(1)
        try:
            if s.lower().startswith('x'):
                codepoint = int(s[1:], 16)
            else:
                codepoint = int(s, 10)
            return chr(codepoint)
        except Exception:
            return ''
    text = re.sub(r'&#(x?[0-9a-fA-F]+);', _unescape_numeric, text)
    return text.strip()


def _shorten_snippet(snippet: str, max_chars: int = 110) -> str:
    """
    Trim long snippets to a short intro:
    - Take up to max_chars
    - Prefer cutting at the end of the first sentence if possible
    """
    if not snippet:
        return ""
    s = snippet.strip()
    if len(s) <= max_chars:
        return s
    cut = s[:max_chars + 1]
    # Try to end at sentence boundary within last 80 chars
    tail = cut[-80:]
    m = re.search(r'[\.!?]\s+[A-Z]', tail)
    if m:
        end_idx = len(cut) - len(tail) + m.start() + 1
        return cut[:end_idx].strip()
    return cut.rstrip() + "…"

def _direct_site_search(cve_id: str, domain: str, max_results: int = 5) -> list:
    """
    Fallback: use the site's own search endpoint when known.
    This avoids relying on third-party search engines that often block scraping.
    Currently implemented for:
      - cybersecuritynews.com (WordPress search: ?s=)
      - thehackernews.com (search?q=)
    """
    try:
        if domain == "cybersecuritynews.com":
            url = "https://cybersecuritynews.com/"
            params = {"s": cve_id}
        elif domain == "thehackernews.com":
            url = "https://thehackernews.com/search"
            params = {"q": cve_id}
        else:
            return []

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CVEAnalyzer/1.0; +https://github.com)",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"⚠ Direct search for {domain} returned {resp.status_code}")
            return []
        html = resp.text
        results = []

        # Generic link extractor: article links on the same domain that mention the CVE
        link_pattern = re.compile(
            rf'<a[^>]+href="(?P<url>https?://{re.escape(domain)}/[^"#]+)"[^>]*>(?P<title>.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        for m in link_pattern.finditer(html):
            url = m.group("url")
            title = _strip_html(m.group("title"))
            if not title:
                continue
            # Require CVE id in title or very close surrounding text
            if cve_id.upper() not in title.upper():
                # Look slightly around the link for the CVE string
                start = max(0, m.start() - 400)
                end = min(len(html), m.end() + 400)
                snippet_region = html[start:end]
                if cve_id.upper() not in snippet_region.upper():
                    continue

            # Build a short snippet from nearby text
            snippet_html = html[m.end(): m.end() + 800]
            snippet = ""
            p_match = re.search(r'<p[^>]*>(?P<p>.*?)</p>', snippet_html, re.IGNORECASE | re.DOTALL)
            if p_match:
                raw_snip = _strip_html(p_match.group("p"))
                if title and raw_snip.lower().startswith(title.lower()[:40]):
                    # Drop repeated title from snippet
                    raw_snip = raw_snip[len(title):].lstrip(" -–—|:•")
                snippet = _shorten_snippet(raw_snip)

            results.append(
                {
                    "source": domain,
                    "title": title,
                    "url": url,
                    "summary": snippet,
                }
            )
            if len(results) >= max_results:
                break

        return results
    except Exception as e:
        print(f"⚠ Direct site search failed for {domain}: {e}")
        return []


def _google_search_cve_news(cve_id: str, domain: str, max_results: int = 3) -> list:
    """
    Use a public web search engine to find news articles about a CVE on a specific domain.
    Originally this used Google HTML, but many environments hit captchas / 4xx.
    Now it uses DuckDuckGo's HTML endpoint, which is more scraping-friendly and
    still does not require an API key.
    """
    try:
        # Prefer direct site search for domains we know how to query
        direct_results = _direct_site_search(cve_id, domain, max_results=max_results)
        if direct_results:
            return direct_results

        query = f"\"{cve_id}\" site:{domain}"
        params = {"q": query}
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CVEAnalyzer/1.0; +https://github.com)",
            "Accept-Language": "en-US,en;q=0.9",
        }
        # DuckDuckGo HTML results page
        resp = requests.get("https://duckduckgo.com/html/", params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"⚠ DuckDuckGo search for {domain} returned {resp.status_code}")
            return []
        html = resp.text
        results = []

        # DuckDuckGo HTML layout: <a class="result__a" href="URL">Title</a>
        link_pattern = re.compile(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="(?P<url>https?[^"]+)"[^>]*>(?P<title>.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        )
        pos = 0
        while len(results) < max_results:
            m = link_pattern.search(html, pos)
            if not m:
                break
            pos = m.end()
            url = m.group("url")
            title_html = m.group("title")
            title = _strip_html(title_html)
            if not title or domain not in url:
                continue

            # Find nearby snippet: <a class="result__snippet">...</a> or <div class="result__snippet">...</div>
            snippet = ""
            tail = html[m.end() : m.end() + 1200]
            snip_match = re.search(
                r'class="[^"]*result__snippet[^"]*"[^>]*>(?P<snip>.*?)</',
                tail,
                re.IGNORECASE | re.DOTALL,
            )
            if snip_match:
                snippet = _shorten_snippet(_strip_html(snip_match.group("snip")))

            results.append(
                {
                    "source": domain,
                    "title": title,
                    "url": url,
                    "summary": snippet,
                }
            )

        return results
    except Exception as e:
        print(f"⚠ News search failed for {domain}: {e}")
        return []


def _pick_repo_file(files):
    """From GitHub API 'contents' list (root), pick best candidate for exploit/PoC code."""
    if not files:
        return None
    by_name = {f.get("name", "").lower(): f for f in files if f.get("type") == "file"}
    # Prefer files whose name suggests PoC/exploit
    for key in REPO_CODE_PRIORITY:
        for name, obj in by_name.items():
            if key in name and any(name.endswith(ext) for ext in REPO_CODE_EXTENSIONS):
                return obj.get("path") or obj.get("name")
    # Then any code file in root
    for name, obj in sorted(by_name.items()):
        if any(name.endswith(ext) for ext in REPO_CODE_EXTENSIONS):
            return obj.get("path") or obj.get("name")
    # Fallback: README
    for name in ("readme.md", "readme.txt", "readme"):
        if name in by_name:
            return by_name[name].get("path") or by_name[name].get("name")
    return None


@app.route('/api/repo-file', methods=['POST'])
def repo_file_endpoint():
    """Fetch a single file content from a GitHub repo (root PoC/exploit preferred)."""
    try:
        data = request.get_json() or {}
        full_name = (data.get("full_name") or data.get("repo") or "").strip()
        if not full_name or "/" not in full_name:
            return jsonify({"error": "Missing or invalid repo full_name (e.g. owner/repo)"}), 400

        headers = {
            "Accept": "application/vnd.github.v3+json, application/vnd.github.raw",
            "User-Agent": "cveResponder/1.0"
        }
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"

        parts = full_name.split("/", 1)
        owner, repo = parts[0], parts[1]

        # Get default branch
        repo_url = f"https://api.github.com/repos/{owner}/{repo}"
        r = requests.get(repo_url, headers={**headers, "Accept": "application/vnd.github.v3+json"}, timeout=10)
        if r.status_code != 200:
            return jsonify({"error": f"Repo not found or inaccessible: {r.status_code}"}), 404
        default_branch = r.json().get("default_branch") or "main"

        # List root contents
        contents_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
        r = requests.get(contents_url, headers={**headers, "Accept": "application/vnd.github.v3+json"}, timeout=10)
        if r.status_code != 200:
            return jsonify({"error": f"Could not list repo contents: {r.status_code}"}), 404
        files = r.json() if isinstance(r.json(), list) else []

        path = _pick_repo_file(files)
        if not path:
            return jsonify({"error": "No suitable code file found in repo root", "content": None}), 404

        # Raw file content
        file_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        r = requests.get(file_url, headers={**headers, "Accept": "application/vnd.github.raw"}, timeout=15)
        if r.status_code != 200:
            return jsonify({"error": f"Could not fetch file: {r.status_code}", "path": path}), 404
        content = r.text if r.text is not None else ""

        return jsonify({"content": content, "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


POC_ANALYSIS_PROMPT_TEMPLATE = string.Template("""CVE: $cve_context

Code:
$code

Analyze the exploit code thoroughly and return a valid JSON object matching the requested schema. Provide detailed technical explanations, not just brief summaries.

Ensure your analysis specifically covers:
1. overview: A detailed 3-4 sentence explanation of the exploit's purpose and impact.
2. mechanics: A step-by-step technical explanation of how the vulnerability trigger works.
3. code_flow: The execution flow of the script (e.g., initialization, request setup, payload delivery).
4. key_functions: Array of objects with 'name' and 'description' of critical functions in the code.
5. cve_relationship: Exactly how this code targets the specific CVE listed above.
6. payload: Analysis of the malicious payload being delivered.
7. steps: An array of strings describing the high-level exploitation steps.
8. detection: Actionable strategies for detecting this exploit attempt (logs, SIEM rules, etc.).
9. mitigation: Instructions on mitigating the vulnerability.
10. highlighted_line: The exact, single most critical line of code.
11. highlighted_explanation: Detailed explanation of why that line is critical.
12. attack_path: Array of objects describing the kill chain.

IMPORTANT: Return ONLY the JSON object. Do not include markdown or reasoning text.
""")

POC_ANALYSIS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "overview": {"type": "string"},
        "mechanics": {"type": "string"},
        "code_flow": {"type": "string"},
        "key_functions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"}
                },
                "required": ["name", "description"]
            }
        },
        "cve_relationship": {"type": "string"},
        "payload": {"type": "string"},
        "steps": {
            "type": "array",
            "items": {"type": "string"}
        },
        "detection": {"type": "string"},
        "mitigation": {"type": "string"},
        "highlighted_line": {"type": "string"},
        "highlighted_explanation": {"type": "string"},
        "attack_path": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"}
                },
                "required": ["type", "title", "description"]
            }
        }
    },
    "required": [
        "overview", "mechanics", "code_flow", "key_functions", 
        "cve_relationship", "payload", "steps", "detection", 
        "mitigation", "highlighted_line", "highlighted_explanation", "attack_path"
    ]
}



def _parse_exploit_json(raw: str) -> dict:
    """Parse LLM exploit analysis response with multiple fallback strategies."""
    raw = raw.replace("```json", "").replace("```", "").strip()

    # Strategy 1: Direct JSON parse (ideal case)
    start = raw.find('{')
    end = raw.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            pass

    # Strategy 2: Regex extraction of individual fields from truncated JSON
    def extract_str(key):
        pattern = rf'"{key}"\s*:\s*"((?:[^"\\]|\\.)*)"'
        m = re.search(pattern, raw, re.DOTALL)
        return m.group(1).replace('\\"', '"').replace('\\n', '\n') if m else ""

    def extract_array(key):
        pattern = rf'"{key}"\s*:\s*\[(.*?)\]'
        m = re.search(pattern, raw, re.DOTALL)
        if not m:
            return []
        inner = m.group(1).strip()
        items = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
        return [i.replace('\\"', '"') for i in items]

    def extract_attack_path():
        pattern = r'"attack_path"\s*:\s*\[(.*)'
        m = re.search(pattern, raw, re.DOTALL)
        if not m:
            return []
        block = m.group(1)
        nodes = []
        for obj_match in re.finditer(
            r'\{\s*"type"\s*:\s*"([^"]*)"\s*,\s*"title"\s*:\s*"([^"]*)"\s*,\s*"description"\s*:\s*"((?:[^"\\]|\\.)*)"\s*\}',
            block
        ):
            nodes.append({
                "type": obj_match.group(1),
                "title": obj_match.group(2),
                "description": obj_match.group(3).replace('\\"', '"')
            })
        return nodes

    analysis = {
        "overview": extract_str("overview"),
        "mechanics": extract_str("mechanics"),
        "code_flow": extract_str("code_flow"),
        "key_functions": [], # Complex extraction skipped in regex fallback
        "cve_relationship": extract_str("cve_relationship"),
        "payload": extract_str("payload"),
        "steps": extract_array("steps"),
        "detection": extract_str("detection"),
        "mitigation": extract_str("mitigation"),
        "highlighted_line": extract_str("highlighted_line"),
        "highlighted_explanation": extract_str("highlighted_explanation"),
        "attack_path": extract_attack_path(),
    }

    has_content = any(v for k, v in analysis.items() if k != "attack_path")
    if has_content:
        print(f"  ✓ JSON recovered via regex extraction")
        return analysis

    # Strategy 3: Complete failure — return raw text in overview
    print(f"  ⚠ All JSON strategies failed, returning raw text")
    return {
        "overview": raw[:600] if raw else "Analysis could not be parsed.",
        "mechanics": "", "code_flow": "", "key_functions": [],
        "cve_relationship": "", "payload": "", "steps": [],
        "detection": "", "mitigation": "", "attack_path": []
    }


@app.route('/api/analyze-exploit', methods=['POST'])
def analyze_exploit_endpoint():
    """Analyze exploit code using Ollama LLM"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        code = data.get("code", "").strip()
        cve_data = data.get("cveData", {})
        model = data.get("model", DEFAULT_MODEL)

        if not code:
            return jsonify({"error": "Exploit code is required"}), 400

        code_excerpt = code[:3000]

        cve_context = "No CVE context available."
        if cve_data:
            cve_id = cve_data.get("id", "")
            desc = cve_data.get("description", "")[:300]
            cvss = cve_data.get("cvss", {})
            score = cvss.get("score", "N/A")
            cve_context = f"{cve_id} (CVSS: {score}) — {desc}"

        prompt = POC_ANALYSIS_PROMPT_TEMPLATE.substitute(
            cve_context=cve_context,
            code=code_excerpt
        )

        print(f"\n🤖 Analyzing exploit code ({len(code)} chars) with {model}...")

        raw = ollama_chat(
            model,
            "You are a senior security researcher. Provide detailed, expert analysis of exploit code. Rely ONLY on the code and CVE data provided.",
            prompt,
            options={"temperature": 0.1, "num_predict": 4096},
            timeout=180,
            think=False,
            format=POC_ANALYSIS_JSON_SCHEMA
        )
        print(f"  Raw response ({len(raw)} chars): {raw[:150]}...")

        analysis = _parse_exploit_json(raw)

        print(f"✓ Exploit analysis complete (fields: {[k for k,v in analysis.items() if v]})")
        return jsonify({"analysis": analysis})

    except Exception as e:
        print(f"✗ analyze-exploit error: {e}")
        return jsonify({"error": f"Exploit analysis failed: {str(e)}"}), 500





@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    ollama_status = "unknown"
    try:
        response = requests.get(f"{OLLAMA_API_BASE}/api/tags", timeout=5)
        ollama_status = "connected" if response.status_code == 200 else "error"
    except Exception:
        ollama_status = "disconnected"
    
    return jsonify({
        "status": "running",
        "ollama": ollama_status
    })


if __name__ == '__main__':
    print("=" * 50)
    print("cveResponderAI Backend Server")
    print("=" * 50)
    print(f"NVD API: {NVD_API_BASE}")
    print(f"Ollama API: {OLLAMA_API_BASE}")
    print("=" * 50)
    print("Starting server on http://localhost:5001")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=5001, debug=True)
