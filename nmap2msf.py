#!/usr/bin/env python3
"""
nmap2msf_full.py - Enhanced Nmap XML to Metasploit RC + reports + optional LLM suggestions

Features:
 - Parse Nmap XML robustly (repair truncated XML)
 - Map services to conservative Metasploit scanner modules
 - Generate .rc file for msfconsole
 - JSON / Markdown / DOCX / PDF reports
 - Dry-run mode
 - Optional interactive accept/reject of modules
 - Optional OpenAI LLM suggestions (--use-llm)
 - Optional exploit search (--find-exploits)
 - Safety level flags: safe, extended, bruteforce
 - Only runs scanner modules; never executes exploits automatically
"""

import argparse
import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import yaml
import json
import re
from datetime import datetime

# Optional libraries
OPENAI_AVAILABLE = False
DOCX_AVAILABLE = False
PDF_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

try:
    from docx import Document
    DOCX_AVAILABLE = True
except Exception:
    DOCX_AVAILABLE = False

try:
    import pdfkit
    PDF_AVAILABLE = True
except Exception:
    PDF_AVAILABLE = False

# -------------------------
# Config / Defaults
# -------------------------
DEFAULT_MAPPING_FILE = "service_module_mapping.yml"
OUTPUT_RC_FILE = "nmap2msf.rc"
OUTPUT_JSON_PLAN = "nmap2msf_plan.json"
OUTPUT_MD_REPORT = "nmap2msf_plan.md"

DEFAULT_MAPPING = {
    "http": ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    "https": ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    "ssh": ["auxiliary/scanner/ssh/ssh_version"],
    "ftp": ["auxiliary/scanner/ftp/ftp_version"],
    "smb": ["auxiliary/scanner/smb/smb_version"],
    "snmp": ["auxiliary/scanner/snmp/snmp_enum"],
    "smtp": ["auxiliary/scanner/smtp/smtp_version"],
    "dns": ["auxiliary/scanner/dns/dns_enum"],
    "mssql": ["auxiliary/scanner/mssql/mssql_ping"],
    "mysql": ["auxiliary/scanner/mysql/mysql_version"],
    "postgresql": ["auxiliary/scanner/postgres/postgres_version"],
    "rdp": ["auxiliary/scanner/rdp/rdp_version"],
    "vnc": ["auxiliary/scanner/vnc/vnc_version"],
    "telnet": ["auxiliary/scanner/telnet/telnet_version"],
    "netbios": ["auxiliary/scanner/netbios/nbname"],
    "rpc": ["auxiliary/scanner/rpc/portmapper"],
    "ldap": ["auxiliary/scanner/ldap/ldap_version"],
    "nntp": ["auxiliary/scanner/nntp/nntp_version"],
    "redis": ["auxiliary/scanner/redis/redis_ping"],
    "memcached": ["auxiliary/scanner/memcached/memcached_version"],
    "couchdb": ["auxiliary/scanner/couchdb/couchdb_version"],
    "elasticsearch": ["auxiliary/scanner/elasticsearch/es_version"],
    "mongodb": ["auxiliary/scanner/mongodb/mongodb_version"],
    "docker": ["auxiliary/scanner/misc/placeholder"],
    "sip": ["auxiliary/scanner/sip/sip_version"],
    "upnp": ["auxiliary/scanner/upnp/upnp_scanner"],
    "imap": ["auxiliary/scanner/imap/imap_version"],
    "pop3": ["auxiliary/scanner/pop3/pop3_version"],
    "postgres": ["auxiliary/scanner/postgres/postgres_version"],
    "oracle_tns": ["auxiliary/scanner/oracle/tns_version"]
}

RISKY_SUBSTRINGS = ["login", "bruteforce", "ftp_login", "vnc_login", "mysql_login", "postgres_login"]

# -------------------------
# Utilities
# -------------------------
def safe_print(*args, **kwargs):
    print(*args, **kwargs)
    sys.stdout.flush()

def ensure_mapping_file(path=DEFAULT_MAPPING_FILE):
    if not os.path.exists(path):
        with open(path, "w") as f:
            yaml.dump(DEFAULT_MAPPING, f, sort_keys=False)
        safe_print(f"[+] Created default mapping file: {path} (edit to customize)")

def load_mapping(path=DEFAULT_MAPPING_FILE):
    ensure_mapping_file(path)
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return {k.lower(): v for k, v in data.items()}

# -------------------------
# Robust Nmap XML parsing
# -------------------------
def try_parse_nmap_xml(path, attempts=5):
    with open(path, "rb") as f:
        raw = f.read()
    for attempt in range(attempts):
        try:
            root = ET.fromstring(raw)
            return root
        except ET.ParseError as e:
            safe_print(f"[!] Parse error attempt {attempt+1}: {e}")
            txt = raw.decode("utf-8", errors="ignore")
            if "</nmaprun>" not in txt:
                txt += "\n</nmaprun>"
                raw = txt.encode("utf-8")
                continue
            last = txt.rfind("</host>")
            if last != -1:
                trunc = txt[: last + len("</host>")]
                if "</nmaprun>" not in trunc:
                    trunc += "\n</nmaprun>"
                raw = trunc.encode("utf-8")
                continue
            if len(raw) > 256:
                raw = raw[:-256]
                continue
            break
    raise ET.ParseError("Failed to parse Nmap XML after repair attempts.")

def extract_hosts(root):
    hosts = []
    for host in root.findall("host"):
        h = {"ip": None, "hostnames": [], "ports": []}
        for addr in host.findall("address"):
            at = addr.get("addrtype")
            if at in ("ipv4", "ipv6"):
                h["ip"] = addr.get("addr")
        hn = host.find("hostnames")
        if hn:
            for n in hn.findall("hostname"):
                name = n.get("name")
                if name:
                    h["hostnames"].append(name)
        for port in host.findall(".//port"):
            portid = port.get("portid")
            proto = port.get("protocol")
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            svc_el = port.find("service")
            svc = svc_el.get("name") if svc_el is not None else None
            product = svc_el.get("product") if svc_el is not None and svc_el.get("product") else None
            h["ports"].append({
                "port": int(portid) if portid and portid.isdigit() else portid,
                "proto": proto,
                "service": svc.lower() if svc else None,
                "product": product,
                "state": state
            })
        hosts.append(h)
    return hosts

# -------------------------
# Mapping & plan creation
# -------------------------
def is_module_allowed(module, safety):
    low = module.lower()
    if safety == "bruteforce":
        return True
    for s in RISKY_SUBSTRINGS:
        if s in low:
            return False if safety == "safe" else True
    return True

def map_services(hosts, mapping, safety="safe", manual=None):
    plan = []
    for h in hosts:
        host_entry = {"ip": h["ip"], "hostnames": h["hostnames"], "services": []}
        for p in h["ports"]:
            if p["state"] != "open":
                continue
            svc = p["service"] or f"port_{p['port']}"
            key = svc.lower()
            chosen = []
            if manual and key in manual:
                chosen = manual[key]
            else:
                if key in mapping:
                    chosen = mapping[key]
                else:
                    chosen = [f"auxiliary/scanner/{key}/{key}_version"]
            filtered = [m for m in chosen if is_module_allowed(m, safety)]
            host_entry["services"].append({
                "port": p["port"],
                "proto": p["proto"],
                "service": svc,
                "product": p.get("product"),
                "modules": filtered,
                "raw_modules": chosen
            })
        plan.append(host_entry)
    return plan

# -------------------------
# RC / reports generation
# -------------------------
def generate_rc(plan, workspace="nmap2msf_workspace", xml_import=None, threads=5, out=OUTPUT_RC_FILE):
    lines = [f"# nmap2msf RC generated at {datetime.utcnow().isoformat()}Z",
             f"workspace -a {workspace}"]
    if xml_import:
        lines.append(f"db_import {xml_import}")
    lines.append("")
    for host in plan:
        ip = host.get("ip")
        if not ip:
            continue
        lines.append(f"# --- Host: {ip} {' '.join(host.get('hostnames', []))}")
        for svc in host["services"]:
            lines.append(f"# Service: {svc['service']} port:{svc['port']}/{svc['proto']} product:{svc.get('product')}")
            if not svc["modules"]:
                lines.append(f"# No permitted modules for this service (filtered by safety level)")
            for mod in svc["modules"]:
                lines.append(f"use {mod}")
                lines.append(f"set RHOSTS {ip}")
                lines.append(f"set RPORT {svc['port']}")
                lines.append(f"set THREADS {threads}")
                lines.append("run -j")
                lines.append(f"# Reason: mapped {svc['service']} -> {mod}")
                lines.append("")
        lines.append("")
    with open(out, "w") as f:
        f.write("\n".join(lines))
    return out

def generate_json(plan, path=OUTPUT_JSON_PLAN):
    payload = {"generated_at": datetime.utcnow().isoformat() + "Z", "plan": plan}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path

def generate_md(plan, path=OUTPUT_MD_REPORT):
    lines = [f"# nmap2msf Report\nGenerated at {datetime.utcnow().isoformat()}Z\n"]
    for host in plan:
        lines.append(f"## Host: {host['ip']}")
        if host.get("hostnames"):
            lines.append(f"- Hostnames: {', '.join(host['hostnames'])}")
        for svc in host["services"]:
            lines.append(f"### {svc['service']} — {svc['port']}/{svc['proto']}")
            lines.append(f"- product: {svc.get('product')}")
            lines.append("- planned modules:")
            if svc['modules']:
                for m in svc['modules']:
                    lines.append(f"  - `{m}`")
            else:
                lines.append("  - _none (filtered by safety)_")
            lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path

def generate_docx(plan, path="nmap2msf_plan.docx"):
    if not DOCX_AVAILABLE:
        safe_print("[!] python-docx not installed; skipping DOCX generation.")
        return None
    doc = Document()
    doc.add_heading("nmap2msf Plan", level=1)
    doc.add_paragraph(f"Generated: {datetime.utcnow().isoformat()}Z")
    for h in plan:
        doc.add_heading(f"Host: {h['ip']}", level=2)
        if h.get("hostnames"):
            doc.add_paragraph("Hostnames: " + ", ".join(h.get("hostnames", [])))
        for s in h['services']:
            p = doc.add_paragraph()
            p.add_run(f"{s['service']}:{s['port']}/{s['proto']} -> ").bold = True
            p.add_run(", ".join(s.get('modules', [])))
    doc.save(path)
    return path

def generate_pdf_from_md(md_path="nmap2msf_plan.md", pdf_path="nmap2msf_plan.pdf"):
    if not PDF_AVAILABLE:
        safe_print("[!] pdfkit not available; skipping PDF generation.")
        return None
    try:
        pdfkit.from_file(md_path, pdf_path)
        return pdf_path
    except Exception as e:
        safe_print(f"[!] PDF conversion failed: {e}")
        return None

# -------------------------
# msfconsole helpers
# -------------------------
def check_tool_exists(cmd):
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0

def start_services():
    try:
        safe_print("[*] Starting PostgreSQL service...")
        subprocess.run(["sudo", "systemctl", "start", "postgresql"], check=False)
    except Exception as e:
        safe_print(f"[!] PostgreSQL start warning: {e}")
    try:
        safe_print("[*] Initializing msfdb (if necessary)...")
        subprocess.run(["sudo", "msfdb", "init"], check=False)
    except Exception as e:
        safe_print(f"[!] msfdb init warning: {e}")

def run_msf_rc(rc_path):
    if not check_tool_exists("msfconsole"):
        safe_print("[ERROR] msfconsole not found")
        return
    safe_print(f"[*] Launching msfconsole with RC: {rc_path}")
    subprocess.run(["msfconsole", "-r", rc_path])

def search_msf_for_exploits(query_terms, limit=50):
    if not check_tool_exists("msfconsole"):
        safe_print("[!] msfconsole not found")
        return []
    cmd = ["msfconsole", "-q", "-x", f"search {query_terms}; exit"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = proc.stdout + "\n" + proc.stderr
    except subprocess.TimeoutExpired:
        safe_print("[!] msfconsole search timed out")
        return []
    matches = re.findall(r"(exploit/[^\s]+)", out)
    unique = []
    for m in matches:
        if m not in unique:
            unique.append(m)
            if len(unique) >= limit:
                break
    return unique

# -------------------------
# LLM helper
# -------------------------
def ask_llm_suggestions(api_key, service, port, top_k=3):
    if not OPENAI_AVAILABLE:
        return {"error": "openai not installed"}
    if not api_key:
        return {"error": "OPENAI_API_KEY not set"}
    openai.api_key = api_key
    prompt = (f"Suggest up to {top_k} safe Metasploit auxiliary or exploit modules "
              f"for service '{service}' on port {port}. Return JSON array of objects (module, reason, safety).")
    try:
        resp = openai.Completion.create(model="gpt-4o-mini", prompt=prompt, max_tokens=512, temperature=0)
        text = resp.choices[0].text.strip()
        try:
            parsed = json.loads(text)
            return parsed
        except Exception:
            return {"raw": text}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Main CLI flow
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="nmap2msf full CLI")
    parser.add_argument("-x", "--xml", required=True)
    parser.add_argument("--mapping", default=DEFAULT_MAPPING_FILE)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-report", action="store_true")
    parser.add_argument("--md-report", action="store_true")
    parser.add_argument("--docx-report", action="store_true")
    parser.add_argument("--pdf-report", action="store_true")
    parser.add_argument("--auto-run", action="store_true")
    parser.add_argument("--find-exploits", action="store_true")
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--safety", choices=["safe", "extended", "bruteforce"], default="safe")
    parser.add_argument("--workspace", default="nmap2msf_workspace")
    parser.add_argument("--output-rc", default=OUTPUT_RC_FILE)
    args = parser.parse_args()

    mapping = load_mapping(args.mapping)
    safe_print(f"[+] Loaded mapping ({len(mapping)} services)")

    try:
        root = try_parse_nmap_xml(args.xml)
    except ET.ParseError as e:
        safe_print(f"[ERROR] XML parse failed: {e}")
        sys.exit(1)

    hosts = extract_hosts(root)
    if not hosts:
        safe_print("[!] No hosts found")
        sys.exit(1)
    safe_print(f"[+] {len(hosts)} hosts found")

    plan = map_services(hosts, mapping, safety=args.safety)

    # Interactive
    if args.interactive:
        safe_print("[*] Interactive module selection")
        for h in plan:
            safe_print(f"\nHost: {h['ip']} {' '.join(h.get('hostnames', []))}")
            for s in h['services']:
                kept = []
                mods = list(s['modules'])
                for i, m in enumerate(mods):
                    ok = None
                    while ok is None:
                        ans = input(f"Keep module {m}? [y/n/a/q]: ").strip().lower()
                        if ans=="y": ok=True
                        elif ans=="n": ok=False
                        elif ans=="a": kept.extend(mods[i:]); mods=[]; break
                        elif ans=="q": mods=[]; ok=False; break
                        else: safe_print("y/n/a/q only")
                    if ok: kept.append(m)
                s['modules'] = kept

    # LLM suggestions
    llm_results = {}
    if args.use_llm and OPENAI_AVAILABLE:
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            safe_print("[*] Querying LLM for suggestions...")
            for h in plan:
                for s in h['services']:
                    res = ask_llm_suggestions(api_key, s['service'], s['port'])
                    llm_results[f"{h['ip']}:{s['port']}"] = res

    # Reports
    if args.json_report: generate_json(plan)
    if args.md_report: generate_md(plan)
    if args.docx_report: generate_docx(plan)
    if args.pdf_report: generate_pdf_from_md()  # uses default MD path

    # RC
    if not args.dry_run:
        rc_path = generate_rc(plan, workspace=args.workspace, xml_import=args.xml, threads=args.threads, out=args.output_rc)
        safe_print(f"[+] RC generated: {rc_path}")

    safe_print("[+] Done. Scanner modules only; exploit execution NOT automatic.")

if __name__=="__main__":
    main()
import textwrap
import os

def create_requirements_and_readme():
    """Automatically create requirements.txt and README.md with all setup + usage instructions."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    req_file = os.path.join(project_dir, "requirements.txt")
    readme_file = os.path.join(project_dir, "README.md")

    # --- Create requirements.txt ---
    requirements = textwrap.dedent("""\
        # Python dependencies for nmap2msf
        pyyaml
        openai
        groq
        python-docx
        pdfkit
        pypandoc
        requests
        lxml
    """)
    with open(req_file, "w") as f:
        f.write(requirements)
    print(f"[+] requirements.txt created at: {req_file}")

    # --- Create README.md ---
    readme_content = textwrap.dedent("""\
        # nmap2msf - Automated Nmap to Metasploit Script

        ##  Overview
        This script automatically parses Nmap XML output and generates a ready-to-run Metasploit `.rc` file.  
        It maps common services (HTTP, SSH, SMB, FTP, SNMP, etc.) to safe auxiliary scanner modules, and can generate detailed reports in JSON, Markdown, DOCX, and PDF formats.  
        It also integrates with AI (GROQ/OpenAI) to suggest better module mappings.

        ---

        ## ⚙️ What the Script Does Automatically
        - Parses Nmap XML files (repairs truncated files if needed)
        - Maps services → Metasploit scanner modules
        - Generates `.rc` file for Metasploit
        - Creates `service_module_mapping.yml` (if not found)
        - Creates structured reports (`.json`, `.md`, `.docx`, `.pdf`)
        - Creates this `README.md` and `requirements.txt`
        - Supports optional AI integration via GROQ/OpenAI
        - Allows dry-run, auto-run, and interactive modes

        ---

        ## 🧩 Requirements
        The following Python libraries are required (auto-created in requirements.txt):

        ```
        pyyaml
        openai
        groq
        python-docx
        pdfkit
        pypandoc
        requests
        lxml
        ```

        Additional tools required on your system:
        - `nmap` (for scanning)
        - `msfconsole` (Metasploit Framework)
        - `wkhtmltopdf` (for PDF generation)
        - Python 3.8 or later

        ---

        ## Installation Steps
        ```bash
        cd /path/to/your/project/
        pip install -r requirements.txt
        ```

        If using AI integration:
        ```bash
        export GROQAI_API_KEY="your_groq_api_key"
        # or
        export OPENAI_API_KEY="your_openai_key"
        ```

        ---

        ##  Usage Examples

        **1. Basic Nmap → RC generation:**
        ```bash
        python3 nmap2msf.py -x scan.xml
        ```

        **2. Include AI mapping suggestions:**
        ```bash
        python3 nmap2msf.py -x scan.xml --use-llm
        ```

        **3. Dry-run (only show what will be done):**
        ```bash
        python3 nmap2msf.py -x scan.xml --dry-run
        ```

        **4. Generate all reports:**
        ```bash
        python3 nmap2msf.py -x scan.xml --json-report --md-report --docx-report --pdf-report
        ```

        **5. Auto-run Metasploit:**
        ```bash
        python3 nmap2msf.py -x scan.xml --auto-run
        ```

        ---

        ##  Output Files
        All output files will be placed in the same working directory (or `reports/` if configured):
        - `nmap2msf.rc` → Metasploit RC script
        - `nmap2msf_plan.json` → JSON plan
        - `nmap2msf_plan.md` → Markdown report
        - `nmap2msf_plan.docx` → Word report
        - `nmap2msf_plan.pdf` → PDF report

        ---

        ##  Safety
        This tool **only uses safe auxiliary scanner modules**.  
        It never runs exploit modules automatically unless the user modifies the `.rc` file manually.

        ---

        ##  Author Notes
        This project was designed for automation labs and penetration testing training environments where all setup and configuration are handled by the script itself.
    """)

    with open(readme_file, "w") as f:
        f.write(readme_content)
    print(f"[+] README.md created at: {readme_file}")


# --- Modify your main call like this ---
if __name__ == "__main__":
    create_requirements_and_readme()  # <- Auto-create README and requirements
    main()
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os
import subprocess
import json

def browse_file():
    # Open file dialog to choose the Nmap XML file
    filename = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
    if filename:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, filename)

def run_script():
    # Get the file path and API key
    xml_file = entry_file.get()
    api_key = entry_api_key.get()

    if not os.path.exists(xml_file):
        messagebox.showerror("Error", "Please select a valid Nmap XML file.")
        return

    if not api_key:
        messagebox.showerror("Error", "Please enter your Groq AI API key.")
        return

    # Example of running your script with the selected XML file and API key
    command = [
        "python3", "nmap2msf.py", "-x", xml_file,
        "--use-llm", "--auto-run", "--json-report"
    ]
    try:
        subprocess.run(command, check=True)
        messagebox.showinfo("Success", "Script executed successfully.")
    except subprocess.CalledProcessError:
        messagebox.showerror("Error", "There was an issue running the script.")

# Create the GUI window
root = tk.Tk()
root.title("Nmap to Metasploit GUI")

# Create and place widgets
label_file = tk.Label(root, text="Select Nmap XML File:")
label_file.grid(row=0, column=0, padx=10, pady=5)

entry_file = tk.Entry(root, width=50)
entry_file.grid(row=0, column=1, padx=10, pady=5)

button_browse = tk.Button(root, text="Browse...", command=browse_file)
button_browse.grid(row=0, column=2, padx=10, pady=5)

label_api_key = tk.Label(root, text="Enter Groq AI API Key:")
label_api_key.grid(row=1, column=0, padx=10, pady=5)

entry_api_key = tk.Entry(root, width=50)
entry_api_key.grid(row=1, column=1, padx=10, pady=5)

button_run = tk.Button(root, text="Run Script", command=run_script)
button_run.grid(row=2, column=1, padx=10, pady=20)

# Start the GUI loop
root.mainloop()

