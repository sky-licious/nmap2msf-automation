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
# nmap2msf-automation
