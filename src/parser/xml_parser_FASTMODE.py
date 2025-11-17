"""
XML Parser FASTMODE — SAFE MODE
Versione ottimizzata con:
- Cache locale CVE
- Limite richieste NVD (30)
- Enrichment solo HIGH/CRITICAL
- Progress bar avanzata
- Deduplicazione CVE
- Compatibile con generate_report.py
"""

import os
import json
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

# ============================================================
# CONFIGURAZIONE FASTMODE
# ============================================================

# Directory della cache (consigliata)
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_FILE = CACHE_DIR / "cve_cache.json"

# Assicuriamoci che esista
CACHE_DIR.mkdir(parents=True, exist_ok=True)
if not CACHE_FILE.exists():
    CACHE_FILE.write_text("{}")

# Numero massimo richieste consentite (SAFE MODE)
MAX_NVD_REQUESTS = 30

# Enrichment solo per CVE importanti
ALLOWED_SEVERITIES = {"HIGH", "CRITICAL"}

# ============================================================
# Funzioni cache FASTMODE
# ============================================================

def load_cve_cache() -> dict:
    """Carica la cache locale dei CVE."""
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_cve_cache(cache: dict):
    """Salva la cache locale CVE."""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"⚠ Errore salvataggio cache: {e}")

# Cache in RAM
CVE_CACHE = load_cve_cache()


# ============================================================
# Funzione progress bar avanzata
# ============================================================

def progress_bar(current, total, prefix=""):
    """Progress bar 20-step elegante."""
    bar_len = 20
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    return f"{prefix} [{bar}] {current}/{total}"

# ============================================================
# PARTE 2 — PARSING BASE
# ============================================================

def parse_nmap_xml(xml_file):
    """Parse Nmap XML file e crea le vulnerabilità di base."""
    vulnerabilities = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall('.//host'):
            addr_elem = host.find('.//address[@addrtype="ipv4"]') \
                        or host.find('.//address[@addrtype="ipv6"]')
            ip_address = addr_elem.get('addr') if addr_elem is not None else "unknown"

            hostname_elem = host.find('.//hostname')
            hostname = hostname_elem.get('name') if hostname_elem is not None else ""

            # Parse ports
            for port in host.findall('.//port'):
                port_id = port.get("portid")
                protocol = port.get("protocol")

                service = port.find("service")
                service_name = service.get("name", "unknown") if service else "unknown"

                # Parse NSE scripts
                for script in port.findall('.//script'):
                    script_id = script.get("id")
                    script_output = script.get("output", "")

                    if "vuln" in script_id or "cve" in script_id.lower():
                        cve_pattern = r"CVE-\d{4}-\d{4,7}"
                        cves = re.findall(cve_pattern, script_output)

                        # CVSS base extraction
                        cvss_pattern = r"CVSS(?:v[23])?:\s*(\d+\.?\d*)"
                        cvss = re.findall(cvss_pattern, script_output)
                        cvss_score = float(cvss[0]) if cvss else 0.0

                        if cves:
                            for cve_id in cves:
                                vulnerabilities.append({
                                    "cve_id": cve_id,
                                    "ip_address": ip_address,
                                    "hostname": hostname,
                                    "port": port_id,
                                    "protocol": protocol,
                                    "service": service_name,
                                    "cvss_score": cvss_score,
                                    "severity": _determine_severity(cvss_score),
                                    "description": script_output[:400]
                                })
                        else:
                            vulnerabilities.append({
                                "cve_id": f"NMAP-{script_id}",
                                "ip_address": ip_address,
                                "hostname": hostname,
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "cvss_score": cvss_score,
                                "severity": _determine_severity(cvss_score),
                                "description": script_output[:400]
                            })

        print(f"✓ Parsed {len(vulnerabilities)} vulnerabilities from XML")
        return vulnerabilities

    except Exception as e:
        print(f"✗ Error parsing XML: {e}")
        return []


def _determine_severity(score):
    """Calcola la severity dal CVSS."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ============================================================
# PARTE 3 — ENHANCED PARSER CON FASTMODE (SAFE MODE)
# ============================================================

class FASTMODEParser:
    """Parser avanzato con ML + FASTMODE per NVD."""

    def __init__(self, use_ml=True, use_risk=True, use_nvd=True):
        self.use_ml = use_ml
        self.use_risk = use_risk
        self.use_nvd = use_nvd

        # ML
        if use_ml:
            try:
                from src.ml.analyzer import VulnerabilityAnalyzer
                self.ml_analyzer = VulnerabilityAnalyzer()
            except Exception as e:
                print(f"⚠ ML Analyzer non disponibile: {e}")
                self.ml_analyzer = None
        else:
            self.ml_analyzer = None

        # Risk scorer
        if use_risk:
            try:
                from src.utils.risk_scorer import RiskScorer
                self.risk = RiskScorer()
            except Exception as e:
                print(f"⚠ Risk scorer non disponibile: {e}")
                self.risk = None
        else:
            self.risk = None

        # NVD
        if use_nvd:
            try:
                from src.nvd.nvd_client import NVDClient
                self.nvd = NVDClient()
            except Exception as e:
                print(f"⚠ NVD Client non disponibile: {e}")
                self.nvd = None
        else:
            self.nvd = None


    # ========================================================
    # FUNZIONE CENTRALE: arricchimento NVD FASTMODE
    # ========================================================
    def _fastmode_nvd(self, vulnerabilities):
        """Enrichment NVD con:
        - deduplicazione CVE
        - LIMITE richieste
        - filtro HIGH/CRITICAL
        - cache locale
        - progress bar
        """

        if not self.nvd:
            print("[4/4] NVD: SKIPPED")
            return vulnerabilities

        print("[4/4] FASTMODE NVD Enrichment (SAFE MODE)")

        # Deduplica CVE validi
        unique_cves = []
        for v in vulnerabilities:
            cid = v.get("cve_id", "")
            if cid.startswith("CVE-") and cid not in unique_cves:
                unique_cves.append(cid)

        # Filtra solo HIGH/CRITICAL
        cve_targets = []
        for cve in unique_cves:
            # Trova severity originale
            for v in vulnerabilities:
                if v["cve_id"] == cve and v["severity"] in ALLOWED_SEVERITIES:
                    cve_targets.append(cve)
                    break

        # Applica limite SAFE
        cve_targets = cve_targets[:MAX_NVD_REQUESTS]

        enriched_counter = 0
        total = len(cve_targets)

        for index, cve_id in enumerate(cve_targets, start=1):

            # Mostra progress bar
            print(progress_bar(index, total, prefix=f"   ↳ {cve_id}"), end="\r")

            # 1) CACHE
            if cve_id in CVE_CACHE:
                nvd_data = CVE_CACHE[cve_id]
            else:
                # 2) REQUEST LIVE
                nvd_data = self.nvd.get_cve(cve_id)
                if nvd_data:
                    CVE_CACHE[cve_id] = nvd_data
                    enriched_counter += 1

            if not nvd_data:
                continue

            # 3) Merge dati NVD dentro ogni vulnerabilità
            for v in vulnerabilities:
                if v["cve_id"] == cve_id:
                    v["nvd_data"] = nvd_data
                    if nvd_data.get("cvss_score", 0) > v.get("cvss_score", 0):
                        v["cvss_score"] = nvd_data["cvss_score"]
                        v["severity"] = nvd_data.get("severity", v["severity"])

        print()  # newline
        save_cve_cache(CVE_CACHE)
        print(f"✓ NVD FASTMODE complete — {enriched_counter} enriched")

        return vulnerabilities

# ============================================================
# PARTE 4 — PARSING COMPLETO + ML + RISK SCORING + FASTMODE
# ============================================================

    def parse_and_enhance(self, xml_file):
        """Esegue parsing + ML + Risk + NVD FASTMODE."""

        print(f"[1/4] Parsing XML: {xml_file}")
        vulnerabilities = parse_nmap_xml(xml_file)

        if not vulnerabilities:
            print("⚠ Nessuna vulnerabilità trovata")
            return {
                "vulnerabilities": [],
                "summary": {
                    "total": 0,
                    "by_severity": {},
                    "by_priority": {},
                    "top_risks": [],
                    "nvd_enriched_count": 0
                }
            }

        print(f"[2/4] Found {len(vulnerabilities)} vulnerabilities")

        # =====================================================
        # ML ANALYSIS
        # =====================================================
        if self.ml_analyzer:
            print("[3/4] Applying ML analysis...")
            for v in vulnerabilities:
                try:
                    ml = self.ml_analyzer.analyze(v)
                    v.update(ml)
                except Exception as e:
                    print(f"⚠ ML failed for {v.get('cve_id')}: {e}")
        else:
            print("[3/4] ML: SKIPPED")

        # =====================================================
        # RISK SCORING
        # =====================================================
        if self.risk:
            print("[3.5/4] Calculating risk scores...")
            for v in vulnerabilities:
                try:
                    r = self.risk.calculate_risk_score(v)
                    v["risk_score"] = r
                    v["priority"] = self.risk.get_priority(r)
                except Exception as e:
                    print(f"⚠ Risk scoring failed for {v.get('cve_id')}: {e}")
        else:
            print("[3.5/4] Risk scoring: SKIPPED")

        # =====================================================
        # FASTMODE NVD
        # =====================================================
        vulnerabilities = self._fastmode_nvd(vulnerabilities)

        # =====================================================
        # SUMMARY
        # =====================================================
        summary = {
            "total": len(vulnerabilities),
            "by_severity": {},
            "by_priority": {},
            "top_risks": [],
            "nvd_enriched_count": 0,
        }

        # severity count
        for v in vulnerabilities:
            sev = v.get("severity", "UNKNOWN")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        # priority count
        for v in vulnerabilities:
            p = v.get("priority", 4)
            summary["by_priority"][p] = summary["by_priority"].get(p, 0) + 1

        # top risks
        if self.risk:
            ordered = sorted(vulnerabilities, key=lambda x: x.get("risk_score", 0), reverse=True)
            summary["top_risks"] = [
                {
                    "cve_id": v["cve_id"],
                    "cvss": v.get("cvss_score", 0),
                    "risk_score": v.get("risk_score", 0),
                    "priority": v.get("priority", 4)
                }
                for v in ordered[:5]
            ]

        # count enriched CVE
        summary["nvd_enriched_count"] = len([v for v in vulnerabilities if "nvd_data" in v])

        return {
            "vulnerabilities": vulnerabilities,
            "summary": summary
        }


# ============================================================
# WRAPPER COMPATIBILE CON generate_report.py
# ============================================================

def parse_with_ml(xml_file, use_ml=True, use_risk_scorer=True, use_nvd=True):
    """
    Wrapper FASTMODE compatibile col tuo generate_report.py.
    """
    parser = FASTMODEParser(
        use_ml=use_ml,
        use_risk=True,
        use_nvd=use_nvd
    )
    return parser.parse_and_enhance(xml_file)

# ============================================================
# PARTE 5 — TEST MODE (facoltativo)
# Permette di eseguire il parser direttamente:
#   python3 xml_parser_FASTMODE.py scan.xml
# ============================================================

if __name__ == "__main__":
    import sys
    import json

    print("=" * 70)
    print(" FASTMODE XML PARSER — SAFE MODE ")
    print("=" * 70)

    if len(sys.argv) < 2:
        print("Uso: python3 xml_parser_FASTMODE.py <scan.xml>")
        sys.exit(0)

    xml_file = sys.argv[1]

    if not os.path.exists(xml_file):
        print(f"Errore: file non trovato: {xml_file}")
        sys.exit(1)

    results = parse_with_ml(xml_file, use_ml=True, use_risk_scorer=True, use_nvd=True)

    print("\n--- SUMMARY ---")
    print(json.dumps(results["summary"], indent=2))

    print("\nPrima vulnerabilità:")
    if results["vulnerabilities"]:
        print(json.dumps(results["vulnerabilities"][0], indent=2))

    print("\n✔ FASTMODE completato")
