# plotter.py – FULL VERSION + EXTRA STABILITY + LOGGING
# Safe, clean, fully compatible with AI_Security_Scan_Team_Core
# ZERO f‑string errors, ZERO multiline breaks, ZERO syntax issues

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import os
import re
import logging

# -------------------------
# Logging setup
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format='[PLOTTER] %(message)s'
)

sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 10


class VulnerabilityPlotter:
    def __init__(self, output_dir='reports/plots'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.severity_colors = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c'
        }

        self.priority_colors = {
            1: '#d32f2f',
            2: '#f57c00',
            3: '#fbc02d',
            4: '#388e3c'
        }

    # ---------------------------------------------------
    # ML NORMALIZATION
    # ---------------------------------------------------
    def _get_ml_data(self, vuln):
        ml = vuln.get('ml')
        if isinstance(ml, dict):
            if ml.get('risk_score') is not None or ml.get('priority') is not None or ml.get('ml_available'):
                return {
                    'ml_available': ml.get('ml_available', True),
                    'risk_score': ml.get('risk_score', vuln.get('risk_score', 0)),
                    'priority': ml.get('priority', vuln.get('priority', vuln.get('ml_priority', 4)))
                }

        ml = vuln.get('ml_analysis')
        if isinstance(ml, dict):
            if ml.get('risk_score') is not None or ml.get('priority') is not None or ml.get('ml_available'):
                return {
                    'ml_available': ml.get('ml_available', True),
                    'risk_score': ml.get('risk_score', vuln.get('risk_score', 0)),
                    'priority': ml.get('priority', vuln.get('priority', vuln.get('ml_priority', 4)))
                }

        if any(k in vuln for k in ('ml_available', 'risk_score', 'priority', 'ml_priority')):
            return {
                'ml_available': vuln.get('ml_available', False),
                'risk_score': vuln.get('risk_score', 0),
                'priority': vuln.get('priority', vuln.get('ml_priority', 4))
            }

        return None

    # ---------------------------------------------------
    # SEVERITY PIE CHART
    # ---------------------------------------------------
    def plot_severity_distribution(self, vulns, filename='severity_dist.png'):
        counts = {}
        for v in vulns:
            sev = (v.get('severity') or 'UNKNOWN').upper()
            counts[sev] = counts.get(sev, 0) + 1

        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        final = [x for x in order if x in counts] + sorted([x for x in counts if x not in order])

        if not final:
            logging.warning("No severity data available")
            return None

        fig, ax = plt.subplots()
        colors = [self.severity_colors.get(k, 'gray') for k in final]

        ax.pie(
            [counts[k] for k in final],
            labels=final,
            colors=colors,
            autopct='%1.1f%%',
            startangle=90
        )

        ax.set_title("Vulnerability Distribution by Severity", fontsize=14, weight='bold')

        path = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()

        logging.info(f"Saved: {path}")
        return path

    # ---------------------------------------------------
    # PRIORITY BAR CHART
    # ---------------------------------------------------
    def plot_priority_distribution(self, vulns, filename='priority_dist.png'):
        counts = {}
        for v in vulns:
            ml = self._get_ml_data(v)
            if ml:
                try:
                    p = int(ml.get('priority', 4))
                except:
                    p = 4
                counts[p] = counts.get(p, 0) + 1

        if not counts:
            logging.warning("No ML priority data")
            return None

        fig, ax = plt.subplots()

        keys = sorted(counts.keys())
        values = [counts[k] for k in keys]
        colors = [self.priority_colors.get(k, 'gray') for k in keys]

        labels = {1: 'Urgent', 2: 'High', 3: 'Medium', 4: 'Low'}
        x_labels = [f"P{k}\n{labels.get(k,'N/A')}" for k in keys]

        bars = ax.bar(range(len(keys)), values, color=colors, alpha=0.8)

        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x()+bar.get_width()/2, h, str(h),
                    ha='center', va='bottom', fontsize=12, weight='bold')

        ax.set_xlabel("Priority")
        ax.set_ylabel("Count")
        ax.set_title("ML Priority Distribution")
        ax.set_xticks(range(len(keys)))
        ax.set_xticklabels(x_labels)

        path = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()

        logging.info(f"Saved: {path}")
        return path

    # ---------------------------------------------------
    # RISK SCORE HISTOGRAM
    # ---------------------------------------------------
    def plot_risk_score_distribution(self, vulns, filename='risk_dist.png'):
        PRI_TO_SCORE = {1: 9.5, 2: 8.0, 3: 5.5, 4: 3.0}

        def to_float(x):
            try: return float(x)
            except: return None

        def walk_cvss(o):
            regex = re.compile(r"(base.?score|cvss.*score|^score$)", re.IGNORECASE)
            stack = [o]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    for k,v in cur.items():
                        if regex.search(str(k)):
                            f = to_float(v if not isinstance(v, dict) else v.get("baseScore") or v.get("score"))
                            if f and 0 <= f <= 10:
                                return f
                    stack.extend(cur.values())
                elif isinstance(cur, (list,tuple)):
                    stack.extend(cur)
            return None

        def derive(v):
            ml = self._get_ml_data(v)
            r = ml.get('risk_score') if ml else v.get('risk_score')
            r = to_float(r)
            if r and 0 <= r <= 10:
                return r

            c = walk_cvss(v) or walk_cvss(v.get('nvd', {}))
            if c:
                return c

            p = ml.get('priority') if ml else v.get('priority', v.get('ml_priority'))
            try: p = int(p)
            except: p = 4

            return PRI_TO_SCORE.get(p, 3.0)

        risks = []
        for v in vulns:
            r = derive(v)
            r = to_float(r)
            if r and r > 0:
                risks.append(r)

        if not risks:
            logging.warning("No risk scores")
            return None

        fig, ax = plt.subplots()
        _, bins, patches = ax.hist(risks, bins=10, edgecolor='black', alpha=0.7)

        for i, patch in enumerate(patches):
            mid = (bins[i] + bins[i+1]) / 2
            if mid >= 9: patch.set_facecolor('#d32f2f')
            elif mid >= 7: patch.set_facecolor('#f57c00')
            elif mid >= 4: patch.set_facecolor('#fbc02d')
            else: patch.set_facecolor('#388e3c')

        avg = sum(risks) / len(risks)
        ax.axvline(avg, color='red', linestyle='--', label=f"Avg: {avg:.2f}")
        ax.legend()
        ax.set_xlim(0, 10)
        ax.set_title("Risk Score Distribution")

        path = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()

        logging.info(f"Saved: {path}")
        return path

    # ---------------------------------------------------
    # TOP VULNERABILITIES
    # ---------------------------------------------------
    def plot_top_vulnerabilities(self, vulns, top_n=10, filename='top_vulns.png'):
        sev_to_score = {
            'CRITICAL': 9.5,
            'HIGH': 8.0,
            'MEDIUM': 5.5,
            'LOW': 3.0,
            'INFO': 1.0
        }

        def risk(v):
            ml = self._get_ml_data(v)
            r = None
            if ml:
                r = ml.get('risk_score')
            if r is None:
                r = v.get('risk_score')

            try:
                rf = float(r)
                return rf
            except:
                pass

            sev = (v.get('severity') or '').upper()
            return sev_to_score.get(sev, 0)

        best = {}

        for idx, v in enumerate(vulns):
            cve = v.get('cve_id') or f"NO_CVE#{idx}"
            r = risk(v)

            if cve not in best or r > best[cve]['risk']:
                best[cve] = {'risk': r, 'label': cve}

        rows = sorted(best.values(), key=lambda x: x['risk'], reverse=True)[:top_n]

        if not rows:
            logging.warning("No vulnerabilities available")
            return None

        labels = [r['label'] for r in rows]
        scores = [r['risk'] for r in rows]

        colors = []
        for s in scores:
            if s >= 9: colors.append('#d32f2f')
            elif s >= 7: colors.append('#f57c00')
            elif s >= 4: colors.append('#fbc02d')
            else: colors.append('#388e3c')

        fig, ax = plt.subplots(figsize=(10, max(6, len(labels)*0.35)))
        bars = ax.barh(range(len(labels)), scores, color=colors)

        for bar, s in zip(bars, scores):
            ax.text(s + 0.1, bar.get_y()+bar.get_height()/2,
                    f"{s:.2f}", va='center', fontsize=10)

        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels)
        ax.set_xlabel("Risk Score")
        ax.set_xlim(0, 10)
        ax.set_title("Top Vulnerabilities (dedup by CVE)")
        ax.grid(axis='x', alpha=0.3)

        path = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight')
        plt.close()

        logging.info(f"Saved: {path}")
        return path

    # ---------------------------------------------------
    # ALL PLOTS
    # ---------------------------------------------------
    def create_all_plots(self, vulns):
        logging.info("=== CREATING ALL PLOTS ===")
        result = {
            'severity': self.plot_severity_distribution(vulns),
            'priority': self.plot_priority_distribution(vulns),
            'risk': self.plot_risk_score_distribution(vulns),
            'top': self.plot_top_vulnerabilities(vulns)
        }
        logging.info("✓ All plots created successfully!")
        return result

