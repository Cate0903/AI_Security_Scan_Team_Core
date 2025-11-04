'''
HTML Dashboard Generator
Crea dashboard interattivo vulnerabilità
'''

import os
from datetime import datetime


class DashboardGenerator:
    '''Genera dashboard HTML per scan results'''
    
    def __init__(self, output_dir='reports'):
        '''Initialize generator'''
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_dashboard(self, scan_results, plots_dir='reports/plots'):
        '''
        Genera dashboard HTML completo
        '''
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary = scan_results.get('summary', {})
        
        # Path RELATIVO dei plot rispetto alla cartella output
        rel_plots_dir = os.path.relpath(plots_dir, start=self.output_dir).replace(os.sep, '/')
        
        # Generate HTML
        html = self._generate_html_template(vulnerabilities, summary, rel_plots_dir)
        
        # Save
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'dashboard_{timestamp}.html'
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f'✓ Dashboard salvato: {filepath}')
        return filepath
    
    # -------------------- helpers logici (no stile) --------------------

    @staticmethod
    def _safe_float(x, default=0.0):
        try:
            return float(x)
        except Exception:
            return default

    @staticmethod
    def _safe_int(x, default=0):
        try:
            return int(x)
        except Exception:
            return default

    @staticmethod
    def _priority_from_risk(r):
        if r >= 9.0:  return 1
        if r >= 7.0:  return 2
        if r >= 4.0:  return 3
        return 4

    def _normalized_risk(self, v):
        """
        Usa SEMPRE i campi normalizzati se presenti:
        - risk_score (top-level) -> principale
        - fallback: ml/ml_analysis.risk_score
        - fallback ulteriore: cvss_score (se proprio serve)
        """
        if isinstance(v.get('risk_score'), (int, float)):
            return float(v['risk_score'])
        ml = v.get('ml') or v.get('ml_analysis') or {}
        if isinstance(ml.get('risk_score'), (int, float)):
            return float(ml['risk_score'])
        return self._safe_float(v.get('cvss_score'), 0.0)

    def _normalized_priority(self, v):
        """
        Usa SEMPRE priority normalizzata se c'è; altrimenti derivala dal risk.
        """
        p = v.get('priority')
        if p is not None:
            return self._safe_int(p, 4)
        ml = v.get('ml') or v.get('ml_analysis') or {}
        if ml.get('priority') is not None:
            return self._safe_int(ml.get('priority'), 4)
        return self._priority_from_risk(self._normalized_risk(v))

    def _dedup_top(self, vulnerabilities, top_n=10):
        """
        Deduplica per (cve_id, ip_address, port) tenendo la riga con risk_score più alto.
        """
        best = {}
        for v in vulnerabilities:
            key = (v.get('cve_id') or 'N/A', v.get('ip_address'), v.get('port'))
            r = self._normalized_risk(v)
            cur = best.get(key)
            if cur is None or r > self._normalized_risk(cur):
                best[key] = v
        top = list(best.values())
        top.sort(key=lambda x: (-self._normalized_risk(x), self._normalized_priority(x)))
        return top[:top_n]

    # -------------------- template HTML (stile invariato) --------------------

    def _generate_html_template(self, vulnerabilities, summary, plots_dir):
        '''Generate complete HTML (stile invariato)'''
        
        # ----- Stats di riepilogo -----
        total = summary.get('total', len(vulnerabilities))
        by_severity = summary.get('by_severity', {})
        by_priority = summary.get('by_priority', {})
        critical_count = by_severity.get('CRITICAL', 0)
        urgent_count = by_priority.get(1, by_priority.get('1', 0))

        # Average risk: preferisci summary.average_risk, altrimenti calcola dai risk_score normalizzati
        if isinstance(summary.get('average_risk'), (int, float)):
            avg_risk = float(summary['average_risk'])
        else:
            risks_all = [self._normalized_risk(v) for v in vulnerabilities] if vulnerabilities else []
            avg_risk = (sum(risks_all) / len(risks_all)) if risks_all else 0.0
        
        # ----- HTML head & layout (INVARIATO) -----
        html = f'''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Inter:wght@400;600&display=swap');

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
    	body {{
               font-family: 'Inter', sans-serif;
 	       background:
   	       radial-gradient(circle at 30% 40%, rgba(0,255,255,0.30), transparent 55%),
    	       radial-gradient(circle at 70% 60%, rgba(0,255,255,0.3), transparent 55%),
   	       #050510;
  	       color: #e0e0e0;
   	       padding: 2rem;
  	       min-height: 100vh;
        }}

        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            padding: 2rem;
            margin-bottom: 2rem;
        }}

        
        h1 {{
            font-family: 'Orbitron', sans-serif;
            font-size: 2.6rem;
            color: #00FFFF;
            text-shadow: 0 0 10px #00FFFF, 0 0 25px #00FFFF55;
            animation: pulse 3s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ text-shadow: 0 0 10px #00FFFF, 0 0 25px #00FFFF55; }}
            50% {{ text-shadow: 0 0 20px #00FFFF, 0 0 40px #00FFFFaa; }}
        }}

        
        .subtitle {{ color: #00FFFF;
	 	     margin-top: 1.9rem;
	 }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: rgba(25, 25, 40, 0.6);
            border-radius: 15px;
            padding: 1.5rem;
            transition: all 0.3s ease;
	    backdrop-filter: blur(10px);
	    border: 2px solid rgba(0, 255, 255, 0.25);
	    box-shadow: 0 0 10px rgba(0, 255, 255, 0.2);
        }}

        
        .stat-value {{
	    font-family: 'Orbitron', sans-serif;
            font-size: 2.6rem;
            font-weight: bold;
            margin: 0.5rem 0;
	    color: #00FFFF;
        }}

	.stat-card:hover {{
            box-shadow: 0 0 25px rgba(0, 255, 255, 0.4);
            transform: translateY(-3px);
        }}

        
        .stat-label {{ color: #00FFFF;
	               font-family: 'Orbitron', sans-serif;
		       text-transform: uppercase;
		       font-size: 0.85rem;
	               letter-spacing: 1px;
		       font-weight: bold;
	}}
          .critical {{
 			 color: #ff4d4d;
			 text-shadow: 0 0 10px #ff4d4d55;
	}}

	  .high {{
			color: #ffb300;
			text-shadow: 0 0 10px #ffb30055;
	}}

	  .medium {{
			color: #00ffff;
			text-shadow: 0 0 10px #00e5ff55;
	}}

	  .low {{
			color: #6eff9f;
			text-shadow: 0 0 10px #6eff9f55;
	}}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
	 }}
        
        .chart-card {{
            background: rgba(25, 25, 40, 0.6);
            border: 2px solid rgba(0, 255, 255, 0.25);
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.2);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }}

        
        .chart-card h2 {{
            color: #00FFFF;
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 1rem;
        }}

        
        .chart-card img {{
            width: 100%;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.2);
        }}
        
        .vulnerability-list {{
            background: rgba(20, 20, 35, 0.7);
            border-radius: 15px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.1);
        }}

	.vulnerability-list h2 {{
	    color: #00FFFF;
	    font-family: 'Orbitron', sans-serif;
	    margin-bottom: 1rem;
	}}

        .vulnerability-item {{
            background: rgba(35, 35, 55, 0.6);
            margin-bottom: 1rem;
            border-left: 4px solid #00FFFF55;
            padding: 1rem;
            border-radius: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .vulnerability-item:hover {{
            transform: translateY(-3px);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
        }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
        .vuln-cve {{ font-weight: bold; color: #00FFFF; font-family: 'Orbitron', sans-serif; }}
        .vuln-score {{
            background: linear-gradient(90deg, #00e5ff, #00bfa5);
            color: #0a0a0f;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: bold;
        }}
        .recommendation {{ margin-top: 0.6rem;
	    		   font-size: 0.9rem;
			   color: #00ffff;
	 }}

        footer {{ text-align: center;
		  color: #555;
		  font-size: 0.9rem;
		  margin-top: 2rem;
		  padding: 1rem;
	 }}

        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ AI Vulnerability Scanner</h1>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value">{total}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Critical Issues</div>
                <div class="stat-value critical">{critical_count}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Urgent Actions</div>
                <div class="stat-value high">{by_priority.get(1, by_priority.get('1', 0))}</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">Average Risk Score</div>
                <div class="stat-value medium">{avg_risk:.2f}</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-card">
                <h2> Severity Distribution</h2>
                <img src="{plots_dir}/severity_dist.png" alt="Severity Distribution">
            </div>
            
            <div class="chart-card">
                <h2> Priority Distribution</h2>
                <img src="{plots_dir}/priority_dist.png" alt="Priority Distribution">
            </div>
            
            <div class="chart-card">
                <h2> Risk Score Distribution</h2>
                <img src="{plots_dir}/risk_dist.png" alt="Risk Distribution">
            </div>
            
            <div class="chart-card">
                <h2> Top Vulnerabilities</h2>
                <img src="{plots_dir}/top_vulns.png" alt="Top Vulnerabilities">
            </div>
        </div>
        
        <div class="vulnerability-list">
            <h2> Top 10 Highest Risk Vulnerabilities</h2>
'''
        # ----- Top 10: dedup per (CVE, IP, Port) e sort su risk/priority (logica invariata nel rendering) -----
        def _rec_from(priority):
            if priority == 1:
                return '🔴 Azione immediata: isolare, patchare, mitigare entro 24h.'
            if priority == 2:
                return '🟠 Mitigazione entro 7 giorni: applicare patch e controlli.'
            if priority == 3:
                return '🟡 Pianificare fix: inserire in sprint/maintenance.'
            return '🟢 Monitorare e documentare: rischio basso.'

        top_10 = self._dedup_top(vulnerabilities, top_n=10)

        if not top_10:
            html += '''
            <div class="vulnerability-item">
                Nessuna vulnerabilità con punteggio disponibile. 
                Assicurati di aver importato correttamente i risultati o abilitato l’analisi ML.
            </div>
            '''
        else:
            for vuln in top_10:
                rk = self._normalized_risk(vuln)
                pr = self._normalized_priority(vuln)
                rec = (vuln.get('ml') or vuln.get('ml_analysis') or {}).get('recommendation') or _rec_from(pr)

                cve_id = vuln.get('cve_id', 'Unknown')
                severity = (vuln.get('severity', 'UNKNOWN') or 'UNKNOWN').lower()
                cvss = vuln.get('cvss_score', '')

                html += f'''
                <div class="vulnerability-item {severity}">
                    <div class="vuln-header">
                        <span class="vuln-cve">{cve_id}</span>
                        <span class="vuln-score">Risk: {rk:.2f}/10</span>
                    </div>
                    <div>
                        <strong>CVSS:</strong> {cvss} | 
                        <strong>Severity:</strong> {severity.upper()} | 
                        <strong>Priority:</strong> {pr}
                    </div>
                    <div class="recommendation">
                         {rec}
                    </div>
                </div>
                '''
        
        # ----- Footer & chiusura -----
        html += '''
        </div>
        
        <footer>
            <p>Generated by AI Security Scanner | Machine Learning Enhanced | NVD Integrated | Created by Team Core</p>
        </footer>
    </div>
</body>
</html>
'''
        return html
