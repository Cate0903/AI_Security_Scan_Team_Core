# AI Security Scanner

![CI/CD](https://github.com/Cate0903/AI_Security_Scan_Team_Core/workflows/CI%2FCD%20Pipeline/badge.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

AI-powered security scanner using Nmap...


![Coverage](https://img.shields.io/codecov/c/github/Cate0903/AI_Security_Scan_Team_Core)
![Issues](https://img.shields.io/github/issues/Cate0903/AI_Security_Scan_Team_Core)
![Stars](https://img.shields.io/github/stars/Cate0903/AI_Security_Scan_Team_Core)

AI Security Scanner è uno strumento open-source per l’analisi automatizzata delle vulnerabilità in ambienti DevSecOps, pipeline CI/CD e infrastrutture applicative.
Integra analisi basate su machine learning, punteggi di rischio normalizzati, arricchimento NVD e reporting interattivo.

✅ Ideale per penetration tester, analisti SOC, DevOps e ingegneri della sicurezza  
✅ Importa e analizza scansioni Nmap (formato XML)  
✅ Assegna punteggi di rischio ML normalizzati  
✅ Genera dashboard HTML interattive con grafici  

## Funzionalità principali

- Analisi avanzata delle vulnerabilità (Nmap XML)

- Arricchimento opzionale tramite API NVD (CVSS v3/v3.1)

- Normalizzazione del risk_score

- Calcolo automatico della priorità per il triage

- Visualizzazioni grafiche:

    - Distribuzione delle severità

    - Distribuzione delle priorità

    - Istogramma dei punteggi di rischio

    - Top vulnerabilità (deduplicate per CVE)

- Dashboard HTML responsive

- Esportazione completa in JSON per integrazioni di sistema

## Come funziona

**Pipeline di elaborazione:**

1. Le vulnerabilità vengono estratte dal report di scansione

2. (Opzionale) vengono recuperati i dati CVSS dall’NVD

3. Un modello ML leggero genera segnali di rischio

4. I punteggi vengono normalizzati considerando:

     - ML risk score

     - CVSS

     - Severity fallback

     - Priority mapping

5. Viene generata una dashboard HTML interattiva

6. I grafici e i metadati JSON vengono salvati per audit e analisi

## Installazione

```bash
git clone https://github.com/Cate0903/AI_Security_Scan_Team_Core.git

cd ai-security-scanner
pip install -r requirements.txt
```
Richiede Python ≥ 3.10

## Esecuzione rapida

**Generare un report completo da un file Nmap XML:**

```bash
python examples/generate_report.py scan_full.xml --nvd
```

**Aprire la dashboard:**

```bash
xdg-open reports/dashboard_*.html
```

## Esempio di output (CLI)

```bash
[STEP 1/5] Parsing and ML Analysis...
✓ 51 vulnerabilità trovate
✓ CVSS arricchite (NVD)

[STEP 2/5] Security Analysis...

Punteggio superficie d’attacco: 293 (CRITICAL)

Punti d’ingresso: 4

[STEP 3/5] Visualizzazioni...
✓ severity_dist.png
✓ priority_dist.png
✓ risk_dist.png
✓ top_vulns.png

[STEP 4/5] Dashboard generata

[STEP 5/5] Report JSON salvato: scan_full_complete_report.json
```

## Configurazione

**Abilitare/disabilitare controlli:**

```yaml
nvd:
enable: true

analysis:
ml: true
risk_normalization: true
```

## Struttura del progetto

```
ai-security-scanner/
├── examples/
│ └── generate_report.py (entry point del reporting)
├── reports/ (output generati)
├── src/
│ ├── parser/
│ │ └── xml_parser.py (ingestione Nmap XML)
│ ├── security/
│ │ ├── attack_surface.py
│ │ ├── threat_model.py
│ │ └── recommendations.py
│ └── visualization/
│ ├── plotter.py (grafici Matplotlib)
│ └── dashboard.py (rendering HTML)
├── requirements.txt
├── README.md
├── LICENSE
└── ...
```

## Normalizzazione del punteggio di rischio

Il sistema considera il massimo tra:

- Punteggio ML

- Punteggio CVSS

- Mappatura di severità

- Mappatura di priorità

**Formula semplificata:**

```python
risk_normalized = max(
ml_risk_score,
cvss_score,
severity_mapping,
priority_mapping
)
```


**Soglie di priorità:**

| Punteggio di rischio | Priorità | Azione consigliata        |
|----------------------:|:----------:|----------------------------|
| ≥ 9.0                | P1        | Mitigazione immediata     |
| ≥ 7.0                | P2        | Alta priorità             |
| ≥ 4.0                | P3        | Correzione pianificata    |
| < 4.0                | P4        | Monitoraggio              |



## Grafici generati

- Distribuzione delle severità

- Distribuzione delle priorità

- Istogramma dei punteggi di rischio

- Top vulnerabilità (uniche per CVE)

## Dashboard

Interattiva, stampabile e strutturata in:

- Indicatori KPI di alto livello

- Grafici e visualizzazioni

- Suddivisione per priorità/severità

- Top 10 vulnerabilità più critiche

- Raccomandazioni di mitigazione

## Integrazione CI/CD

Esempio di step di pipeline che fallisce in presenza di vulnerabilità P1:

```bash

grep '"priority": 1' scan_full_complete_report.json
| wc -l | awk '$1 > 0 { exit 1 }'
```

## Test

```bash
pytest
```
pytest è uno strumento che esegue automaticamente test di verifica sulle funzioni principali del progetto, per assicurarsi che tutto funzioni correttamente e che eventuali errori vengano rilevati subito.

## Nota importante

Questo strumento non sostituisce l’analisi umana.
Serve ad accelerare il triage, ma il giudizio di un esperto resta indispensabile.

## Piano di sviluppo futuro

- Esportazione nativa in PDF

- Architettura a plugin (controlli OWASP)

- Scansione di immagini container

- Ingestione SBOM

- Rilevamento di segreti con ML

- Analisi storica e trend nel tempo

## Licenza

MIT — libera anche per uso commerciale.

## Team di sviluppo

- Caterina Argentieri
- Giovanni Leogrande
- Doriana Lucia
- Mirko Garofalo
- Matteo Renzulli
- Damiano Tommasino
- Claudio Campione
