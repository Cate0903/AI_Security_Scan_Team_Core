'''
Vulnerability Data Visualization
Crea grafici per analisi vulnerabilità
'''

import matplotlib
matplotlib.use('Agg')  # Backend non-interactive
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import os
from datetime import datetime


# Set style
sns.set_style('whitegrid')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 10


class VulnerabilityPlotter:
    '''Crea visualizzazioni dati vulnerabilità'''
    
    def __init__(self, output_dir='reports/plots'):
        '''Initialize plotter'''
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Color palette
        self.severity_colors = {
            'CRITICAL': '#d32f2f',  # Red
            'HIGH': '#f57c00',      # Orange
            'MEDIUM': '#fbc02d',    # Yellow
            'LOW': '#388e3c'        # Green
        }
        
        self.priority_colors = {
            1: '#d32f2f',  # Urgent - Red
            2: '#f57c00',  # High - Orange
            3: '#fbc02d',  # Medium - Yellow
            4: '#388e3c'   # Low - Green
        }
    
    def plot_severity_distribution(self, vulnerabilities, filename='severity_dist.png'):
        '''
        Grafico a torta distribuzione severity
        
        Args:
            vulnerabilities: lista dict vulnerabilità
            filename: nome file output
        '''
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Sort by severity order
        order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        sorted_counts = {k: severity_counts.get(k, 0) for k in order if k in severity_counts}
        
        # Create pie chart
        fig, ax = plt.subplots()
        
        colors = [self.severity_colors.get(k, '#gray') for k in sorted_counts.keys()]
        
        wedges, texts, autotexts = ax.pie(
            sorted_counts.values(),
            labels=sorted_counts.keys(),
            colors=colors,
            autopct='%1.1f%%',
            startangle=90
        )
        
        # Style
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(12)
            autotext.set_weight('bold')
        
        ax.set_title('Vulnerability Distribution by Severity', fontsize=14, weight='bold')
        
        # Save
        filepath = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f'✓ Salvato: {filepath}')
        return filepath
    def plot_priority_distribution(self, vulnerabilities, filename='priority_dist.png'):
        '''Grafico barre distribuzione priorità ML'''
        # Count by priority
        priority_counts = {}
        for vuln in vulnerabilities:
            ml = vuln.get('ml_analysis', {})
            if ml.get('ml_available'):
                priority = ml.get('priority', 4)
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
        
        if not priority_counts:
            print('⚠ Nessun dato ML priority disponibile')
            return None
        
        # Create bar chart
        fig, ax = plt.subplots()
        
        priorities = sorted(priority_counts.keys())
        counts = [priority_counts[p] for p in priorities]
        colors = [self.priority_colors[p] for p in priorities]
        
        labels = {1: 'Urgent', 2: 'High', 3: 'Medium', 4: 'Low'}
        x_labels = [f'P{p}\\n{labels[p]}' for p in priorities]
        
        bars = ax.bar(range(len(priorities)), counts, color=colors, alpha=0.8)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=12, weight='bold')
        
        ax.set_xlabel('Priority Level', fontsize=12, weight='bold')
        ax.set_ylabel('Number of Vulnerabilities', fontsize=12, weight='bold')
        ax.set_title('ML Priority Distribution', fontsize=14, weight='bold')
        ax.set_xticks(range(len(priorities)))
        ax.set_xticklabels(x_labels)
        
        # Save
        filepath = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f'✓ Salvato: {filepath}')
        return filepath
    
    def plot_risk_score_distribution(self, vulnerabilities, filename='risk_dist.png'):
        '''Istogramma distribuzione risk score'''
        # Extract risk scores
        risk_scores = []
        for vuln in vulnerabilities:
            ml = vuln.get('ml_analysis', {})
            if ml.get('ml_available'):
                risk_scores.append(ml.get('risk_score', 0))
        
        if not risk_scores:
            print('⚠ Nessun risk score disponibile')
            return None
        
        # Create histogram
        fig, ax = plt.subplots()
        
        n, bins, patches = ax.hist(risk_scores, bins=10, edgecolor='black', alpha=0.7)
        
        # Color bars by risk level
        for i, patch in enumerate(patches):
            bin_center = (bins[i] + bins[i+1]) / 2
            if bin_center >= 9:
                patch.set_facecolor('#d32f2f')
            elif bin_center >= 7:
                patch.set_facecolor('#f57c00')
            elif bin_center >= 4:
                patch.set_facecolor('#fbc02d')
            else:
                patch.set_facecolor('#388e3c')
        
        ax.set_xlabel('Risk Score', fontsize=12, weight='bold')
        ax.set_ylabel('Frequency', fontsize=12, weight='bold')
        ax.set_title('Risk Score Distribution', fontsize=14, weight='bold')
        ax.set_xlim(0, 10)
        
        # Add stats
        avg_risk = sum(risk_scores) / len(risk_scores)
        ax.axvline(avg_risk, color='red', linestyle='--', linewidth=2, label=f'Avg: {avg_risk:.2f}')
        ax.legend()
        
        # Save
        filepath = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f'✓ Salvato: {filepath}')
        return filepath
    
    def plot_top_vulnerabilities(self, vulnerabilities, top_n=10, filename='top_vulns.png'):
        '''Grafico barre top N vulnerabilità più rischiose'''
        # Filter and sort by risk score
        ml_vulns = [v for v in vulnerabilities 
                   if v.get('ml_analysis', {}).get('ml_available')]
        
        sorted_vulns = sorted(ml_vulns, 
                            key=lambda x: x['ml_analysis'].get('risk_score', 0),
                            reverse=True)[:top_n]
        
        if not sorted_vulns:
            print('⚠ Nessuna vulnerabilità con ML disponibile')
            return None
        
        # Prepare data
        cve_ids = [v.get('cve_id', 'Unknown')[:15] for v in sorted_vulns]
        risk_scores = [v['ml_analysis']['risk_score'] for v in sorted_vulns]
        
        # Create horizontal bar chart
        fig, ax = plt.subplots(figsize=(10, max(6, len(cve_ids) * 0.4)))
        
        # Color by risk level
        colors = []
        for score in risk_scores:
            if score >= 9:
                colors.append('#d32f2f')
            elif score >= 7:
                colors.append('#f57c00')
            elif score >= 4:
                colors.append('#fbc02d')
            else:
                colors.append('#388e3c')
        
        bars = ax.barh(range(len(cve_ids)), risk_scores, color=colors, alpha=0.8)
        
        # Add value labels
        for i, (bar, score) in enumerate(zip(bars, risk_scores)):
            ax.text(score + 0.1, bar.get_y() + bar.get_height()/2.,
                   f'{score:.2f}',
                   va='center', fontsize=10, weight='bold')
        
        ax.set_yticks(range(len(cve_ids)))
        ax.set_yticklabels(cve_ids)
        ax.set_xlabel('Risk Score', fontsize=12, weight='bold')
        ax.set_title(f'Top {len(sorted_vulns)} Highest Risk Vulnerabilities', 
                    fontsize=14, weight='bold')
        ax.set_xlim(0, 10)
        
        # Grid
        ax.grid(axis='x', alpha=0.3)
        
        # Save
        filepath = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f'✓ Salvato: {filepath}')
        return filepath
    
    def create_all_plots(self, vulnerabilities):
        '''Crea tutti i grafici'''
        print('\\n=== CREAZIONE GRAFICI ===')
        
        plots = {}
        
        # Severity distribution
        print('\\n1. Severity Distribution...')
        plots['severity'] = self.plot_severity_distribution(vulnerabilities)
        
        # Priority distribution
        print('\\n2. Priority Distribution...')
        plots['priority'] = self.plot_priority_distribution(vulnerabilities)
        
        # Risk score distribution
        print('\\n3. Risk Score Distribution...')
        plots['risk'] = self.plot_risk_score_distribution(vulnerabilities)
        
        # Top vulnerabilities
        print('\\n4. Top Vulnerabilities...')
        plots['top'] = self.plot_top_vulnerabilities(vulnerabilities)
        
        print('\\n✓ Tutti i grafici creati!')
        return plots


if __name__ == '__main__':
    # Test con dati mock
    print('='*60)
    print('TEST PLOTTER')
    print('='*60)
    
    # Mock data
    test_vulns = [
        {
            'cve_id': 'CVE-2024-0001',
            'severity': 'CRITICAL',
            'ml_analysis': {'ml_available': True, 'risk_score': 9.5, 'priority': 1}
        },
        {
            'cve_id': 'CVE-2024-0002',
            'severity': 'CRITICAL',
            'ml_analysis': {'ml_available': True, 'risk_score': 9.2, 'priority': 1}
        },
        {
            'cve_id': 'CVE-2024-0003',
            'severity': 'HIGH',
            'ml_analysis': {'ml_available': True, 'risk_score': 7.8, 'priority': 2}
        },
        {
            'cve_id': 'CVE-2024-0004',
            'severity': 'HIGH',
            'ml_analysis': {'ml_available': True, 'risk_score': 7.3, 'priority': 2}
        },
        {
            'cve_id': 'CVE-2024-0005',
            'severity': 'MEDIUM',
            'ml_analysis': {'ml_available': True, 'risk_score': 5.5, 'priority': 3}
        },
        {
            'cve_id': 'CVE-2024-0006',
            'severity': 'MEDIUM',
            'ml_analysis': {'ml_available': True, 'risk_score': 4.8, 'priority': 3}
        },
        {
            'cve_id': 'CVE-2024-0007',
            'severity': 'LOW',
            'ml_analysis': {'ml_available': True, 'risk_score': 3.2, 'priority': 4}
        },
    ]
    
    plotter = VulnerabilityPlotter()
    plots = plotter.create_all_plots(test_vulns)
    
    print('\\n' + '='*60)
    print('Grafici salvati in: reports/plots/')
    print('='*60)
