#!/usr/bin/env python3
'''
Complete Report Generator
Scan → Analysis → Visualization → Dashboard
'''

import sys
import os
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.xml_parser import parse_with_ml
from src.visualization.plotter import VulnerabilityPlotter
from src.visualization.dashboard import DashboardGenerator


def generate_complete_report(xml_file, use_nvd=False):
    '''Generate complete security report'''
    
    print("="*70)
    print("COMPLETE SECURITY REPORT GENERATOR")
    print("="*70)
    
    # Step 1: Parse and analyze
    print("\n[STEP 1/4] Parsing and ML Analysis...")
    results = parse_with_ml(xml_file, use_ml=True, use_nvd=use_nvd)
    
    vulnerabilities = results['vulnerabilities']
    
    if not vulnerabilities:
        print("⚠ No vulnerabilities found")
        return
    
    print(f"✓ Found {len(vulnerabilities)} vulnerabilities")
    
    # Step 2: Generate plots
    print("\n[STEP 2/4] Generating Visualizations...")
    plotter = VulnerabilityPlotter()
    plots = plotter.create_all_plots(vulnerabilities)
    print("✓ All plots created")
    
    # Step 3: Generate dashboard
    print("\n[STEP 3/4] Creating Dashboard...")
    dashboard_gen = DashboardGenerator()
    dashboard_path = dashboard_gen.generate_dashboard(results)
    print(f"✓ Dashboard: {dashboard_path}")
    
    # Step 4: Save JSON report
    print("\n[STEP 4/4] Saving JSON Report...")
    report_path = xml_file.replace('.xml', '_complete_report.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"✓ JSON Report: {report_path}")
    
    # Summary
    print("\n" + "="*70)
    print("REPORT GENERATION COMPLETE!")
    print("="*70)
    
    summary = results['summary']
    print(f"\n📊 Summary:")
    print(f"  Total Vulnerabilities: {summary['total']}")
    print(f"  Critical: {summary['by_severity'].get('CRITICAL', 0)}")
    print(f"  High: {summary['by_severity'].get('HIGH', 0)}")
    print(f"  Medium: {summary['by_severity'].get('MEDIUM', 0)}")
    print(f"  Low: {summary['by_severity'].get('LOW', 0)}")
    
    if summary.get('by_priority'):
        print(f"\n🎯 By Priority:")
        for priority in sorted(summary['by_priority'].keys()):
            count = summary['by_priority'][priority]
            labels = {1: 'URGENT', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}
            print(f"  Priority {priority} ({labels[priority]:7s}): {count}")
    
    print(f"\n📁 Generated Files:")
    print(f"  📊 Plots: reports/plots/")
    print(f"  🖥️  Dashboard: {dashboard_path}")
    print(f"  📄 JSON: {report_path}")
    
    print("\n💡 Next Steps:")
    print(f"  1. Open dashboard: xdg-open {dashboard_path}")
    print(f"  2. Review JSON: cat {report_path} | python3 -m json.tool | less")
    print(f"  3. Share with team!")
    
    print("\n" + "="*70)
    
    return {
        'dashboard': dashboard_path,
        'json': report_path,
        'plots': plots
    }


def main():
    if len(sys.argv) < 2:
        print("\nUsage: python3 generate_report.py <nmap_xml_file> [--nvd]")
        print("\nExample:")
        print("  python3 generate_report.py scan.xml")
        print("  python3 generate_report.py scan.xml --nvd")
        return
    
    xml_file = sys.argv[1]
    use_nvd = '--nvd' in sys.argv
    
    if not os.path.exists(xml_file):
        print(f"✗ File not found: {xml_file}")
        return
    
    generate_complete_report(xml_file, use_nvd)


if __name__ == '__main__':
    main()
