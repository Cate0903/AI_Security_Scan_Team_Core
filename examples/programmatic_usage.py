#!/usr/bin/env python3
"""
Example script demonstrating programmatic usage of the AI Security Scanner
"""
import sys
from pathlib import Path

# Add parent directory to path to import security_scanner
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_scanner import SecurityScanner


def main():
    """Example of using the scanner programmatically"""
    
    # Initialize the scanner
    print("Initializing AI Security Scanner...")
    scanner = SecurityScanner()
    
    # Scan the examples directory
    print("\nScanning examples directory...")
    vulnerabilities = scanner.scan_directory('examples/')
    
    # Get summary
    summary = scanner.get_summary()
    
    # Print results
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"Total vulnerabilities found: {summary['total_vulnerabilities']}")
    print(f"Files with issues: {summary['files_with_issues']}")
    
    print("\nSeverity breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    # Show first 3 vulnerabilities as examples
    print("\nFirst 3 vulnerabilities detected:")
    for i, vuln in enumerate(vulnerabilities[:3], 1):
        print(f"\n{i}. [{vuln.rule.severity}] {vuln.rule.name}")
        print(f"   File: {vuln.file_path}")
        print(f"   Line {vuln.line_number}: {vuln.code_snippet.strip()}")
    
    # Generate JSON report
    print("\n" + "=" * 60)
    print("Generating JSON report...")
    json_report = scanner.generate_report('json')
    
    # Save to file
    with open('security_report.json', 'w') as f:
        f.write(json_report)
    print("✓ JSON report saved to: security_report.json")
    
    # Generate HTML report
    print("\nGenerating HTML report...")
    html_report = scanner.generate_report('html')
    
    # Save to file
    with open('security_report.html', 'w') as f:
        f.write(html_report)
    print("✓ HTML report saved to: security_report.html")
    
    print("\n" + "=" * 60)
    print("Scan complete!")


if __name__ == '__main__':
    main()
