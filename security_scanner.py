"""
AI Security Scanner - Main module for security scanning functionality
"""
import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class SecurityRule:
    """Represents a security vulnerability detection rule"""
    
    def __init__(self, rule_id: str, name: str, description: str, 
                 severity: str, pattern: str, file_types: List[str],
                 cwe_id: Optional[str] = None):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.file_types = file_types
        self.cwe_id = cwe_id


class Vulnerability:
    """Represents a detected security vulnerability"""
    
    def __init__(self, rule: SecurityRule, file_path: str, 
                 line_number: int, code_snippet: str):
        self.rule = rule
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format"""
        return {
            'rule_id': self.rule.rule_id,
            'name': self.rule.name,
            'description': self.rule.description,
            'severity': self.rule.severity,
            'cwe_id': self.rule.cwe_id,
            'file': self.file_path,
            'line': self.line_number,
            'code': self.code_snippet.strip(),
            'timestamp': self.timestamp.isoformat()
        }


class SecurityScanner:
    """Main security scanner class"""
    
    def __init__(self):
        self.rules = self._load_default_rules()
        self.vulnerabilities: List[Vulnerability] = []
        
    def _load_default_rules(self) -> List[SecurityRule]:
        """Load default security rules"""
        rules = [
            # SQL Injection
            SecurityRule(
                rule_id="SQL001",
                name="SQL Injection",
                description="Potential SQL injection vulnerability detected",
                severity="HIGH",
                pattern=r'(execute|cursor\.execute|db\.query|sql\.exec)\s*\(\s*["\'].*%s.*["\']|'
                        r'(execute|cursor\.execute|db\.query|sql\.exec)\s*\(\s*.*\+\s*.*\)',
                file_types=['.py', '.js', '.java', '.php'],
                cwe_id="CWE-89"
            ),
            # Hardcoded Credentials
            SecurityRule(
                rule_id="CRED001",
                name="Hardcoded Credentials",
                description="Hardcoded password or secret detected",
                severity="CRITICAL",
                pattern=r'(password|passwd|pwd|secret|api_key|apikey|access_token)\s*=\s*["\'][^"\']{3,}["\']',
                file_types=['.py', '.js', '.java', '.php', '.rb', '.go', '.cs'],
                cwe_id="CWE-798"
            ),
            # Command Injection
            SecurityRule(
                rule_id="CMD001",
                name="Command Injection",
                description="Potential command injection vulnerability detected",
                severity="CRITICAL",
                pattern=r'(os\.system|subprocess\.call|subprocess\.run|exec|eval|shell_exec|system)\s*\(\s*.*\+',
                file_types=['.py', '.js', '.java', '.php', '.rb'],
                cwe_id="CWE-78"
            ),
            # Path Traversal
            SecurityRule(
                rule_id="PATH001",
                name="Path Traversal",
                description="Potential path traversal vulnerability detected",
                severity="HIGH",
                pattern=r'(open|file|readFile|readFileSync)\s*\(\s*.*\+.*\)|'
                        r'(open|file|readFile|readFileSync)\s*\(\s*.*%.*\)',
                file_types=['.py', '.js', '.java', '.php'],
                cwe_id="CWE-22"
            ),
            # XSS (Cross-Site Scripting)
            SecurityRule(
                rule_id="XSS001",
                name="Cross-Site Scripting (XSS)",
                description="Potential XSS vulnerability detected",
                severity="HIGH",
                pattern=r'(innerHTML|outerHTML|document\.write)\s*=\s*.*\+|'
                        r'(innerHTML|outerHTML|document\.write)\s*\(\s*.*\+',
                file_types=['.js', '.jsx', '.ts', '.tsx', '.html'],
                cwe_id="CWE-79"
            ),
            # Insecure Deserialization
            SecurityRule(
                rule_id="DESER001",
                name="Insecure Deserialization",
                description="Potential insecure deserialization detected",
                severity="HIGH",
                pattern=r'(pickle\.loads|yaml\.load|unserialize|JSON\.parse)\s*\(',
                file_types=['.py', '.js', '.java', '.php', '.rb'],
                cwe_id="CWE-502"
            ),
            # Use of eval()
            SecurityRule(
                rule_id="EVAL001",
                name="Dangerous Function: eval()",
                description="Use of dangerous eval() function detected",
                severity="HIGH",
                pattern=r'\beval\s*\(',
                file_types=['.py', '.js', '.php', '.rb'],
                cwe_id="CWE-94"
            ),
            # Weak Cryptography
            SecurityRule(
                rule_id="CRYPTO001",
                name="Weak Cryptographic Algorithm",
                description="Use of weak cryptographic algorithm detected",
                severity="MEDIUM",
                pattern=r'(MD5|SHA1|DES|RC4|md5|sha1)\s*\(',
                file_types=['.py', '.js', '.java', '.cs', '.go'],
                cwe_id="CWE-327"
            ),
            # Debug Mode Enabled
            SecurityRule(
                rule_id="DEBUG001",
                name="Debug Mode Enabled",
                description="Debug mode enabled in code",
                severity="LOW",
                pattern=r'(DEBUG|debug)\s*=\s*(True|true|1|"true")',
                file_types=['.py', '.js', '.java', '.cs', '.rb', '.go'],
                cwe_id="CWE-489"
            ),
            # Insufficient SSL/TLS Verification
            SecurityRule(
                rule_id="SSL001",
                name="Insufficient SSL/TLS Verification",
                description="SSL/TLS verification disabled",
                severity="HIGH",
                pattern=r'(verify\s*=\s*False|SSL_VERIFY_NONE|disable.*ssl.*verify)',
                file_types=['.py', '.js', '.java', '.cs', '.go'],
                cwe_id="CWE-295"
            ),
        ]
        return rules
    
    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities"""
        file_ext = Path(file_path).suffix
        vulnerabilities = []
        
        # Skip files that don't match any rule's file types
        applicable_rules = [r for r in self.rules if file_ext in r.file_types]
        if not applicable_rules:
            return vulnerabilities
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, start=1):
                for rule in applicable_rules:
                    if rule.pattern.search(line):
                        vuln = Vulnerability(
                            rule=rule,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line
                        )
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            print(f"Error scanning {file_path}: {str(e)}")
            
        return vulnerabilities
    
    def scan_directory(self, directory: str, exclude_dirs: Optional[List[str]] = None) -> List[Vulnerability]:
        """Scan all files in a directory recursively"""
        if exclude_dirs is None:
            exclude_dirs = ['.git', 'node_modules', 'venv', '__pycache__', '.venv', 
                          'build', 'dist', '.eggs', 'target']
        
        all_vulnerabilities = []
        
        for root, dirs, files in os.walk(directory):
            # Remove excluded directories from search
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                vulnerabilities = self.scan_file(file_path)
                all_vulnerabilities.extend(vulnerabilities)
        
        self.vulnerabilities = all_vulnerabilities
        return all_vulnerabilities
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of scan results"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.rule.severity] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'files_with_issues': len(set(v.file_path for v in self.vulnerabilities))
        }
    
    def generate_report(self, format: str = 'text') -> str:
        """Generate a report in the specified format"""
        if format == 'json':
            return self._generate_json_report()
        elif format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_text_report()
    
    def _generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        return json.dumps(report, indent=2)
    
    def _generate_text_report(self) -> str:
        """Generate plain text report"""
        summary = self.get_summary()
        
        report = []
        report.append("=" * 80)
        report.append("AI SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        report.append("SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Vulnerabilities Found: {summary['total_vulnerabilities']}")
        report.append(f"Files with Issues: {summary['files_with_issues']}")
        report.append("")
        report.append("Severity Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            report.append(f"  {severity}: {count}")
        report.append("")
        
        if self.vulnerabilities:
            report.append("VULNERABILITIES")
            report.append("-" * 80)
            
            # Group by file
            files_dict = {}
            for vuln in self.vulnerabilities:
                if vuln.file_path not in files_dict:
                    files_dict[vuln.file_path] = []
                files_dict[vuln.file_path].append(vuln)
            
            for file_path, vulns in sorted(files_dict.items()):
                report.append(f"\nFile: {file_path}")
                report.append("-" * 80)
                
                for vuln in vulns:
                    report.append(f"  [{vuln.rule.severity}] {vuln.rule.name}")
                    report.append(f"  Rule ID: {vuln.rule.rule_id}")
                    if vuln.rule.cwe_id:
                        report.append(f"  CWE: {vuln.rule.cwe_id}")
                    report.append(f"  Line {vuln.line_number}: {vuln.code_snippet.strip()}")
                    report.append(f"  Description: {vuln.rule.description}")
                    report.append("")
        
        report.append("=" * 80)
        return "\n".join(report)
    
    def _generate_html_report(self) -> str:
        """Generate HTML format report"""
        summary = self.get_summary()
        
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append("  <meta charset='UTF-8'>")
        html.append("  <title>AI Security Scan Report</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }")
        html.append("    .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }")
        html.append("    h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }")
        html.append("    h2 { color: #555; margin-top: 30px; }")
        html.append("    .summary { background-color: #f9f9f9; padding: 15px; border-left: 4px solid #4CAF50; margin: 20px 0; }")
        html.append("    .vulnerability { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }")
        html.append("    .critical { border-left: 5px solid #d32f2f; background-color: #ffebee; }")
        html.append("    .high { border-left: 5px solid #f57c00; background-color: #fff3e0; }")
        html.append("    .medium { border-left: 5px solid #fbc02d; background-color: #fffde7; }")
        html.append("    .low { border-left: 5px solid #388e3c; background-color: #e8f5e9; }")
        html.append("    .severity { font-weight: bold; padding: 5px 10px; border-radius: 3px; display: inline-block; }")
        html.append("    .severity.critical { background-color: #d32f2f; color: white; }")
        html.append("    .severity.high { background-color: #f57c00; color: white; }")
        html.append("    .severity.medium { background-color: #fbc02d; color: black; }")
        html.append("    .severity.low { background-color: #388e3c; color: white; }")
        html.append("    .code { background-color: #263238; color: #aed581; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }")
        html.append("    .file-path { color: #1976d2; font-weight: bold; }")
        html.append("    table { width: 100%; border-collapse: collapse; margin: 20px 0; }")
        html.append("    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    th { background-color: #4CAF50; color: white; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("  <div class='container'>")
        html.append("    <h1>🔒 AI Security Scan Report</h1>")
        html.append(f"    <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        
        html.append("    <div class='summary'>")
        html.append("      <h2>Summary</h2>")
        html.append(f"      <p><strong>Total Vulnerabilities Found:</strong> {summary['total_vulnerabilities']}</p>")
        html.append(f"      <p><strong>Files with Issues:</strong> {summary['files_with_issues']}</p>")
        html.append("      <table>")
        html.append("        <tr><th>Severity</th><th>Count</th></tr>")
        for severity, count in summary['severity_breakdown'].items():
            html.append(f"        <tr><td>{severity}</td><td>{count}</td></tr>")
        html.append("      </table>")
        html.append("    </div>")
        
        if self.vulnerabilities:
            html.append("    <h2>Vulnerabilities</h2>")
            
            # Group by file
            files_dict = {}
            for vuln in self.vulnerabilities:
                if vuln.file_path not in files_dict:
                    files_dict[vuln.file_path] = []
                files_dict[vuln.file_path].append(vuln)
            
            for file_path, vulns in sorted(files_dict.items()):
                html.append(f"    <h3 class='file-path'>📄 {file_path}</h3>")
                
                for vuln in vulns:
                    severity_class = vuln.rule.severity.lower()
                    html.append(f"    <div class='vulnerability {severity_class}'>")
                    html.append(f"      <span class='severity {severity_class}'>{vuln.rule.severity}</span>")
                    html.append(f"      <strong> {vuln.rule.name}</strong>")
                    html.append(f"      <p><strong>Rule ID:</strong> {vuln.rule.rule_id}")
                    if vuln.rule.cwe_id:
                        html.append(f" | <strong>CWE:</strong> {vuln.rule.cwe_id}")
                    html.append("</p>")
                    html.append(f"      <p><strong>Line:</strong> {vuln.line_number}</p>")
                    html.append(f"      <p><strong>Description:</strong> {vuln.rule.description}</p>")
                    html.append(f"      <div class='code'>{vuln.code_snippet.strip()}</div>")
                    html.append("    </div>")
        
        html.append("  </div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
