# 🔒 AI Security Scanner

A comprehensive AI-powered security scanner that detects common security vulnerabilities in your code across multiple programming languages.

## Features

- ✅ **Multi-language Support**: Scans Python, JavaScript, Java, PHP, Ruby, Go, C#, and more
- 🔍 **Comprehensive Detection**: Identifies 10+ types of security vulnerabilities
- 📊 **Multiple Report Formats**: Generate reports in text, JSON, or HTML format
- 🎯 **Severity Levels**: Categorizes issues by CRITICAL, HIGH, MEDIUM, and LOW severity
- 🚀 **Easy to Use**: Simple CLI interface with minimal configuration
- 📝 **Detailed Reports**: Get line-by-line analysis with CWE references

## Detected Vulnerabilities

The scanner detects the following security issues:

| Rule ID | Vulnerability | Severity | CWE |
|---------|--------------|----------|-----|
| SQL001 | SQL Injection | HIGH | CWE-89 |
| CRED001 | Hardcoded Credentials | CRITICAL | CWE-798 |
| CMD001 | Command Injection | CRITICAL | CWE-78 |
| PATH001 | Path Traversal | HIGH | CWE-22 |
| XSS001 | Cross-Site Scripting (XSS) | HIGH | CWE-79 |
| DESER001 | Insecure Deserialization | HIGH | CWE-502 |
| EVAL001 | Dangerous Function: eval() | HIGH | CWE-94 |
| CRYPTO001 | Weak Cryptographic Algorithm | MEDIUM | CWE-327 |
| DEBUG001 | Debug Mode Enabled | LOW | CWE-489 |
| SSL001 | Insufficient SSL/TLS Verification | HIGH | CWE-295 |

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan a directory:
```bash
python ai_security_scan.py /path/to/project
```

Scan a single file:
```bash
python ai_security_scan.py /path/to/file.py
```

### Advanced Usage

Generate a JSON report:
```bash
python ai_security_scan.py /path/to/project -f json -o report.json
```

Generate an HTML report:
```bash
python ai_security_scan.py /path/to/project -f html -o report.html
```

Filter by severity level:
```bash
python ai_security_scan.py /path/to/project --severity HIGH
```

Exclude specific directories:
```bash
python ai_security_scan.py /path/to/project --exclude node_modules venv build
```

Verbose output:
```bash
python ai_security_scan.py /path/to/project -v
```

### Command Line Options

```
usage: ai_security_scan.py [-h] [-o OUTPUT] [-f {text,json,html}]
                           [--severity {LOW,MEDIUM,HIGH,CRITICAL}]
                           [--exclude EXCLUDE [EXCLUDE ...]]
                           [--no-banner] [-v]
                           target

positional arguments:
  target                Target file or directory to scan

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file path for the report
  -f {text,json,html}, --format {text,json,html}
                        Report format (default: text)
  --severity {LOW,MEDIUM,HIGH,CRITICAL}
                        Minimum severity level to report
  --exclude EXCLUDE [EXCLUDE ...]
                        Directories to exclude from scanning
  --no-banner           Suppress the banner output
  -v, --verbose         Verbose output
```

## Examples

### Example 1: Scan a Python Project

```bash
python ai_security_scan.py ./my_project
```

Output:
```
================================================================================
AI SECURITY SCAN REPORT
================================================================================
Scan Date: 2025-10-20 08:30:00

SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Found: 5
Files with Issues: 2

Severity Breakdown:
  CRITICAL: 2
  HIGH: 2
  MEDIUM: 1
  LOW: 0

VULNERABILITIES
--------------------------------------------------------------------------------

File: ./my_project/app.py
--------------------------------------------------------------------------------
  [CRITICAL] Hardcoded Credentials
  Rule ID: CRED001
  CWE: CWE-798
  Line 10: password = "admin123"
  Description: Hardcoded password or secret detected
```

### Example 2: Generate HTML Report

```bash
python ai_security_scan.py ./my_project -f html -o security_report.html
```

This creates a professional HTML report with color-coded severity levels and detailed vulnerability information.

### Example 3: Check Only Critical Issues

```bash
python ai_security_scan.py ./my_project --severity CRITICAL
```

## Testing

Run the test suite:

```bash
python -m pytest tests/test_scanner.py -v
```

Or using unittest:

```bash
python -m unittest tests.test_scanner
```

## Example Vulnerable Code

The `examples/` directory contains sample vulnerable code for testing:

- `examples/vulnerable_code.py` - Python examples
- `examples/vulnerable_code.js` - JavaScript examples

You can test the scanner on these files:

```bash
python ai_security_scan.py examples/vulnerable_code.py
```

## API Usage

You can also use the scanner programmatically in your Python code:

```python
from security_scanner import SecurityScanner

# Initialize scanner
scanner = SecurityScanner()

# Scan a file
vulnerabilities = scanner.scan_file('path/to/file.py')

# Scan a directory
vulnerabilities = scanner.scan_directory('path/to/project')

# Get summary
summary = scanner.get_summary()
print(f"Found {summary['total_vulnerabilities']} issues")

# Generate report
report = scanner.generate_report('json')
print(report)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is designed to help identify potential security vulnerabilities in code. It uses pattern matching and may produce false positives. Always review findings manually and use additional security testing tools for comprehensive security assessment.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

## Roadmap

Future enhancements planned:

- [ ] AI/ML-based vulnerability detection
- [ ] Integration with CI/CD pipelines
- [ ] Custom rule configuration via YAML
- [ ] Support for more programming languages
- [ ] Real-time scanning mode
- [ ] IDE plugins (VS Code, IntelliJ)
- [ ] Automated fix suggestions

---

**Made with ❤️ for secure coding**
