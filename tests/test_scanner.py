"""
Unit tests for the AI Security Scanner
"""
import unittest
import os
import json
import tempfile
import shutil
from pathlib import Path
from security_scanner import SecurityScanner, SecurityRule, Vulnerability


class TestSecurityScanner(unittest.TestCase):
    """Test cases for SecurityScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = SecurityScanner()
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_scanner_initialization(self):
        """Test that scanner initializes with default rules"""
        self.assertIsNotNone(self.scanner.rules)
        self.assertGreater(len(self.scanner.rules), 0)
        self.assertEqual(len(self.scanner.vulnerabilities), 0)
    
    def test_sql_injection_detection(self):
        """Test SQL injection vulnerability detection"""
        # Create a test file with SQL injection
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n')
        
        vulnerabilities = self.scanner.scan_file(test_file)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertEqual(vulnerabilities[0].rule.rule_id, 'SQL001')
    
    def test_hardcoded_credentials_detection(self):
        """Test hardcoded credentials detection"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('password = "mysecretpassword123"\n')
        
        vulnerabilities = self.scanner.scan_file(test_file)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertEqual(vulnerabilities[0].rule.rule_id, 'CRED001')
    
    def test_command_injection_detection(self):
        """Test command injection vulnerability detection"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('os.system("ls " + user_input)\n')
        
        vulnerabilities = self.scanner.scan_file(test_file)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertEqual(vulnerabilities[0].rule.rule_id, 'CMD001')
    
    def test_eval_detection(self):
        """Test eval() function detection"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('result = eval(user_expression)\n')
        
        vulnerabilities = self.scanner.scan_file(test_file)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertEqual(vulnerabilities[0].rule.rule_id, 'EVAL001')
    
    def test_clean_code_no_vulnerabilities(self):
        """Test that clean code produces no vulnerabilities"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('def hello():\n')
            f.write('    print("Hello, World!")\n')
        
        vulnerabilities = self.scanner.scan_file(test_file)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_scan_directory(self):
        """Test scanning a directory with multiple files"""
        # Create test files
        test_file1 = os.path.join(self.test_dir, 'file1.py')
        with open(test_file1, 'w') as f:
            f.write('password = "secret123"\n')
        
        test_file2 = os.path.join(self.test_dir, 'file2.py')
        with open(test_file2, 'w') as f:
            f.write('result = eval(code)\n')
        
        vulnerabilities = self.scanner.scan_directory(self.test_dir)
        
        self.assertEqual(len(vulnerabilities), 2)
    
    def test_get_summary(self):
        """Test summary generation"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('password = "secret123"\n')
            f.write('result = eval(code)\n')
        
        self.scanner.scan_directory(self.test_dir)
        summary = self.scanner.get_summary()
        
        self.assertIn('total_vulnerabilities', summary)
        self.assertIn('severity_breakdown', summary)
        self.assertIn('files_with_issues', summary)
        self.assertEqual(summary['total_vulnerabilities'], 2)
    
    def test_json_report_generation(self):
        """Test JSON report generation"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('password = "secret123"\n')
        
        self.scanner.scan_directory(self.test_dir)
        report = self.scanner.generate_report('json')
        
        # Verify it's valid JSON
        data = json.loads(report)
        self.assertIn('scan_timestamp', data)
        self.assertIn('summary', data)
        self.assertIn('vulnerabilities', data)
    
    def test_text_report_generation(self):
        """Test text report generation"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('password = "secret123"\n')
        
        self.scanner.scan_directory(self.test_dir)
        report = self.scanner.generate_report('text')
        
        self.assertIn('AI SECURITY SCAN REPORT', report)
        self.assertIn('SUMMARY', report)
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        test_file = os.path.join(self.test_dir, 'test.py')
        with open(test_file, 'w') as f:
            f.write('password = "secret123"\n')
        
        self.scanner.scan_directory(self.test_dir)
        report = self.scanner.generate_report('html')
        
        self.assertIn('<!DOCTYPE html>', report)
        self.assertIn('AI Security Scan Report', report)
    
    def test_exclude_directories(self):
        """Test that excluded directories are skipped"""
        # Create a subdirectory that should be excluded
        excluded_dir = os.path.join(self.test_dir, 'node_modules')
        os.makedirs(excluded_dir)
        
        test_file = os.path.join(excluded_dir, 'test.js')
        with open(test_file, 'w') as f:
            f.write('const password = "secret123";\n')
        
        vulnerabilities = self.scanner.scan_directory(self.test_dir)
        
        # Should find no vulnerabilities since node_modules is excluded by default
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_vulnerability_to_dict(self):
        """Test Vulnerability.to_dict() method"""
        rule = SecurityRule(
            rule_id="TEST001",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            pattern=r"test",
            file_types=['.py']
        )
        
        vuln = Vulnerability(
            rule=rule,
            file_path="/test/file.py",
            line_number=10,
            code_snippet="test code"
        )
        
        vuln_dict = vuln.to_dict()
        
        self.assertEqual(vuln_dict['rule_id'], 'TEST001')
        self.assertEqual(vuln_dict['name'], 'Test Rule')
        self.assertEqual(vuln_dict['file'], '/test/file.py')
        self.assertEqual(vuln_dict['line'], 10)


class TestSecurityRule(unittest.TestCase):
    """Test cases for SecurityRule class"""
    
    def test_rule_creation(self):
        """Test creating a security rule"""
        rule = SecurityRule(
            rule_id="TEST001",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            pattern=r"dangerous_function\(",
            file_types=['.py', '.js']
        )
        
        self.assertEqual(rule.rule_id, "TEST001")
        self.assertEqual(rule.name, "Test Rule")
        self.assertEqual(rule.severity, "HIGH")
        self.assertIn('.py', rule.file_types)
    
    def test_rule_pattern_matching(self):
        """Test that rule patterns match correctly"""
        rule = SecurityRule(
            rule_id="TEST001",
            name="Test Rule",
            description="Test description",
            severity="HIGH",
            pattern=r"eval\s*\(",
            file_types=['.py']
        )
        
        # Test matching
        self.assertIsNotNone(rule.pattern.search("result = eval(code)"))
        self.assertIsNotNone(rule.pattern.search("EVAL(data)"))  # Case insensitive
        
        # Test non-matching
        self.assertIsNone(rule.pattern.search("evaluate_function()"))


if __name__ == '__main__':
    unittest.main()
