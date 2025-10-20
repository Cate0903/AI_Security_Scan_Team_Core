#!/usr/bin/env python3
"""
AI Security Scanner - Command Line Interface

A comprehensive security scanner that detects common vulnerabilities in code.
"""
import argparse
import sys
import os
from pathlib import Path
from security_scanner import SecurityScanner

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    

def print_banner():
    """Print the tool banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║         🔒 AI Security Scanner v1.0                       ║
    ║         Detect vulnerabilities in your code               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    if COLORS_AVAILABLE:
        print(Fore.CYAN + banner + Style.RESET_ALL)
    else:
        print(banner)


def colorize(text: str, color: str) -> str:
    """Add color to text if colorama is available"""
    if not COLORS_AVAILABLE:
        return text
    
    color_map = {
        'red': Fore.RED,
        'yellow': Fore.YELLOW,
        'green': Fore.GREEN,
        'cyan': Fore.CYAN,
        'magenta': Fore.MAGENTA,
    }
    
    return color_map.get(color, '') + text + Style.RESET_ALL


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI Security Scanner - Detect security vulnerabilities in code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project                    # Scan a directory
  %(prog)s /path/to/file.py                    # Scan a single file
  %(prog)s /path/to/project -o report.json     # Save results to JSON
  %(prog)s /path/to/project -f html -o report.html  # Generate HTML report
  %(prog)s /path/to/project --severity HIGH    # Show only HIGH and CRITICAL issues
        """
    )
    
    parser.add_argument(
        'target',
        help='Target file or directory to scan'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path for the report',
        default=None
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['text', 'json', 'html'],
        default='text',
        help='Report format (default: text)'
    )
    
    parser.add_argument(
        '--severity',
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        help='Minimum severity level to report',
        default=None
    )
    
    parser.add_argument(
        '--exclude',
        nargs='+',
        help='Directories to exclude from scanning',
        default=None
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress the banner output'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Print banner
    if not args.no_banner:
        print_banner()
    
    # Validate target path
    target_path = Path(args.target)
    if not target_path.exists():
        print(colorize(f"Error: Target path '{args.target}' does not exist", 'red'))
        sys.exit(1)
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    # Perform scan
    if args.verbose:
        print(colorize(f"Starting scan of: {args.target}", 'cyan'))
    
    if target_path.is_file():
        vulnerabilities = scanner.scan_file(str(target_path))
        scanner.vulnerabilities = vulnerabilities
    else:
        vulnerabilities = scanner.scan_directory(str(target_path), args.exclude)
    
    if args.verbose:
        print(colorize(f"Scan complete. Found {len(vulnerabilities)} potential issues.", 'cyan'))
    
    # Filter by severity if specified
    if args.severity:
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_severity_index = severity_order.index(args.severity)
        
        filtered_vulns = [
            v for v in scanner.vulnerabilities 
            if severity_order.index(v.rule.severity) >= min_severity_index
        ]
        scanner.vulnerabilities = filtered_vulns
        
        if args.verbose:
            print(colorize(f"Filtered to {len(filtered_vulns)} issues with severity >= {args.severity}", 'cyan'))
    
    # Generate report
    report = scanner.generate_report(args.format)
    
    # Output report
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(colorize(f"✓ Report saved to: {args.output}", 'green'))
        except Exception as e:
            print(colorize(f"Error saving report: {str(e)}", 'red'))
            sys.exit(1)
    else:
        # Print to console (only for text format)
        if args.format == 'text':
            print(report)
        else:
            print(colorize(f"Warning: {args.format} format requires -o/--output option", 'yellow'))
            print(report)
    
    # Print summary
    summary = scanner.get_summary()
    
    if args.format == 'text' and not args.output:
        # Summary already included in text report
        pass
    else:
        print("\n" + "=" * 60)
        print(colorize("SUMMARY", 'cyan'))
        print("=" * 60)
        print(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"Files with Issues: {summary['files_with_issues']}")
        print("\nSeverity Breakdown:")
        
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'yellow',
                    'MEDIUM': 'magenta',
                    'LOW': 'green'
                }.get(severity, 'cyan')
                print(f"  {colorize(severity, color)}: {count}")
    
    # Exit with appropriate code
    if summary['total_vulnerabilities'] > 0:
        if summary['severity_breakdown']['CRITICAL'] > 0 or summary['severity_breakdown']['HIGH'] > 0:
            sys.exit(1)  # Exit with error if critical or high severity issues found
        else:
            sys.exit(0)
    else:
        print(colorize("\n✓ No security issues detected!", 'green'))
        sys.exit(0)


if __name__ == '__main__':
    main()
