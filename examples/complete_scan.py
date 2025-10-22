'''
Complete Scan Pipeline Example
Demonstrates full workflow: Scan → Parse → Convert → Save
'''

import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner.nmap_wrapper import NmapScanner
from src.parser.xml_parser import NmapXMLParser
from src.parser.json_converter import NmapJSONConverter

def main():
    '''Main function - complete scan pipeline'''
    
    print('=' * 60)
    print('AI Security Scanner - Complete Pipeline')
    print('=' * 60)
    
    # Get target from user
    target = input('\\nEnter target (IP or hostname): ').strip()
    
    if not target:
        print('[!] Error: Target required')
        sys.exit(1)
    
    # Sanitize filename
    safe_target = target.replace('.', '_').replace('/', '_')
    
    # File names
    xml_file = f'scan_results/{safe_target}_scan.xml'
    json_file = f'scan_results/{safe_target}_scan.json'
    
    # Ensure scan_results directory exists
    os.makedirs('scan_results', exist_ok=True)
    
    try:
        # Step 1: Scan with Nmap
        print(f'\\n[1/4] Scanning {target}...')
        print(f'      Arguments: -sV -T4 -F')
        
        scanner = NmapScanner()
        result = scanner.scan_to_xml(target, xml_file, '-sV -T4 -F')
        
        if not result['success']:
            print(f'[!] Scan failed: {result.get("error", "Unknown error")}')
            sys.exit(1)
        
        print(f'      ✓ Scan completed')
        print(f'      ✓ XML saved to {xml_file}')
        
        # Step 2: Parse XML
        print(f'\\n[2/4] Parsing XML output...')
        
        parser = NmapXMLParser(xml_file)
        parsed_data = parser.parse_complete()
        
        print(f'      ✓ XML parsed successfully')
        
        # Step 3: Convert to JSON
        print(f'\\n[3/4] Converting to JSON...')
        
        converter = NmapJSONConverter(parsed_data)
        converter.to_json_file(json_file)
        
        print(f'      ✓ JSON saved to {json_file}')
        
        # Step 4: Display Summary
        print(f'\\n[4/4] Generating summary...')
        
        summary = converter.get_summary()
        
        print('\\n' + '=' * 60)
        print('SCAN SUMMARY')
        print('=' * 60)
        print(f'Target:        {target}')
        print(f'Total Hosts:   {summary["total_hosts"]}')
        print(f'Hosts Up:      {summary["hosts_up"]}')
        print(f'Open Ports:    {summary["total_open_ports"]}')
        print(f'Services:      {", ".join(summary["unique_services"])}')
        print('=' * 60)
        
        # Show detailed results
        print('\\n' + '=' * 60)
        print('DETAILED RESULTS')
        print('=' * 60)
        
        for host in parsed_data['hosts']:
            # Host info
            ip = host['addresses'][0]['addr'] if host['addresses'] else 'N/A'
            state = host['status'].get('state', 'unknown')
            
            print(f'\\nHost: {ip}')
            print(f'State: {state}')
            
            if host['hostnames']:
                hostname = host['hostnames'][0]['name']
                print(f'Hostname: {hostname}')
            
            # Ports
            if host['ports']:
                print(f'\\nOpen Ports ({len(host["ports"])}):')
                for port in host['ports']:
                    portid = port['portid']
                    protocol = port['protocol']
                    port_state = port['state'].get('state')
                    service_name = port['service'].get('name', 'unknown')
                    product = port['service'].get('product', '')
                    version = port['service'].get('version', '')
                    
                    service_str = f'{product} {version}'.strip() if product else service_name
                    
                    print(f'  {portid}/{protocol} - {port_state} - {service_str}')
            else:
                print('\\nNo open ports found')
        
        print('\\n' + '=' * 60)
        print('[+] Scan complete!')
        print(f'[+] Results saved to:')
        print(f'    - XML:  {xml_file}')
        print(f'    - JSON: {json_file}')
        print('=' * 60)
        
    except KeyboardInterrupt:
        print('\\n\\n[!] Scan interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'\\n[!] Error: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
