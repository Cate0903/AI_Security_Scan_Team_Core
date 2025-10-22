'''
XML Parser for Nmap Output
Parses Nmap XML output into structured Python dictionaries
'''

import xml.etree.ElementTree as ET
import os
from typing import Dict, List, Optional

class NmapXMLParser:
    '''Parser for Nmap XML output files'''
    
    def __init__(self, xml_file: str):
        '''
        Initialize parser with XML file
        
        Args:
            xml_file (str): Path to Nmap XML output file
        '''
        self.xml_file = xml_file
        self.tree = None
        self.root = None
        self._parse_file()
    
    def _parse_file(self):
        '''Parse XML file and set tree/root'''
        try:
            self.tree = ET.parse(self.xml_file)
            self.root = self.tree.getroot()
        except ET.ParseError as e:
            raise Exception(f'XML parsing error: {e}')
        except FileNotFoundError:
            raise Exception(f'XML file not found: {self.xml_file}')
    
    def get_scan_info(self) -> Dict:
        '''
        Extract scan metadata
        
        Returns:
            dict: Scan information
        '''
        return {
            'scanner': self.root.get('scanner'),
            'args': self.root.get('args'),
            'start_time': self.root.get('start'),
            'version': self.root.get('version')
        }
    
    def parse_host(self, host_elem) -> Dict:
        '''
        Parse single host element
        
        Args:
            host_elem: XML element for host
        
        Returns:
            dict: Parsed host data
        '''
        host_data = {
            'status': {},
            'addresses': [],
            'hostnames': [],
            'ports': []
        }
        
        # Status
        status = host_elem.find('status')
        if status is not None:
            host_data['status'] = {
                'state': status.get('state'),
                'reason': status.get('reason')
            }
        
        # Addresses
        for addr in host_elem.findall('address'):
            host_data['addresses'].append({
                'addr': addr.get('addr'),
                'addrtype': addr.get('addrtype')
            })
        
        # Hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            for hostname in hostnames.findall('hostname'):
                host_data['hostnames'].append({
                    'name': hostname.get('name'),
                    'type': hostname.get('type')
                })
        
        # Ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = self._parse_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        return host_data
    
    def _parse_port(self, port_elem) -> Optional[Dict]:
        '''
        Parse single port element
        
        Args:
            port_elem: XML element for port
        
        Returns:
            dict: Parsed port data
        '''
        port_data = {
            'portid': port_elem.get('portid'),
            'protocol': port_elem.get('protocol'),
            'state': {},
            'service': {}
        }
        
        # State
        state = port_elem.find('state')
        if state is not None:
            port_data['state'] = {
                'state': state.get('state'),
                'reason': state.get('reason')
            }
        
        # Service
        service = port_elem.find('service')
        if service is not None:
            port_data['service'] = {
                'name': service.get('name'),
                'product': service.get('product'),
                'version': service.get('version')
            }
        
        return port_data
    
    def parse_all_hosts(self) -> List[Dict]:
        '''
        Parse all hosts in scan
        
        Returns:
            list: List of parsed host dictionaries
        '''
        hosts = []
        for host_elem in self.root.findall('host'):
            host_data = self.parse_host(host_elem)
            hosts.append(host_data)
        return hosts
    
    def parse_complete(self) -> Dict:
        '''
        Parse complete scan output
        
        Returns:
            dict: Complete parsed data
        '''
        return {
            'scan_info': self.get_scan_info(),
            'hosts': self.parse_all_hosts()
        }


# Test code
if __name__ == '__main__':
    import sys
    
    # Need XML file to test
    xml_file = 'test_scan.xml'
    
    if not os.path.exists(xml_file):
        print(f'Error: {xml_file} not found!')
        print('Run nmap_wrapper.py first to create XML file.')
        sys.exit(1)
    
    try:
        parser = NmapXMLParser(xml_file)
        
        print('=== Scan Info ===')
        scan_info = parser.get_scan_info()
        for key, value in scan_info.items():
            print(f'{key}: {value}')
        
        print('\\n=== Hosts ===')
        hosts = parser.parse_all_hosts()
        print(f'Found {len(hosts)} host(s)')
        
        for host in hosts:
            ip = host['addresses'][0]['addr'] if host['addresses'] else 'N/A'
            state = host['status'].get('state', 'unknown')
            print(f'\\nHost: {ip} - {state}')
            print(f'  Ports: {len(host["ports"])} found')
            
            for port in host['ports'][:5]:  # Show first 5
                portid = port['portid']
                port_state = port['state'].get('state')
                service = port['service'].get('name', 'unknown')
                print(f'    {portid}/{port["protocol"]}: {port_state} ({service})')
    
    except Exception as e:
        print(f'Error: {e}')
        sys.exit(1)
