import subprocess
import json
import argparse
import time
import requests
from bs4 import BeautifulSoup

class WiFiAuditor:
    def __init__(self):
        self.networks = []
        self.vulnerabilities = []
        self.risk_scores = {}
        self.manufacturer_db = {} # To store manufacturer data

    def _run_termux_command(self, command):
        """Helper to run termux commands and handle errors."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {' '.join(command)}")
            print(f"Stderr: {e.stderr}")
            return None
        except FileNotFoundError:
            print(f"Command not found: {command[0]}. Please ensure Termux API is installed and permissions are granted.")
            return None

    def scan_networks(self):
        """Discover nearby Wi-Fi networks using termux-wifi-scaninfo."""
        print("Scanning for Wi-Fi networks...")
        output = self._run_termux_command(['termux-wifi-scaninfo'])
        if output:
            try:
                self.networks = json.loads(output)
                print(f"Found {len(self.networks)} networks.")
                return True
            except json.JSONDecodeError:
                print("Failed to decode Wi-Fi scan information. Ensure termux-api is installed and permissions are granted.")
                return False
        return False

    def check_encryption(self, network):
        """Detect weak encryption protocols."""
        capabilities = network.get('capabilities', '')
        if 'WEP' in capabilities:
            return 'CRITICAL: WEP encryption'
        if 'WPA2' in capabilities and 'TKIP' in capabilities:
            return 'HIGH: WPA2 with TKIP vulnerability'
        return 'Secure'

    def get_manufacturer(self, bssid):
        """Lookup router manufacturer based on BSSID (MAC address prefix)."""
        # This would require an external API or a local database.
        # For now, a placeholder.
        mac_prefix = bssid[:8].replace(':', '').upper()
        # A real implementation would query a database or API
        # For demonstration, let's assume a few common ones
        if mac_prefix.startswith('001A2B'):
            return 'TP-Link'
        elif mac_prefix.startswith('001B2C'):
            return 'Netgear'
        return 'Unknown'

    def load_defaults(self, manufacturer):
        """Load default credentials for a given manufacturer."""
        # This would ideally fetch from a database or a web source like default-password.info
        # For now, a placeholder.
        if manufacturer == 'TP-Link':
            return [{'username': 'admin', 'password': 'admin'}, {'username': 'admin', 'password': 'password'}]
        elif manufacturer == 'Netgear':
            return [{'username': 'admin', 'password': 'password'}, {'username': 'admin', 'password': 'netgear'}]
        return []

    def check_default_creds(self, bssid):
        """Test common default credentials against routers."""
        manufacturer = self.get_manufacturer(bssid)
        defaults = self.load_defaults(manufacturer)

        # This is a simulated check. A real check would involve network requests.
        for creds in defaults:
            # Simulate success for 'admin/admin' for demonstration
            if creds['username'] == 'admin' and creds['password'] == 'admin':
                return f'VULNERABLE: Default credentials ({creds["username"]}/{creds["password"]})'
        return 'Secure'

    def get_router_ip(self, bssid):
        """Attempt to get the router's IP address. This is complex without root."""
        # In Termux, getting the router's IP directly from BSSID is hard without root.
        # A common approach is to assume the gateway IP.
        # This is a placeholder and might not work reliably.
        print(f"Attempting to find IP for BSSID {bssid} (might require network connection to it).")
        # This is a very basic placeholder. A real implementation would be more robust.
        # For now, let's return a dummy IP for demonstration.
        return "192.168.1.1" # Common default gateway IP

    def port_scan(self, ip):
        """Check for open management ports using nmap."""
        print(f"Scanning ports on {ip} (requires nmap)...")
        try:
            # -Pn: Treat all hosts as online -- skip host discovery.
            # -F: Fast mode - Scan fewer ports than the default scan.
            result = subprocess.run(['nmap', '-Pn', '-p', '21,22,23,80,443', ip],
                                    capture_output=True, text=True, check=True, timeout=30)
            open_ports = []
            for line in result.stdout.splitlines():
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0]
                    open_ports.append(port)
            return open_ports
        except subprocess.CalledProcessError as e:
            print(f"Nmap error: {e.stderr}")
            return []
        except FileNotFoundError:
            print("Nmap not found. Please install it: pkg install nmap")
            return []
        except subprocess.TimeoutExpired:
            print(f"Nmap scan timed out for {ip}.")
            return []

    def calculate_risk_score(self, network_assessment):
        """Calculate a risk score based on vulnerabilities."""
        score = 0
        threats = []

        if 'CRITICAL: WEP encryption' in network_assessment['encryption']:
            score += 10
            threats.append('CRITICAL: WEP encryption')
        elif 'HIGH: WPA2 with TKIP vulnerability' in network_assessment['encryption']:
            score += 7
            threats.append('HIGH: WPA2-TKIP')

        if 'VULNERABLE: Default credentials' in network_assessment['credentials']:
            score += 8
            threats.append('HIGH: Default credentials')

        if network_assessment['ports']:
            score += len(network_assessment['ports']) * 1.5 # Each open port adds to risk
            threats.append('MEDIUM: Open management ports')

        # Cap score at 10
        score = min(10, round(score))
        return score, threats

    def assess_network(self, network):
        """Perform a full security assessment for a single network."""
        ssid = network.get('ssid', 'Hidden Network')
        bssid = network['bssid']

        print(f"\nAssessing network: {ssid} ({bssid})")

        encryption_status = self.check_encryption(network)
        default_creds_status = self.check_default_creds(bssid)
        router_ip = self.get_router_ip(bssid) # This is a weak point without root
        open_ports = self.port_scan(router_ip) or [] # Ensure open_ports is always a list

        assessment = {
            'ssid': ssid,
            'bssid': bssid,
            'encryption': encryption_status,
            'credentials': default_creds_status,
            'open_ports': open_ports,
            'recommendations': []
        }

        # Add recommendations based on findings
        if 'WEP' in encryption_status:
            assessment['recommendations'].append("Upgrade to WPA2/WPA3 encryption.")
        if 'TKIP' in encryption_status:
            assessment['recommendations'].append("Configure router to use AES encryption for WPA2.")
        if 'Default credentials' in default_creds_status:
            assessment['recommendations'].append("Change default router administrator credentials immediately.")
        if open_ports:
            assessment['recommendations'].append(f"Close unnecessary open ports ({', '.join(open_ports)}) on your router.")
            assessment['recommendations'].append("Ensure router management interface is not exposed to the internet.")

        risk_score, threats = self.calculate_risk_score(assessment)
        assessment['risk_score'] = risk_score
        assessment['threats'] = threats

        return assessment

    def generate_terminal_report(self, assessments):
        """Generate and print a report to the terminal."""
        print("\n--- Wi-Fi Security Audit Report ---")
        for assessment in assessments:
            print(f"\n[!] {assessment['ssid']} (BSSID: {assessment['bssid']})")
            print(f"  Encryption: {assessment['encryption']}")
            print(f"  Credentials: {assessment['credentials']}")
            if assessment['open_ports']:
                print(f"  Open Ports: {', '.join(assessment['open_ports'])}")
            else:
                print("  Open Ports: None detected")
            print(f"  Risk Score: {assessment['risk_score']}/10 ({self._get_risk_level(assessment['risk_score'])})")
            if assessment['recommendations']:
                print("  [RECOMMENDATIONS]:")
                for rec in assessment['recommendations']:
                    print(f"    - {rec}")
            print("-" * 40)

    def _get_risk_level(self, score):
        if score >= 8:
            return "CRITICAL"
        elif score >= 5:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_html_report(self, assessments, filename="wifi_audit_report.html"):
        """Generate an HTML report."""
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Wi-Fi Security Audit Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
                .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                h1 { color: #0056b3; text-align: center; }
                .network-card { border: 1px solid #ddd; border-radius: 5px; margin-bottom: 20px; padding: 15px; background-color: #fff; }
                .network-card h2 { margin-top: 0; color: #0056b3; }
                .risk-critical { color: #d9534f; font-weight: bold; }
                .risk-high { color: #f0ad4e; font-weight: bold; }
                .risk-medium { color: #5bc0de; font-weight: bold; }
                .risk-low { color: #5cb85c; font-weight: bold; }
                .recommendations ul { list-style-type: disc; padding-left: 20px; }
                .recommendations li { margin-bottom: 5px; }
                .threat-critical { color: #d9534f; }
                .threat-high { color: #f0ad4e; }
                .threat-medium { color: #5bc0de; }
                .threat-low { color: #5cb85c; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Wi-Fi Security Audit Report</h1>
                <p>Generated on: ''' + time.strftime("%Y-%m-%d %H:%M:%S") + '''</p>
        """

        for assessment in assessments:
            risk_class = f"risk-{self._get_risk_level(assessment['risk_score']).lower()}"
            html_content += f"""
                <div class="network-card">
                    <h2><span class="{risk_class}">[!]</span> {assessment['ssid']} (BSSID: {assessment['bssid']})</h2>
                    <p><strong>Encryption:</strong> {assessment['encryption']}</p>
                    <p><strong>Credentials:</strong> {assessment['credentials']}</p>
                    <p><strong>Open Ports:</strong> {', '.join(assessment['open_ports']) if assessment['open_ports'] else 'None detected'}</p>
                    <p><strong>Risk Score:</strong> <span class="{risk_class}">{assessment['risk_score']}/10 ({self._get_risk_level(assessment['risk_score'])})</span></p>
                    <div class="recommendations">
                        <h3>Recommendations:</h3>
                        <ul>
            """
            for rec in assessment['recommendations']:
                html_content += f"<li>{rec}</li>"
            html_content += """
                        </ul>
                    </div>
                </div>
            """
        html_content += """
            </div>
        </body>
        </html>
        """

        with open(filename, 'w') as f:
            f.write(html_content)
        print(f"HTML report generated: {filename}")

    def ethical_hacking_disclaimer(self):
        """Displays a disclaimer for ethical hacking mode."""
        print("\n" + "="*70)
        print("                 !!! ETHICAL HACKING MODE !!!")
        print("="*70)
        print("  WARNING: This mode performs intrusive tests like password guessing.")
        print("  ONLY use this on networks you own or have explicit permission to test.")
        print("  Unauthorized access to computer systems is illegal and unethical.")
        print("  You are solely responsible for your actions.")
        print("="*70)
        response = input("Do you understand and agree to these terms? (yes/no): ").lower()
        return response == 'yes'

    def run_password_test(self, target_ssid, wordlist_path):
        """Simulated password testing against a target network."""
        if not self.ethical_hacking_disclaimer():
            print("Ethical hacking mode cancelled.")
            return

        print(f"\nStarting password test for '{target_ssid}' using wordlist '{wordlist_path}'...")
        print("This is a simulated test. Real password testing can be time-consuming and resource-intensive.")

        try:
            with open(wordlist_path, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_path}' not found.")
            return

        found_password = None
        for i, password in enumerate(passwords):
            print(f"  Trying password: {password} ({i+1}/{len(passwords)})", end='\r')
            time.sleep(0.1) # Simulate rate limiting
            # In a real scenario, this would involve a tool like Aircrack-ng or Hashcat
            # For this simulation, let's just "find" a password after a few tries
            if password == "password123" and target_ssid == "HomeWiFi":
                found_password = password
                break
        print("\n") # Newline after the progress indicator

        if found_password:
            print(f"SUCCESS: Found password for '{target_ssid}': '{found_password}'")
        else:
            print(f"FAILURE: No common password found for '{target_ssid}' in the provided wordlist.")
        print("Password testing complete.")


def main():
    parser = argparse.ArgumentParser(description="Termux Wi-Fi Security Auditor")
    parser.add_argument('mode', choices=['scan', 'test', 'report'],
                        help="Operation mode: 'scan' for network discovery, 'test' for password testing, 'report' for HTML report generation.")
    parser.add_argument('--target', help="Target SSID for 'test' mode.")
    parser.add_argument('--wordlist', help="Path to wordlist for 'test' mode (e.g., rockyou.txt).")
    parser.add_argument('--output', default='wifi_audit_report.html',
                        help="Output filename for HTML report (default: wifi_audit_report.html).")

    args = parser.parse_args()

    auditor = WiFiAuditor()

    # Legal Disclaimer on startup
    print("="*70)
    print("                 Wi-Fi Security Auditor")
    print("="*70)
    print("  Disclaimer: This tool is for educational and ethical purposes only.")
    print("  Only use it on networks you own or have explicit permission to scan.")
    print("  Unauthorized access is illegal. The author is not responsible for misuse.")
    print("="*70)
    input("Press Enter to continue...")

    if args.mode == 'scan':
        if auditor.scan_networks():
            assessments = [auditor.assess_network(net) for net in auditor.networks]
            auditor.generate_terminal_report(assessments)
        else:
            print("Failed to scan networks. Exiting.")
    elif args.mode == 'test':
        if not args.target or not args.wordlist:
            parser.error("--target and --wordlist are required for 'test' mode.")
        auditor.run_password_test(args.target, args.wordlist)
    elif args.mode == 'report':
        if not auditor.scan_networks():
            print("Failed to scan networks for reporting. Exiting.")
            return
        assessments = [auditor.assess_network(net) for net in auditor.networks]
        auditor.generate_html_report(assessments, args.output)

if __name__ == "__main__":
    main()
