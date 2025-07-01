# Wi-Fi Security Auditor for Termux

This is a Python-based Wi-Fi security auditing tool designed for Termux, allowing users to assess the security posture of Wi-Fi networks. It includes features for network discovery, vulnerability scanning, and password testing (ethical hacking mode).

## Features

1.  **Network Discovery**: Scans for nearby Wi-Fi networks, collecting SSID, BSSID, encryption type, and signal strength.
2.  **Vulnerability Scanning**:
    *   Detects weak encryption protocols (WEP, WPA2-TKIP).
    *   Checks for common router default credentials.
    *   Identifies open management ports (21, 22, 23, 80, 443).
3.  **Password Testing (Ethical Hacking Mode)**:
    *   Simulates testing common default passwords against routers.
    *   Supports dictionary attacks for WPA2 networks using a custom wordlist (e.g., `rockyou.txt`).
    *   **Requires explicit user confirmation** before execution.
4.  **Security Assessment**:
    *   Generates risk scores (1-10) for each network.
    *   Classifies threats (CRITICAL, HIGH, MEDIUM).
    *   Provides security improvement tips and recommendations.
5.  **Reporting**:
    *   Outputs results in a clear terminal table format.
    *   Generates comprehensive HTML reports with color-coded threats for easy analysis.
6.  **Termux Compatibility**:
    *   Works without root permissions.
    *   Handles permission constraints and uses `termux-wifi-scaninfo` and `nmap`.
7.  **Safety Features**:
    *   Ethical hacking confirmation prompt.
    *   Simulated rate limiting to avoid detection during testing.
    *   Legal disclaimer displayed on startup.
    *   Error handling for no Wi-Fi, permission issues, and scan interruptions.

## Installation

1.  **Install Termux**: Download Termux from F-Droid or Google Play Store.
2.  **Update Termux**:
    ```bash
    pkg update && pkg upgrade
    ```
3.  **Install Required Packages**:
    ```bash
    pkg install python nmap termux-api
    ```
4.  **Clone the Repository**:
    ```bash
    git clone https://github.com/rkstudio585/Wifi-Audit.git
    cd Wifi-Audit
    ```
5.  **Grant Permissions**: Ensure Termux has permission to access Wi-Fi information. You might need to grant this manually in your Android settings for the Termux app.

## Usage

```bash
python wifi_audit.py <mode> [options]
```

### Modes:

*   `scan`: Performs network discovery and vulnerability scanning, displaying results in the terminal.
*   `test`: Initiates password testing against a target network using a specified wordlist. **Requires user confirmation.**
*   `report`: Generates a comprehensive HTML report of the network scan and assessment.

### Options:

*   `--target <SSID>`: (Required for `test` mode) Specifies the SSID of the target network for password testing.
*   `--wordlist <path/to/wordlist.txt>`: (Required for `test` mode) Specifies the path to the wordlist file for dictionary attacks.
*   `--output <filename.html>`: (Optional for `report` mode) Specifies the output filename for the HTML report. Default is `wifi_audit_report.html`.

### Examples:

1.  **Scan and display results in terminal**:
    ```bash
    python wifi_audit.py scan
    ```
2.  **Run password test against "HomeWiFi" using "passwords.txt"**:
    ```bash
    python wifi_audit.py test --target HomeWiFi --wordlist passwords.txt
    ```
3.  **Generate an HTML report**:
    ```bash
    python wifi_audit.py report --output my_wifi_report.html
    ```

## Ethical Use Disclaimer

This tool is provided for **educational and ethical purposes only**. You are solely responsible for your actions.

*   **ONLY** use this tool on networks you own or have explicit, written permission to test.
*   Unauthorized access to computer systems and networks is illegal and unethical.
*   The developers and contributors of this tool are not responsible for any misuse or damage caused by its use.

Always ensure you comply with all applicable laws and regulations in your jurisdiction.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Acknowledgements

*   Termux Project
*   Nmap Security Scanner
