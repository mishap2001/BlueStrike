# BlueStrike

BlueStrike is an interactive offensive security lab framework written in Bash.  
It integrates enumeration, MiTM, DoS, brute force, and password spraying workflows with centralized activity logging.

---

## Overview

BlueStrike provides a structured interface for executing controlled attack scenarios within a lab environment.

Core capabilities include:

- Network range validation
- Live host discovery
- Infrastructure identification (DHCP, DNS, Default Gateway)
- Optional anonymity mode
- Interactive attack workflow selection
- Centralized logging of all activity

All execution events are logged to:

```
/var/log/BlueStrike.log
```

---

## Attack Workflows

### Scanning and Enumeration
- Manual or random target selection
- Port discovery
- Service-specific enumeration using Nmap scripts:
  - FTP
  - SSH
  - Telnet
  - HTTP / HTTPS
  - SMB
  - MySQL
  - PostgreSQL
  - RDP
  - VNC

### Man-in-the-Middle (MiTM)
- IP forwarding activation
- ARP spoofing
- Timed packet capture using Tshark
- Automatic `.pcap` file generation

### Denial of Service (DoS)
- Target selection
- Port selection (predefined, random, or custom)
- Packet flooding using hping3

### Brute Force
- Service detection
- Username list input
- Automatic password list generation
- Hydra-based authentication attempts

### Password Spraying
- Target selection
- Username list input
- Single password testing across multiple accounts
- Execution using CrackMapExec

---

## Installation

Clone the repository:

```bash
git clone https://github.com/mishap2001/BlueStrike.git
cd BlueStrike
```

Install required dependencies:

```bash
sudo apt update
sudo apt install nmap hydra hping3 tshark arpspoof crackmapexec geoip-bin figlet crunch curl
```

Make the script executable:

```bash
chmod +x BlueStrike.sh
```

---

## Usage

Run as root:

```bash
sudo bash BlueStrike.sh
```

Execution flow:

1. Root privilege validation  
2. Network range selection and validation  
3. Live host discovery  
4. Infrastructure identification  
5. Optional anonymity activation  
6. Attack workflow selection  
7. Logging of all actions to `/var/log/BlueStrike.log`

---

## Output

Depending on the selected workflow, generated artifacts may include:

- Enumeration results  
- Service scan outputs  
- Password spraying results  
- MiTM packet capture (`MiTM.pcap`)  

All activity is recorded in:

```
/var/log/BlueStrike.log
```

---

## Author

Michael Pritsert  
GitHub: https://github.com/mishap2001  
LinkedIn: https://www.linkedin.com/in/michael-pritsert-8168bb38a  
