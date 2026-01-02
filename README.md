# Honeypot Multi-Services with Wazuh SIEM

## Project Overview
This project presents the deployment of a **multi-services honeypot environment**
integrated with **Wazuh SIEM** for intrusion detection, monitoring, and attack analysis.
The infrastructure simulates real-world cyber attacks in a controlled lab environment
to better understand attacker behavior and improve defensive strategies.

The project combines **Cowrie** (SSH/Telnet honeypot) and **Dionaea** (malware and SMB honeypot),
secured and routed through **pfSense**, with centralized monitoring using **Wazuh**.

---

## Objectives
- Simulate real cyber attacks in a safe environment  
- Capture attacker activities and malware samples  
- Monitor and analyze security events using Wazuh SIEM  
- Understand brute-force, scanning, and malware propagation techniques  

---

## Technologies Used
- **Wazuh** – SIEM / XDR platform  
- **Cowrie** – SSH & Telnet Honeypot  
- **Dionaea** – Malware & SMB Honeypot  
- **pfSense** – Firewall & Routing  
- **Docker** – Containerization (Dionaea)  
- **Linux (Kali / Ubuntu)** – Honeypot systems  

---

## Architecture
The architecture is based on a segmented lab network:
- Attack traffic is routed through pfSense  
- Honeypots collect malicious activities  
- Wazuh agents forward logs to the Wazuh Manager  
- Alerts are visualized in the Wazuh Dashboard  


---

## Installation & Configuration
Detailed installation and configuration steps are available in the documentation:

- Wazuh installation (All-in-One)
- Cowrie deployment and configuration
- Dionaea deployment using Docker
- Wazuh agent integration
- Custom Wazuh rules for honeypots

---

## Attacks Detected
- SSH brute-force attacks  
- Telnet login attempts  
- SMB scanning and enumeration  
- Malware drop attempts  
- Service reconnaissance  

All events are collected and correlated by Wazuh SIEM.

---

## Results
- Real-time alerts visible in Wazuh Dashboard  
- Logs showing attacker IPs, credentials, and commands  
- Detection of suspicious SMB activity and malware behavior  
- Improved visibility of attack patterns  

---

## Security Notice
This project is intended for educational and research purposes only.
Honeypots must never be deployed in production environments without proper isolation.

All sensitive data (IP addresses, credentials, keys) have been removed or anonymized.

---

## Author
Bensair Asmaa  
Cybersecurity & Networking Student  

---

## Tags
`honeypot` `wazuh` `siem` `cybersecurity` `blue-team` `soc` `docker`
