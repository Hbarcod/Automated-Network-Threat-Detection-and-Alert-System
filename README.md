## Automated Network Threat Detection and Alert System

### Overview
I developed an automated network threat detection and alert system designed to monitor network traffic for malicious activity. The system utilizes Wireshark/Tshark for packet capture, Python for automation, and VirusTotal for threat intelligence integration. It performs regular network scans, extracts IP addresses, checks them for threats, and notifies via email when malicious activity is detected.

### Key Features
- **Automated Network Traffic Capture**: Implemented periodic network packet capture using Wireshark/Tshark.
- **Threat Intelligence Integration**: Extracted IP addresses and checked them against VirusTotal's threat database to identify malicious activity.
- **Logging of Malicious IPs**: Only malicious IPs are logged, focusing on actionable items to keep the output clean.
- **Email Alert System**: Configured an automated email alert system to notify stakeholders whenever malicious IPs are detected.
- **AI-Assisted Development**: Leveraged AI tools to efficiently develop and customize the Python script, showcasing the ability to utilize cutting-edge technology to improve workflow.

### Technologies and Tools Used
- **Wireshark/Tshark**: Network packet capture and analysis.
- **Python**: Scripting for automation of scanning, IP extraction, and threat analysis.
- **VirusTotal API**: Integrated to verify the reputation of IP addresses and identify threats.
- **Email Notification System**: Configured for proactive incident response when threats are detected.
- **AI Tools**: Utilized AI, such as ChatGPT, to assist in development, enabling efficient prototyping and problem-solving.

### Impact and Skills Demonstrated
- **Network Security Automation**: Created a system that automates network monitoring, demonstrating practical skills in network security and automation.
- **Threat Intelligence**: Integrated external threat intelligence (VirusTotal) to enrich network traffic data, showcasing skills in using third-party APIs for cybersecurity.
- **Incident Response**: Developed an alert mechanism to support proactive threat management, highlighting the ability to design systems for real-time incident detection.
- **AI Utilization**: Used AI to assist with code generation and problem-solving, demonstrating an innovative approach to project development.

### Project Structure
```
root
├── capture.pcapng              # Example network capture file
├── ips.txt                    # Extracted IP addresses from network capture
├── malicious_ips.csv          # Logged malicious IP addresses (CSV format)
├── network_threat_detection.py # Main Python script for automated scanning
├── README.md                  # Project overview and documentation (this file)
```

### License
This project is licensed under the MIT License - see the LICENSE file for details.

### Acknowledgements
- **VirusTotal** for providing the API to check IP addresses.
- **Wireshark** for providing tools for network traffic capture.
- **OpenAI** for assisting in the development of this project using ChatGPT.


