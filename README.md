# Automated Network Threat Detection and Alert System

## Overview
This project is an automated network threat detection and alert system that monitors network traffic for malicious activity. Using Wireshark/Tshark for packet capture, Python for automation, and VirusTotal for threat intelligence, the system performs regular network scans, extracts IP addresses, checks for threats, and notifies via email when malicious activity is detected.

## Features
- **Automated Network Traffic Capture**: Uses Wireshark/Tshark to periodically capture network packets.
- **Threat Intelligence Integration**: Extracts IP addresses and checks them against VirusTotal's threat database.
- **Logging of Malicious IPs**: Only malicious IPs are logged, making the output clean and focused on actionable items.
- **Email Alert System**: Sends an automated email alert if any malicious IPs are detected.
- **AI-Assisted Development**: Leveraged AI tools to assist in developing and customizing the script for effective implementation.

## Project Structure
```
root
├── capture.pcapng              # Example network capture file
├── ips.txt                    # Extracted IP addresses from network capture
├── malicious_ips.csv          # Logged malicious IP addresses (CSV format)
├── network_threat_detection.py # Main Python script for automated scanning
├── README.md                  # Project overview and documentation (this file)
```

## Installation and Setup
### Prerequisites
- **Python 3.x**
- **Wireshark/Tshark** installed and added to the system PATH
- **Requests** library for Python:
  ```bash
  pip install requests
  ```

### VirusTotal API Key
You will need a VirusTotal API key to run this project. Create an account on [VirusTotal](https://www.virustotal.com/) and obtain an API key.

### Email Setup
For sending email alerts, configure the following in the Python script:
- `EMAIL_ADDRESS`: Your Gmail address.
- `EMAIL_PASSWORD`: Your Gmail app password (requires enabling "App Passwords" under Google account settings).
- `RECIPIENT_EMAIL`: The email address that will receive the alerts.

## Running the Project
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/network-threat-detection.git
   ```
2. **Navigate to the Project Directory**:
   ```bash
   cd network-threat-detection
   ```
3. **Run the Script**:
   ```bash
   python network_threat_detection.py
   ```

The script will start capturing network traffic, extract IPs, and periodically check them against VirusTotal. If any malicious IPs are detected, they will be logged, and an email alert will be sent.

## How AI Assisted This Project
This project was built with the assistance of AI tools like ChatGPT to efficiently generate and refine Python code, integrate various components, and create a workflow suited for real-world threat detection. Leveraging AI enabled rapid prototyping, problem-solving, and learning, leading to the development of a scalable and effective network security monitoring solution.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please create an issue first to discuss what you would like to change.

## Acknowledgements
- **VirusTotal** for providing the API to check IP addresses.
- **Wireshark** for providing tools for network traffic capture.
- **OpenAI** for assisting in the development of this project using ChatGPT.
