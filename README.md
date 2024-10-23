<h1>Automated Network Threat Detection and Alert System</h1>

<p>
    This project implements an <strong>Automated Network Threat Detection System</strong> that monitors network traffic and checks for malicious IP addresses using data from <strong>VirusTotal</strong>. The system automates periodic network captures and alerts the user if malicious IPs are detected. The system is designed to help network administrators or security enthusiasts monitor for potential threats and respond accordingly.
</p>

<h2>Key Features:</h2>
<ul>
    <li><strong>Automated Packet Capture:</strong>
        <p>
            The system uses <strong>Tshark</strong> (the command-line version of Wireshark) to capture network traffic on a specified interface for a set duration. IP addresses are extracted from the captured packets and checked against the <strong>VirusTotal</strong> database for malicious activity.
        </p>
    </li>
    <li><strong>Malicious IP Detection:</strong>
        <p>
            IP addresses captured are verified against VirusTotal to detect known malicious IPs. If an IP has been flagged by VirusTotal, an alert is sent via email to notify the administrator.
        </p>
    </li>
    <li><strong>Email Alerts:</strong>
        <p>
            If malicious IPs are detected, the system sends an email alert with the details of the threat. This allows for quick responses and potential remediation actions.
        </p>
    </li>
    <li><strong>CSV Logging of Malicious IPs:</strong>
        <p>
            Detected malicious IPs are logged in a CSV file for further analysis and tracking over time.
        </p>
    </li>
    <li><strong>Legal and Privacy Considerations:</strong>
        <p>
            The system has been updated to ensure compliance with privacy laws and regulations. 
            A user consent feature has been added to notify and request permission before any packet capture begins. This ensures that no network monitoring occurs without the user’s explicit approval, mitigating potential privacy violations. This feature helps ensure the program is only used on networks where the user has appropriate authorization, aligning with <em>wiretap laws</em> and <em>privacy regulations</em>.
        </p>
    </li>
</ul>

<h2>Legal and Privacy Considerations:</h2>
<p>
    In recognition of the need for lawful network monitoring, this system prompts the user for permission before capturing any network traffic. This prompt ensures that the user is aware of the operation and has authorized the monitoring in the current environment, especially when using networks not owned by the user. This feature protects against unintended violations of privacy and ensures compliance with <strong>local, state, and federal laws</strong>.
</p>

<h2>Requirements:</h2>
<ul>
    <li>Tshark (Wireshark command-line tool)</li>
    <li>VirusTotal API Key</li>
    <li>Python 3</li>
</ul>



