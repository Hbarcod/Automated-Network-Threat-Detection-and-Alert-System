import os
import subprocess
import requests
import csv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import time

# VirusTotal API key
API_KEY = "e5c5d5e777256a91b7c58e22599dd8d4026ba518a40da09e575d87fe5fdb9eac"

# Email configuration
EMAIL_ADDRESS = "millerj1996@gmail.com"  # Replace with your Gmail address
EMAIL_PASSWORD = "ovsn oepo ngni ubaa"  # Replace with your app password (Gmail)
RECIPIENT_EMAIL = "millerj1996@gmail.com"  # Recipient email for alerts

# Function to capture network traffic using Tshark
def capture_traffic(capture_file, interface="5", duration=300):
    tshark_cmd = [
        "tshark", "-i", interface, "-a", f"duration:{duration}", "-w", capture_file
    ]
    subprocess.run(tshark_cmd)

# Function to extract IP addresses from the capture file
def extract_ips(capture_file, ips_file):
    tshark_cmd = [
        "tshark", "-r", capture_file, "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-Y", "ip"
    ]
    with open(ips_file, "w") as file:
        subprocess.run(tshark_cmd, stdout=file)

# Function to check IPs against VirusTotal
def check_ip_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {'apikey': api_key, 'ip': ip}
    response = requests.get(url, params=params)
    return response.json()

# Function to log only malicious IPs to a CSV file
def log_malicious_ip_csv(ip, result, log_file):
    with open(log_file, "a", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        if 'positives' in result and result['positives'] > 0:
            csvwriter.writerow([ip, result['positives'], "Malicious", datetime.now()])

# Function to send email alerts for malicious IPs
def send_email_alert(malicious_ips):
    if not malicious_ips:
        return  # Don't send email if there are no malicious IPs

    subject = "Alert: Malicious IPs Detected!"
    body = "The following IPs were detected as malicious during the latest scan:\n\n"
    body += "\n".join(malicious_ips)

    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            text = msg.as_string()
            server.sendmail(EMAIL_ADDRESS, RECIPIENT_EMAIL, text)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to request user permission
def request_permission():
    response = input("Do you want to start the packet capture? (yes/no): ").strip().lower()
    return response == "yes"

# Main function to automate the process
def automate_scan():
    capture_file = "capture.pcapng"
    ips_file = "ips.txt"
    log_file = "malicious_ips.csv"  # Only save malicious IPs

    # Request user permission before starting the capture
    if request_permission():
        print("Permission granted. Starting packet capture...")
        
        # Capture traffic
        capture_traffic(capture_file)

        # Extract IPs
        extract_ips(capture_file, ips_file)

        # Create CSV file with header if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, "w", newline="") as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["IP Address", "Detections", "Status", "Scan Time"])

        # Read and check each IP
        malicious_ips = []
        with open(ips_file, "r") as file:
            ips = set(line.strip() for line in file if line.strip())
            for ip in ips:
                result = check_ip_virustotal(ip, API_KEY)
                if 'positives' in result and result['positives'] > 0:
                    log_malicious_ip_csv(ip, result, log_file)
                    malicious_ips.append(f"{ip} (Detections: {result['positives']})")

        # Send an email alert if malicious IPs are found
        send_email_alert(malicious_ips)
    else:
        print("Permission denied. Packet capture will not run.")

if __name__ == "__main__":
    while True:
        print(f"Starting scan at {datetime.now()}...")
        automate_scan()
        # Sleep for an hour before the next scan
        time.sleep(3600)
