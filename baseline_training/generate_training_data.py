"""
Script to generate realistic training data for baseline learning.

Generates 1000+ records for each agent type with real-world patterns.
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta

# Real-world data patterns
ROUTER_DESTINATIONS = [
    # Common services
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",  # DNS
    "google.com", "youtube.com", "gmail.com", "drive.google.com",
    "github.com", "stackoverflow.com", "microsoft.com", "office.com",
    "amazon.com", "aws.amazon.com", "facebook.com", "twitter.com",
    "linkedin.com", "reddit.com", "wikipedia.org", "cloudflare.com",
    "akamai.com", "fastly.com", "cdnjs.cloudflare.com",
    # Corporate domains
    "outlook.com", "live.com", "azure.microsoft.com", "portal.azure.com",
    "slack.com", "zoom.us", "teams.microsoft.com", "dropbox.com",
    # Development
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io",
    # News and media
    "cnn.com", "bbc.com", "reuters.com", "techcrunch.com",
]

ROUTER_PROTOCOLS = ["HTTPS", "HTTP", "DNS", "TCP", "UDP", "ICMP"]
ROUTER_PORTS = [80, 443, 53, 22, 25, 587, 993, 995, 3306, 5432, 8080, 8443]

COMPUTER_PROCESSES = [
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    # System
    "explorer.exe", "svchost.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "csrss.exe", "smss.exe", "dwm.exe",
    # Office
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "teams.exe", "onedrive.exe",
    # Development
    "code.exe", "devenv.exe", "pycharm64.exe", "idea64.exe",
    "notepad++.exe", "sublime_text.exe",
    # Communication
    "slack.exe", "zoom.exe", "discord.exe", "telegram.exe",
    # Utilities
    "notepad.exe", "calc.exe", "mspaint.exe", "cmd.exe",
    "powershell.exe", "wsl.exe",
]

COMPUTER_USERS = ["admin", "user", "john.doe", "jane.smith", "SYSTEM", "NETWORK SERVICE"]

COMPUTER_FILE_PATHS = [
    "C:\\Users\\admin\\Documents\\",
    "C:\\Users\\admin\\Downloads\\",
    "C:\\Users\\admin\\Desktop\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\",
]

EMAIL_SENDERS = [
    "noreply@company.com", "support@company.com", "hr@company.com",
    "it@company.com", "security@company.com", "finance@company.com",
    "marketing@company.com", "sales@company.com", "admin@company.com",
    "notifications@company.com", "alerts@company.com",
    # External
    "newsletter@example.com", "updates@example.com",
]

EMAIL_DOMAINS = ["company.com", "example.com", "corp.com", "enterprise.com"]

EMAIL_SUBJECTS = [
    "Weekly Report", "Monthly Newsletter", "System Maintenance Notice",
    "Password Reset Request", "Invoice #", "Meeting Invitation",
    "Project Update", "Security Alert", "Benefits Enrollment",
    "Software Update Available", "New Product Launch", "Training Schedule",
    "Performance Review", "Holiday Schedule", "Policy Update",
]

ATTACHMENT_TYPES = ["pdf", "docx", "xlsx", "pptx", "txt", "zip", "jpg", "png", "csv"]

LINK_DOMAINS = [
    "company.com", "portal.company.com", "docs.company.com",
    "support.company.com", "hr.company.com", "it.company.com",
]


def generate_router_data(count=1000):
    """Generate realistic router/network traffic data."""
    data = []
    
    for i in range(count):
        # Common patterns: 80% HTTPS, 15% HTTP, 5% DNS
        protocol_weights = {"HTTPS": 0.8, "HTTP": 0.15, "DNS": 0.05}
        protocol = random.choices(
            list(protocol_weights.keys()),
            weights=list(protocol_weights.values())
        )[0]
        
        # Destination selection
        if random.random() < 0.3:  # 30% IP addresses
            dest_ip = random.choice([
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "172.217.164.110", "172.217.164.142", "208.67.222.222"
            ])
            dest_domain = None
        else:  # 70% domains
            dest_domain = random.choice(ROUTER_DESTINATIONS)
            dest_ip = None
        
        # Port based on protocol
        if protocol == "HTTPS":
            port = 443
        elif protocol == "HTTP":
            port = 80
        elif protocol == "DNS":
            port = 53
        else:
            port = random.choice(ROUTER_PORTS)
        
        # Data volumes - realistic distributions
        if protocol == "DNS":
            bytes_sent = random.randint(32, 128)
            bytes_received = random.randint(64, 256)
            duration = random.uniform(0.1, 1.0)
        elif protocol == "HTTPS":
            # Most traffic is HTTPS with varying sizes
            if random.random() < 0.7:  # 70% small requests
                bytes_sent = random.randint(512, 10240)
                bytes_received = random.randint(1024, 51200)
            else:  # 30% larger requests (downloads, streaming)
                bytes_sent = random.randint(1024, 5120)
                bytes_received = random.randint(51200, 10485760)  # Up to 10MB
            duration = random.uniform(5.0, 300.0)
        else:  # HTTP
            bytes_sent = random.randint(256, 5120)
            bytes_received = random.randint(512, 102400)
            duration = random.uniform(1.0, 60.0)
        
        record = {
            "protocol": protocol,
            "port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2)
        }
        
        if dest_ip:
            record["dest_ip"] = dest_ip
        if dest_domain:
            record["dest_domain"] = dest_domain
        
        # Add source IP occasionally
        if random.random() < 0.3:
            record["source_ip"] = f"192.168.1.{random.randint(1, 254)}"
        
        data.append(record)
    
    return data


def generate_computer_data(count=1000):
    """Generate realistic computer/system log data."""
    data = []
    
    for i in range(count):
        process = random.choice(COMPUTER_PROCESSES)
        user = random.choice(COMPUTER_USERS)
        
        # Process-specific patterns
        if process in ["chrome.exe", "firefox.exe", "msedge.exe"]:
            file_path = random.choice([
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
                "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            ])
            command_line = f"{process} --start-maximized"
        elif process == "explorer.exe":
            file_path = "C:\\Windows\\explorer.exe"
            command_line = "explorer.exe"
        elif process in ["svchost.exe", "winlogon.exe", "lsass.exe"]:
            file_path = f"C:\\Windows\\System32\\{process}"
            command_line = f"{process} -k netsvcs" if process == "svchost.exe" else process
            user = "SYSTEM"
        elif process in ["winword.exe", "excel.exe", "powerpnt.exe"]:
            file_path = f"C:\\Program Files\\Microsoft Office\\root\\Office16\\{process}"
            doc_name = random.choice(["document", "report", "presentation", "spreadsheet"])
            command_line = f"{process} {doc_name}.docx"
        elif process == "code.exe":
            file_path = "C:\\Users\\admin\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
            command_line = "code.exe --new-window"
        elif process == "powershell.exe":
            file_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            commands = [
                "Get-Process",
                "Get-Service",
                "Get-EventLog -LogName Application",
                "Get-ChildItem",
            ]
            command_line = f"powershell.exe -Command {random.choice(commands)}"
        elif process == "cmd.exe":
            file_path = "C:\\Windows\\System32\\cmd.exe"
            commands = ["dir", "cd", "type", "echo"]
            command_line = f"cmd.exe /c {random.choice(commands)}"
        else:
            file_path = f"C:\\Program Files\\{process}"
            command_line = process
        
        record = {
            "process_name": process,
            "user": user,
            "file_path": file_path,
            "command_line": command_line,
            "pid": random.randint(1000, 65535),
        }
        
        # Add parent PID occasionally
        if random.random() < 0.5:
            record["parent_pid"] = random.randint(100, 999)
        
        # Add event type occasionally
        if random.random() < 0.3:
            event_types = ["process_start", "file_access", "registry_access", "network_connection"]
            record["event_type"] = random.choice(event_types)
        
        data.append(record)
    
    return data


def generate_email_data(count=1000):
    """Generate realistic email data."""
    data = []
    
    for i in range(count):
        # Sender selection
        if random.random() < 0.8:  # 80% internal
            sender = random.choice(EMAIL_SENDERS)
            sender_domain = sender.split("@")[1]
        else:  # 20% external
            sender_domain = random.choice(EMAIL_DOMAINS)
            sender = f"{random.choice(['noreply', 'support', 'info', 'contact'])}@{sender_domain}"
        
        # Subject
        subject_base = random.choice(EMAIL_SUBJECTS)
        if "#" in subject_base:
            subject = f"{subject_base}{random.randint(10000, 99999)}"
        else:
            subject = subject_base
        
        record = {
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": subject,
        }
        
        # Attachment (60% have attachments)
        if random.random() < 0.6:
            att_type = random.choice(ATTACHMENT_TYPES)
            att_name = f"{random.choice(['document', 'report', 'invoice', 'attachment', 'file'])}.{att_type}"
            record["attachment_name"] = att_name
            record["attachment_type"] = att_type
            
            # Size based on type
            if att_type in ["pdf", "docx", "xlsx", "pptx"]:
                record["attachment_size"] = random.randint(100000, 5000000)  # 100KB - 5MB
            elif att_type in ["jpg", "png"]:
                record["attachment_size"] = random.randint(50000, 2000000)  # 50KB - 2MB
            elif att_type == "zip":
                record["attachment_size"] = random.randint(1000000, 10000000)  # 1MB - 10MB
            else:
                record["attachment_size"] = random.randint(1000, 100000)  # 1KB - 100KB
        
        # Links (70% have links)
        if random.random() < 0.7:
            num_links = random.randint(1, 3)
            links = []
            for _ in range(num_links):
                domain = random.choice(LINK_DOMAINS)
                path = random.choice([
                    "/", "/dashboard", "/reports", "/support", "/docs",
                    "/login", "/reset", "/verify", "/download"
                ])
                links.append(f"https://{domain}{path}")
            record["links"] = links
        
        data.append(record)
    
    return data


def main():
    """Generate and save training data files."""
    print("Generating training data...")
    
    # Generate data
    print("  Generating Router data (1000 records)...")
    router_data = generate_router_data(1000)
    
    print("  Generating Computer data (1000 records)...")
    computer_data = generate_computer_data(1000)
    
    print("  Generating Email data (1000 records)...")
    email_data = generate_email_data(1000)
    
    # Save files
    examples_dir = Path(__file__).parent / "examples"
    examples_dir.mkdir(exist_ok=True)
    
    router_file = examples_dir / "router_training_data.json"
    computer_file = examples_dir / "computer_training_data.json"
    email_file = examples_dir / "email_training_data.json"
    
    print(f"\nSaving files...")
    print(f"  {router_file} ({len(router_data)} records)")
    with open(router_file, 'w') as f:
        json.dump(router_data, f, indent=2)
    
    print(f"  {computer_file} ({len(computer_data)} records)")
    with open(computer_file, 'w') as f:
        json.dump(computer_data, f, indent=2)
    
    print(f"  {email_file} ({len(email_data)} records)")
    with open(email_file, 'w') as f:
        json.dump(email_data, f, indent=2)
    
    print("\n✓ Training data generation complete!")
    print(f"  Router: {len(router_data)} records")
    print(f"  Computer: {len(computer_data)} records")
    print(f"  Email: {len(email_data)} records")


if __name__ == "__main__":
    main()




