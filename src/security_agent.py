#!/usr/bin/env python3
"""
Linux Security AI Agent - Your Personal Security Assistant
A persistent, intelligent agent that monitors and protects your Linux system
"""

import os
import sys
import json
import time
import logging
import subprocess
import threading
import sqlite3
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import asyncio
import aiofiles

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/home/cooldad7777/linux-security-agent/logs/agent.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)


class SecurityAgent:
    """Your AI-powered Linux security assistant"""

    def __init__(self):
        self.data_dir = Path.home() / "linux-security-agent" / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.db_path = self.data_dir / "security.db"
        self.initialize_db()
        self.threat_patterns = self.load_threat_patterns()
        self.system_baseline = {}
        self.active_monitors = {}

    def initialize_db(self):
        """Initialize SQLite database for storing security events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT,
                severity TEXT,
                description TEXT,
                details TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_baseline (
                component TEXT PRIMARY KEY,
                baseline_data TEXT,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def load_threat_patterns(self):
        """Load known threat patterns"""
        return {
            "ssh_bruteforce": {
                "pattern": r"Failed password|authentication failure",
                "threshold": 5,
                "window": 300,  # 5 minutes
                "severity": "high",
            },
            "port_scan": {
                "pattern": r"Connection refused|stealth scan",
                "threshold": 20,
                "window": 60,
                "severity": "medium",
            },
            "privilege_escalation": {
                "pattern": r"sudo.*COMMAND|su\[",
                "threshold": 10,
                "window": 600,
                "severity": "critical",
            },
        }

    def natural_language_response(self, event):
        """Convert security events to natural language"""
        responses = {
            "ssh_bruteforce": f"🚨 Someone's trying to break into your system via SSH! I've detected {event['count']} failed login attempts from {event['source']}. I'm blocking them now.",
            "port_scan": f"🔍 Your system is being scanned from {event['source']}. They're looking for open ports. I'll tighten the firewall.",
            "privilege_escalation": f"⚠️ Unusual sudo activity detected. User {event['user']} is trying to run privileged commands frequently.",
            "service_started": f"✅ New service '{event['service']}' started. This is normal if you just installed something.",
            "update_available": f"📦 Security updates available for {event['count']} packages. Want me to install them?",
            "all_clear": "✨ Everything looks good! No security issues detected in the last hour.",
        }

        event_type = event.get("type", "unknown")
        return responses.get(event_type, f"📊 Security event: {event}")

    def check_ssh_security(self):
        """Monitor SSH authentication attempts"""
        try:
            # Check auth log for failed attempts
            result = subprocess.run(
                [
                    "sudo",
                    "journalctl",
                    "-u",
                    "sshd",
                    "--since",
                    "5 minutes ago",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                failed_attempts = defaultdict(int)
                for line in result.stdout.splitlines():
                    if "Failed password" in line or "authentication failure" in line:
                        # Extract IP address
                        import re

                        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                        if ip_match:
                            failed_attempts[ip_match.group(1)] += 1

                # Check for brute force attempts
                for ip, count in failed_attempts.items():
                    if count >= 3:
                        self.handle_threat(
                            {"type": "ssh_bruteforce", "source": ip, "count": count}
                        )

        except Exception as e:
            logger.error(f"Error checking SSH security: {e}")

    def check_open_ports(self):
        """Monitor for suspicious open ports"""
        try:
            result = subprocess.run(
                ["sudo", "ss", "-tulnp"], capture_output=True, text=True
            )

            if result.returncode == 0:
                current_ports = set()
                for line in result.stdout.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 5:
                        port_info = parts[4]
                        if ":" in port_info:
                            port = port_info.split(":")[-1]
                            current_ports.add(port)

                # Store baseline if first run
                if "open_ports" not in self.system_baseline:
                    self.system_baseline["open_ports"] = current_ports
                    self.save_baseline("open_ports", list(current_ports))
                else:
                    # Check for new ports
                    new_ports = current_ports - self.system_baseline["open_ports"]
                    if new_ports:
                        self.log_event(
                            {
                                "type": "new_ports_opened",
                                "ports": list(new_ports),
                                "severity": "medium",
                                "description": f"New ports opened: {', '.join(new_ports)}",
                            }
                        )

        except Exception as e:
            logger.error(f"Error checking open ports: {e}")

    def check_system_updates(self):
        """Check for security updates"""
        try:
            # For Fedora
            result = subprocess.run(
                ["sudo", "dnf", "check-update", "--security"],
                capture_output=True,
                text=True,
            )

            updates = []
            if result.stdout:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    if line and not line.startswith("Last metadata"):
                        updates.append(line.split()[0])

            if updates:
                self.log_event(
                    {
                        "type": "update_available",
                        "count": len(updates),
                        "packages": updates[:5],  # Show first 5
                        "severity": "low",
                    }
                )

        except Exception as e:
            logger.error(f"Error checking updates: {e}")

    def handle_threat(self, threat):
        """Handle detected security threats"""
        logger.warning(f"Threat detected: {threat}")

        # Log the threat
        self.log_event(
            {
                "event_type": threat["type"],
                "severity": "high",
                "description": self.natural_language_response(threat),
                "details": json.dumps(threat),
            }
        )

        # Take action based on threat type
        if threat["type"] == "ssh_bruteforce":
            # Block the IP using firewall
            ip = threat["source"]
            self.block_ip(ip)

    def block_ip(self, ip):
        """Block an IP address using firewall"""
        try:
            # Add firewall rule to block IP
            subprocess.run(
                [
                    "sudo",
                    "firewall-cmd",
                    "--add-rich-rule",
                    f'rule family="ipv4" source address="{ip}" reject',
                ],
                check=True,
            )
            logger.info(f"Blocked IP address: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False

    def log_event(self, event):
        """Log security event to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO security_events 
            (event_type, severity, description, details, action_taken)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                event.get("event_type", event.get("type", "unknown")),
                event.get("severity", "info"),
                event.get("description", str(event)),
                json.dumps(event),
                event.get("action_taken", ""),
            ),
        )

        conn.commit()
        conn.close()

        # Print to console for visibility
        print(f"\n🔒 Security Agent: {self.natural_language_response(event)}\n")

    def save_baseline(self, component, data):
        """Save system baseline data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO system_baseline (component, baseline_data)
            VALUES (?, ?)
        """,
            (component, json.dumps(data)),
        )

        conn.commit()
        conn.close()

    def run_continuous_monitoring(self):
        """Run all security checks continuously"""
        logger.info(
            "🚀 Linux Security AI Agent started - I'm now protecting your system!"
        )

        while True:
            try:
                # Run various security checks
                self.check_ssh_security()
                self.check_open_ports()
                self.check_system_updates()

                # Check every 60 seconds
                time.sleep(60)

            except KeyboardInterrupt:
                logger.info("Security Agent stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)

    def interactive_mode(self):
        """Interactive chat mode for user queries"""
        print(
            "\n💬 Security Agent Chat Mode - Ask me anything about your system security!"
        )
        print("Commands: 'status', 'scan', 'updates', 'help', 'exit'\n")

        while True:
            try:
                user_input = input("You: ").strip().lower()

                if user_input == "exit":
                    break
                elif user_input == "status":
                    self.show_security_status()
                elif user_input == "scan":
                    self.run_security_scan()
                elif user_input == "updates":
                    self.check_system_updates()
                elif user_input == "help":
                    self.show_help()
                else:
                    # Natural language processing would go here
                    print(
                        f"Agent: I understand you want to know about '{user_input}'. Let me check..."
                    )

            except KeyboardInterrupt:
                break

    def show_security_status(self):
        """Show current security status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get recent events
        cursor.execute("""
            SELECT event_type, severity, description, timestamp
            FROM security_events
            WHERE timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            LIMIT 10
        """)

        recent_events = cursor.fetchall()

        if recent_events:
            print("\n📊 Recent Security Events (Last 24 hours):")
            for event in recent_events:
                print(f"  - [{event[1].upper()}] {event[2]} ({event[3]})")
        else:
            print("\n✨ No security events in the last 24 hours - All clear!")

        conn.close()

    def run_security_scan(self):
        """Run a comprehensive security scan"""
        print("\n🔍 Starting comprehensive security scan...")
        self.check_ssh_security()
        self.check_open_ports()
        self.check_system_updates()
        print("✅ Security scan complete!")

    def show_help(self):
        """Show available commands"""
        print("\n📖 Available Commands:")
        print("  status - Show current security status")
        print("  scan   - Run comprehensive security scan")
        print("  updates - Check for system updates")
        print("  help   - Show this help message")
        print("  exit   - Exit interactive mode\n")


if __name__ == "__main__":
    agent = SecurityAgent()

    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--daemon":
            agent.run_continuous_monitoring()
        elif sys.argv[1] == "--chat":
            agent.interactive_mode()
    else:
        # Default: run a single scan
        print("🔍 Running security scan...")
        agent.check_ssh_security()
        agent.check_open_ports()
        agent.check_system_updates()
        agent.show_security_status()
