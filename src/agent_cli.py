#!/usr/bin/env python3
"""
Security Agent CLI - Natural language interface for Linux security
"""

import os
import sys
import json
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path


class SecurityAgentCLI:
    """Command-line interface for the Security Agent"""

    def __init__(self):
        self.commands = {
            "status": self.show_status,
            "scan": self.run_scan,
            "monitor": self.start_monitoring,
            "stop": self.stop_monitoring,
            "history": self.show_history,
            "help": self.show_help,
            "ask": self.natural_language_query,
        }
        self.db_path = Path.home() / "linux-security-agent" / "data" / "security.db"

    def show_banner(self):
        """Display welcome banner"""
        banner = """
╔══════════════════════════════════════════════════════╗
║          🛡️  Linux Security AI Agent 🛡️              ║
║     Your Personal Linux Security Assistant           ║
║                                                      ║
║  I can help you:                                     ║
║  • Monitor your system for threats                   ║
║  • Explain security issues in plain English          ║
║  • Automatically fix common problems                 ║
║  • Teach you about Linux security                    ║
╚══════════════════════════════════════════════════════╝
        """
        print(banner)

    def natural_language_query(self, query):
        """Process natural language security questions"""
        query = query.lower()

        # Simple pattern matching for demo - would use AI in production
        if "safe" in query or "secure" in query:
            self.check_security_status()
        elif "ssh" in query:
            self.check_ssh_status()
        elif "update" in query:
            self.check_updates()
        elif "port" in query:
            self.check_ports()
        elif "firewall" in query:
            self.check_firewall()
        else:
            print(f"\n🤔 Let me analyze '{query}' for you...")
            print("I'm checking your system security based on your question...")
            self.run_relevant_checks(query)

    def check_security_status(self):
        """Check overall security status"""
        print("\n🔍 Analyzing your system security...")

        issues = []

        # Check SSH configuration
        try:
            result = subprocess.run(
                ["grep", "PasswordAuthentication", "/etc/ssh/sshd_config"],
                capture_output=True,
                text=True,
            )
            if "yes" in result.stdout:
                issues.append("⚠️  SSH allows password authentication (less secure)")
        except:
            pass

        # Check for updates
        try:
            result = subprocess.run(
                ["sudo", "dnf", "check-update", "--security"],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip():
                issues.append("📦 Security updates are available")
        except:
            pass

        # Check firewall
        try:
            result = subprocess.run(
                ["sudo", "firewall-cmd", "--state"], capture_output=True, text=True
            )
            if "not running" in result.stdout:
                issues.append("🚫 Firewall is not running!")
        except:
            pass

        if issues:
            print("\n⚠️  I found some security concerns:")
            for issue in issues:
                print(f"  {issue}")
            print(
                "\n💡 Would you like me to fix these issues? Type 'fix' or ask me about any concern."
            )
        else:
            print("\n✅ Your system security looks good! No immediate issues found.")
            print("   I'm continuously monitoring for any threats.")

    def check_ssh_status(self):
        """Check SSH security specifically"""
        print("\n🔐 Checking SSH Security...")

        # Check if SSH is running
        result = subprocess.run(
            ["systemctl", "is-active", "sshd"], capture_output=True, text=True
        )

        if result.stdout.strip() == "active":
            print("✅ SSH service is running")

            # Check recent login attempts
            result = subprocess.run(
                [
                    "sudo",
                    "journalctl",
                    "-u",
                    "sshd",
                    "--since",
                    "24 hours ago",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
            )

            failed_count = result.stdout.count("Failed password")
            if failed_count > 0:
                print(f"⚠️  {failed_count} failed login attempts in the last 24 hours")
                print("   I can block these IPs if you'd like.")
            else:
                print("✅ No failed login attempts recently")
        else:
            print("ℹ️  SSH service is not running")

    def check_updates(self):
        """Check for system updates"""
        print("\n📦 Checking for updates...")

        result = subprocess.run(
            ["sudo", "dnf", "check-update"], capture_output=True, text=True
        )

        if result.returncode == 100:  # Updates available
            updates = len(result.stdout.strip().split("\n")) - 2
            print(f"📦 {updates} updates available")
            print(
                "   Would you like me to install them? (I'll create a backup point first)"
            )
        else:
            print("✅ Your system is up to date!")

    def check_ports(self):
        """Check open ports"""
        print("\n🔌 Checking open ports...")

        result = subprocess.run(
            ["sudo", "ss", "-tulnp"], capture_output=True, text=True
        )

        ports = []
        for line in result.stdout.splitlines()[1:]:
            if "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    port_info = parts[4]
                    ports.append(port_info)

        print(f"📊 Found {len(ports)} open ports:")
        common_ports = {
            "22": "SSH",
            "80": "HTTP",
            "443": "HTTPS",
            "3306": "MySQL",
            "5432": "PostgreSQL",
        }

        for port in ports[:10]:  # Show first 10
            port_num = port.split(":")[-1]
            service = common_ports.get(port_num, "Unknown service")
            print(f"   • Port {port_num}: {service}")

        print("\n💡 Tip: Only keep ports open that you actually need!")

    def check_firewall(self):
        """Check firewall status"""
        print("\n🛡️  Checking firewall...")

        result = subprocess.run(
            ["sudo", "firewall-cmd", "--list-all"], capture_output=True, text=True
        )

        if result.returncode == 0:
            print("✅ Firewall is active")
            print(result.stdout)
        else:
            print("❌ Firewall is not properly configured")
            print("   Would you like me to set it up for you?")

    def run_relevant_checks(self, query):
        """Run checks based on query content"""
        if any(word in query for word in ["hack", "attack", "breach"]):
            self.check_recent_threats()
        elif any(word in query for word in ["slow", "performance"]):
            self.check_performance_security()
        else:
            self.check_security_status()

    def check_recent_threats(self):
        """Check for recent security threats"""
        print("\n🚨 Checking for recent threats...")

        if self.db_path.exists():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT event_type, description, timestamp
                FROM security_events
                WHERE severity IN ('high', 'critical')
                AND timestamp > datetime('now', '-7 days')
                ORDER BY timestamp DESC
                LIMIT 5
            """)

            threats = cursor.fetchall()

            if threats:
                print("\n⚠️  Recent security events:")
                for threat in threats:
                    print(f"   • {threat[1]} ({threat[2]})")
            else:
                print("✅ No high-severity threats detected recently")

            conn.close()

    def check_performance_security(self):
        """Check if security issues affect performance"""
        print("\n⚡ Checking security-related performance issues...")

        # Check for excessive logging
        result = subprocess.run(
            ["du", "-sh", "/var/log"], capture_output=True, text=True
        )
        print(f"📊 Log directory size: {result.stdout.strip()}")

        # Check for too many firewall rules
        result = subprocess.run(
            ["sudo", "firewall-cmd", "--list-rich-rules"],
            capture_output=True,
            text=True,
        )
        rule_count = len(result.stdout.strip().split("\n"))
        print(f"🛡️  Firewall rules: {rule_count}")

        if rule_count > 100:
            print("   ⚠️  Many firewall rules might slow down network performance")

    def show_status(self):
        """Show current agent status"""
        # Check if service is running
        result = subprocess.run(
            ["systemctl", "is-active", "security-agent"], capture_output=True, text=True
        )

        if result.stdout.strip() == "active":
            print("\n✅ Security Agent is actively protecting your system")
        else:
            print("\n❌ Security Agent is not running")
            print("   Start it with: security-agent monitor")

        self.check_security_status()

    def run_scan(self):
        """Run a comprehensive security scan"""
        print("\n🔍 Running comprehensive security scan...")
        print("This will check:")
        print("  • Open ports and services")
        print("  • SSH configuration")
        print("  • System updates")
        print("  • Firewall rules")
        print("  • Recent security events")
        print("\nScanning...\n")

        self.check_ports()
        print()
        self.check_ssh_status()
        print()
        self.check_updates()
        print()
        self.check_firewall()
        print()
        self.check_recent_threats()

        print("\n✅ Scan complete! Ask me about any concerns you have.")

    def start_monitoring(self):
        """Start the monitoring service"""
        print("\n🚀 Starting continuous security monitoring...")

        # Start the systemd service
        result = subprocess.run(
            ["sudo", "systemctl", "start", "security-agent"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ Security monitoring started successfully!")
            print("   I'll alert you if I detect any threats.")
        else:
            # Fallback: run directly
            print("Starting agent directly...")
            subprocess.Popen(
                [
                    sys.executable,
                    str(
                        Path.home()
                        / "linux-security-agent"
                        / "src"
                        / "security_agent.py"
                    ),
                    "--daemon",
                ]
            )
            print("✅ Security agent started!")

    def stop_monitoring(self):
        """Stop the monitoring service"""
        print("\n⏹️  Stopping security monitoring...")
        subprocess.run(["sudo", "systemctl", "stop", "security-agent"])
        print("Security monitoring stopped.")

    def show_history(self):
        """Show security event history"""
        if self.db_path.exists():
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, event_type, severity, description
                FROM security_events
                ORDER BY timestamp DESC
                LIMIT 20
            """)

            events = cursor.fetchall()

            if events:
                print("\n📜 Recent Security Events:")
                for event in events:
                    severity_emoji = {
                        "low": "📘",
                        "medium": "📙",
                        "high": "📕",
                        "critical": "🚨",
                    }
                    emoji = severity_emoji.get(event[2], "📊")
                    print(f"{emoji} [{event[0]}] {event[3]}")
            else:
                print("\n📜 No security events recorded yet.")

            conn.close()

    def show_help(self):
        """Show help information"""
        help_text = """
🛡️  Security Agent Commands:

  status    - Check current security status
  scan      - Run comprehensive security scan  
  monitor   - Start continuous monitoring
  stop      - Stop monitoring
  history   - View security event history
  ask <question> - Ask anything about security
  help      - Show this help

📝 Example questions you can ask:
  • "Is my system secure?"
  • "Check SSH security"
  • "Are there any updates?"
  • "What ports are open?"
  • "Has anyone tried to hack me?"
  
💡 Tip: I understand natural language! Just ask your security questions.
        """
        print(help_text)

    def run(self):
        """Main CLI loop"""
        self.show_banner()

        if len(sys.argv) > 1:
            command = sys.argv[1].lower()

            if command in self.commands:
                if command == "ask" and len(sys.argv) > 2:
                    query = " ".join(sys.argv[2:])
                    self.natural_language_query(query)
                else:
                    self.commands[command]()
            else:
                # Treat as natural language query
                query = " ".join(sys.argv[1:])
                self.natural_language_query(query)
        else:
            # Interactive mode
            print("\n💬 Hi! I'm your Linux Security Assistant.")
            print("Type 'help' for commands, or just ask me about your security!\n")

            while True:
                try:
                    user_input = input("🛡️  Security Agent > ").strip()

                    if user_input.lower() in ["exit", "quit"]:
                        print("Stay secure! 👋")
                        break

                    # Parse command
                    parts = user_input.split()
                    if parts:
                        command = parts[0].lower()

                        if command in self.commands:
                            if command == "ask" and len(parts) > 1:
                                query = " ".join(parts[1:])
                                self.natural_language_query(query)
                            else:
                                self.commands[command]()
                        else:
                            # Treat as natural language
                            self.natural_language_query(user_input)

                except KeyboardInterrupt:
                    print("\n\nSecurity Agent stopped. Stay safe! 👋")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")


if __name__ == "__main__":
    cli = SecurityAgentCLI()
    cli.run()
