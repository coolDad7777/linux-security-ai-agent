# 🛡️ Linux Security AI Agent

Your personal AI-powered Linux security assistant that monitors, protects, and educates you about system security.

## Features

### 🤖 Natural Language Interface
Talk to your security agent like a real security expert:
- "Is my system secure?"
- "Someone is trying to hack me"
- "Check if I have any vulnerabilities"
- "Explain what ports should be open"

### 🔍 Real-time Monitoring
- SSH brute-force detection
- Port scanning detection  
- Unusual process monitoring
- File system integrity checking
- Automatic threat response

### 🎓 Educational Mode
- Explains security issues in plain English
- Teaches you why things matter
- Offers "fix it for me" or "show me how" options

## Quick Start

1. **Install the agent:**
   ```bash
   cd ~/linux-security-agent
   ./install.sh
   source ~/.bashrc
   ```

2. **Check your security status:**
   ```bash
   security-agent status
   ```

3. **Ask questions naturally:**
   ```bash
   security-agent "is someone trying to hack me?"
   security-agent "what ports are open?"
   security-agent "check ssh security"
   ```

4. **Start continuous monitoring:**
   ```bash
   security-agent monitor
   # Or as a service:
   sudo systemctl start security-agent
   ```

## Commands

- `security-agent` - Interactive mode
- `security-agent status` - Quick security check
- `security-agent scan` - Comprehensive scan
- `security-agent monitor` - Start monitoring
- `security-agent history` - View past events
- `security-agent <question>` - Ask anything!

## How It Works

The agent continuously:
1. **Monitors** system logs and network activity
2. **Detects** suspicious patterns and anomalies
3. **Alerts** you in plain English
4. **Takes action** to protect your system
5. **Learns** your normal usage patterns

## Examples

### Check SSH Security
```bash
$ security-agent "check ssh"

🔐 Checking SSH Security...
✅ SSH service is running
⚠️  4 failed login attempts in the last 24 hours
   I can block these IPs if you'd like.
```

### Natural Conversations
```bash
$ security-agent

💬 Hi! I'm your Linux Security Assistant.
🛡️  Security Agent > someone is port scanning me

🚨 Let me check for port scanning activity...
⚠️  Detected rapid connection attempts from 192.168.1.105
   Blocking this IP and tightening firewall rules...
✅ Threat neutralized! Added firewall rule to block scanner.
```

### Automatic Protection
When running as a service, the agent:
- Blocks IPs after repeated failed SSH attempts
- Alerts you to new services or ports
- Checks for security updates
- Monitors for privilege escalation

## Security Features

- **No cloud dependency** - Runs entirely on your machine
- **Privacy-first** - No data leaves your system
- **Transparent actions** - Always explains what it's doing
- **Safe defaults** - Won't break your system
- **Educational** - Teaches you as it protects

## Future Enhancements

- [ ] Integration with AI APIs for smarter analysis
- [ ] Web dashboard for visual monitoring  
- [ ] Mobile notifications
- [ ] Advanced threat intelligence
- [ ] Custom security policies
- [ ] Integration with other security tools

## Requirements

- Linux (tested on Fedora, Ubuntu, Debian)
- Python 3.6+
- systemd (for service mode)
- sudo access (for some security features)

## Troubleshooting

**Agent won't start:**
```bash
# Check logs
cat ~/linux-security-agent/logs/agent.log

# Run directly to see errors
python3 ~/linux-security-agent/src/security_agent.py
```

**Permission issues:**
- Some features require sudo (firewall, system logs)
- Run install.sh as regular user, not root

**Service issues:**
```bash
sudo systemctl status security-agent
sudo journalctl -u security-agent -f
```

## Contributing

This is a prototype demonstrating how AI can make Linux security accessible to everyone. Feel free to extend and improve!

## License

MIT - Use freely and responsibly!