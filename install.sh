#!/bin/bash
# Install Linux Security AI Agent

echo "🛡️  Installing Linux Security AI Agent..."

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Please don't run this as root. Run as your regular user."
   exit 1
fi

# Install directory
INSTALL_DIR="$HOME/linux-security-agent"

# Create alias for easy access
echo "Creating command alias..."
if ! grep -q "alias security-agent" ~/.bashrc; then
    echo "alias security-agent='$INSTALL_DIR/security-agent'" >> ~/.bashrc
fi

# Install systemd service (optional)
read -p "Install as system service for continuous monitoring? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing systemd service..."
    sudo cp $INSTALL_DIR/config/security-agent.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable security-agent
    echo "✅ Service installed! Start with: sudo systemctl start security-agent"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🚀 To start using the Security Agent:"
echo "   1. Run: source ~/.bashrc"
echo "   2. Then: security-agent"
echo ""
echo "📝 Quick commands:"
echo "   security-agent status    - Check security status"
echo "   security-agent scan      - Run security scan"
echo "   security-agent monitor   - Start monitoring"
echo "   security-agent 'is my system secure?'  - Ask anything!"
echo ""