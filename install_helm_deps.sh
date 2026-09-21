#!/bin/bash
echo "Installing Helm SDK Dependencies"
echo "================================="
echo ""

# Check if pip3 is available
if ! command -v pip3 &> /dev/null; then
    echo "✗ Error: pip3 not found"
    echo "  Install Python 3 and pip first"
    exit 1
fi

echo "Installing required libraries..."
echo "  - requests"
echo "  - protobuf==3.20"
echo ""

# Try regular install first, fallback to user install
if pip3 install requests "protobuf==3.20" 2>/dev/null; then
    echo "✓ Installed successfully"
elif pip3 install --user requests "protobuf==3.20"; then
    echo "✓ Installed successfully (user mode)"
else
    echo "✗ Installation failed"
    echo "  Try manually: pip3 install --user requests 'protobuf==3.20'"
    exit 1
fi

echo ""
echo "Verifying installation..."

# Verify
python3 -c "
import requests
import google.protobuf
print('✓ requests version:', requests.__version__)
print('✓ protobuf version:', google.protobuf.__version__)
" 2>/dev/null

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ All dependencies installed!"
    echo ""
    echo "Next steps:"
    echo "  1. Edit config.py (set HELM_PRODUCT_NAME and HELM_WORKSPACE_NAME)"
    echo "  2. Create mc_api_key.txt (Helm credentials)"
    echo "  3. Create viper_api_key.txt (Viper token)"
    echo "  4. Run: python3 helm_viper_integration.py"
else
    echo ""
    echo "✗ Verification failed"
    echo "  Check for errors above"
    exit 1
fi
