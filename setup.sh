#!/bin/bash
set -e

echo "🔧 Setting up az_vuln_cli dependencies..."

# Detect operating system
OS="unknown"
case "$(uname -s)" in
    Darwin*)    OS="macOS" ;;
    Linux*)     OS="Linux" ;;
esac
echo "🖥️  Detected OS: $OS"

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed."
    echo "Please install Python 3:"
    case $OS in
        "macOS")
            echo "  brew install python3" ;;
        "Linux")
            echo "  sudo apt-get update && sudo apt-get install python3 python3-pip" ;;
        *)
            echo "  Visit: https://www.python.org/downloads/" ;;
    esac
    exit 1
fi

# Check if Azure CLI is available
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is required but not installed."
    echo "Please install Azure CLI:"
    case $OS in
        "macOS")
            echo "  brew install azure-cli" ;;
        "Linux")
            echo "  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash" ;;
        *)
            echo "  Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli" ;;
    esac
    exit 1
fi

# Check if Trivy is available
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy is required but not installed."
    echo "Please install Trivy:"
    case $OS in
        "macOS")
            echo "  brew install trivy" ;;
        "Linux")
            echo "  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin" ;;
        *)
            echo "  Visit: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" ;;
    esac
    exit 1
fi

# Check if user is logged in to Azure CLI
echo "🔐 Checking Azure CLI authentication..."
if ! az account show &> /dev/null; then
    echo "⚠️  You are not logged in to Azure CLI."
    echo "Please run 'az login' and try again."
    echo "If you need to login to a specific tenant, use:"
    echo "  az login --tenant <tenant-id>"
    exit 1
fi

# Get current Azure subscription info
SUBSCRIPTION_NAME=$(az account show --query "name" -o tsv)
SUBSCRIPTION_ID=$(az account show --query "id" -o tsv)
echo "✅ Authenticated to Azure subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"

# Install dependencies using pip (user mode to avoid permission issues)
echo "📦 Installing Python dependencies..."
python3 -m pip install --user -r requirements.txt

echo "✅ Setup complete! You can now run:"
echo "    ./az_vuln_cli.py --help"
printf '%0.s-' {1..50}; echo
echo "Quick start:"
printf '%0.s-' {1..50}; echo
echo "# Log in to services:"
echo "    ./az_vuln_cli.py auth"
echo "# Generate inventory:"
echo "    ./az_vuln_cli.py inventory all"
echo "# Scan images and generate reports:"
echo "    ./az_vuln_cli.py scan all"
printf '%0.s-' {1..50}; echo
echo "The final output will be ./reports/vulnerability_comparison_analysis.xlsx"
