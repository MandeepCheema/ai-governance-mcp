#!/bin/bash

# AI Governance MCP Installation Script
# This script sets up the AI Governance MCP server

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_color() {
    color=$1
    message=$2
    echo -e "${color}${message}${NC}"
}

# Print header
print_header() {
    print_color "$BLUE" "
╔══════════════════════════════════════════╗
║      AI Governance MCP Installer         ║
║      Stop AI data leaks today! 🛡️        ║
╚══════════════════════════════════════════╝
"
}

# Check Python version
check_python() {
    print_color "$YELLOW" "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        print_color "$GREEN" "✓ Python $python_version found"
        
        # Check if version is 3.10+
        if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 10) else 1)'; then
            print_color "$GREEN" "✓ Python version is compatible"
        else
            print_color "$RED" "✗ Python 3.10+ required. Please upgrade Python."
            exit 1
        fi
    else
        print_color "$RED" "✗ Python 3 not found. Please install Python 3.10+"
        exit 1
    fi
}

# Create virtual environment
create_venv() {
    print_color "$YELLOW" "\nCreating virtual environment..."
    
    if [ -d "venv" ]; then
        print_color "$YELLOW" "Virtual environment already exists. Skipping..."
    else
        python3 -m venv venv
        print_color "$GREEN" "✓ Virtual environment created"
    fi
    
    # Activate venv
    source venv/bin/activate
    print_color "$GREEN" "✓ Virtual environment activated"
}

# Install dependencies
install_deps() {
    print_color "$YELLOW" "\nInstalling dependencies..."
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install package in editable mode
    pip install -e .
    
    # Install dev dependencies
    pip install -e ".[dev]"
    
    print_color "$GREEN" "✓ Dependencies installed"
}

# Run tests
run_tests() {
    print_color "$YELLOW" "\nRunning tests..."
    
    if pytest tests/ -v; then
        print_color "$GREEN" "✓ All tests passed!"
    else
        print_color "$YELLOW" "⚠️  Some tests failed, but installation completed"
    fi
}

# Configure Claude Desktop
configure_claude() {
    print_color "$YELLOW" "\nConfiguring Claude Desktop..."
    
    # Detect OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        config_path="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        config_path="$APPDATA/Claude/claude_desktop_config.json"
    else
        print_color "$YELLOW" "⚠️  Could not detect Claude Desktop config location"
        print_color "$YELLOW" "Please manually add the configuration to Claude Desktop"
        return
    fi
    
    # Check if config exists
    if [ -f "$config_path" ]; then
        print_color "$YELLOW" "Found Claude Desktop config at: $config_path"
        print_color "$YELLOW" "\nAdd this to your mcpServers section:"
        
        cat << EOF

{
  "mcpServers": {
    "ai-governance": {
      "command": "python",
      "args": ["$(pwd)/venv/bin/python", "-m", "ai_governance_mcp.server"],
      "env": {}
    }
  }
}

EOF
    else
        print_color "$YELLOW" "Claude Desktop config not found"
        print_color "$YELLOW" "Please create the config file and add the MCP server configuration"
    fi
}

# Main installation flow
main() {
    print_header
    
    # Check prerequisites
    check_python
    
    # Setup environment
    create_venv
    
    # Install package
    install_deps
    
    # Run tests
    run_tests
    
    # Configure Claude
    configure_claude
    
    # Success message
    print_color "$GREEN" "
╔══════════════════════════════════════════╗
║      Installation Complete! 🎉           ║
╚══════════════════════════════════════════╝

Next steps:
1. Add the configuration to Claude Desktop
2. Restart Claude Desktop
3. Test with: 'Use scan_prompt to check: My SSN is 123-45-6789'

For more information:
- Documentation: https://github.com/yourusername/ai-governance-mcp
- Discord: https://discord.gg/ai-governance

Star us on GitHub if you find this useful! ⭐
"
}

# Run main function
main