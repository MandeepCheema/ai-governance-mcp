# AI Governance MCP Server 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.com)

Stop AI data leaks before they happen. AI Governance MCP provides enterprise-grade security and compliance for any LLM, integrated directly into Claude Desktop and other MCP-compatible applications.

## 🌟 Features

### 🔒 **PII Detection**
- **10+ Built-in Patterns**: SSN, emails, phone numbers, credit cards, API keys, and more
- **Validation**: Smart detection with Luhn algorithm for credit cards
- **Extensible**: Add custom patterns for your organization
- **Real-time**: <50ms processing time

### 🛡️ **Policy Enforcement**
- **Pre-built Rules**: Medical, legal, financial advice blocking
- **Custom Policies**: Define your own rules and actions
- **Flexible Actions**: Block, warn, or redact based on context
- **Keyword & Regex**: Both simple and complex pattern matching

### 📊 **Audit Trail**
- **Immutable Logs**: Blockchain-style hash chain
- **Complete History**: Every prompt, action, and decision logged
- **Compliance Ready**: Export for SOC2, HIPAA, GDPR audits
- **Integrity Verification**: Detect tampering attempts

### ⚡ **Zero Friction**
- **Local Processing**: Your data never leaves your machine
- **No API Keys**: Direct integration with Claude Desktop
- **5-Minute Setup**: Simple configuration file
- **Minimal Overhead**: Lightweight and fast

## 🚀 Quick Start

### 1. Install

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-governance-mcp
cd ai-governance-mcp

# Install dependencies
pip install -e .
```

### 2. Configure Claude Desktop

Add to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ai-governance": {
      "command": "python",
      "args": ["-m", "ai_governance_mcp.server"],
      "env": {}
    }
  }
}
```

### 3. Restart Claude Desktop

That's it! AI Governance is now protecting your AI interactions.

## 📖 Usage

### Basic Commands

In Claude, simply type:

```
Use scan_prompt to check: "Contact me at john@email.com or 555-123-4567"
```

Claude will respond with:
```json
{
  "pii_detected": ["email", "phone"],
  "redacted_prompt": "Contact me at [REDACTED] or [REDACTED]",
  "safe_to_send": true
}
```

### Available Tools

| Tool | Description | Example |
|------|-------------|---------|
| `scan_prompt` | Scan text for PII and policy violations | `scan_prompt "My SSN is 123-45-6789"` |
| `check_compliance` | Quick compliance check | `check_compliance "Is this text safe?"` |
| `redact_pii` | Redact PII from text | `redact_pii "Email: john@example.com"` |
| `get_statistics` | View usage statistics | `get_statistics for last 7 days` |
| `export_audit_logs` | Export logs for compliance | `export_audit_logs as CSV` |
| `verify_integrity` | Verify audit log integrity | `verify_integrity last 100 entries` |

## 🎯 Use Cases

### For Developers
```
"I need to ask Claude about our database schema"
*Accidentally pastes connection string with password*

AI Governance: "Detected API credentials - automatically redacted"
```

### For Customer Support
```
"Customer John Doe (SSN: 123-45-6789) needs help with..."

AI Governance: "Customer John Doe (SSN: [REDACTED]) needs help with..."
```

### For Healthcare
```
"Patient symptoms indicate possible diagnosis of..."

AI Governance: "Medical advice policy violation - blocked"
```

## 🔧 Configuration

### Custom PII Patterns

Create `~/.ai_governance_mcp/custom_patterns.json`:

```json
{
  "employee_id": {
    "pattern": "EMP\\d{6}",
    "name": "Employee ID",
    "severity": "high"
  },
  "internal_project": {
    "pattern": "PROJECT-[A-Z]{3}-\\d{4}",
    "name": "Internal Project Code",
    "severity": "medium"
  }
}
```

### Custom Policies

Create `~/.ai_governance_mcp/custom_policies.json`:

```json
{
  "company_secrets": {
    "keywords": ["project phoenix", "operation blue"],
    "action": "block",
    "message": "Company confidential information detected"
  }
}
```

## 📊 Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Desktop │────▶│  AI Governance  │────▶│   Your LLM      │
│                 │◀────│   MCP Server    │◀────│                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │  Local SQLite   │
                        │   Audit Log     │
                        └─────────────────┘
```

## 🔒 Security

- **Local Processing**: All scanning happens on your machine
- **No Cloud Dependencies**: Works offline
- **Encrypted Storage**: Audit logs use SQLite with optional encryption
- **Hash Chain**: Tamper-evident audit trail
- **Zero Trust**: No external API calls

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ai_governance_mcp

# Run specific test
pytest tests/test_patterns.py -v
```

## 📈 Performance

- **Latency**: <50ms for typical prompts
- **Throughput**: 1000+ prompts/second
- **Memory**: <100MB RAM usage
- **Storage**: ~1KB per audit log entry

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run formatter
black src/ tests/

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🌟 Pro Version

Need enterprise features? The Pro version includes:

- **50+ PII Patterns**: International IDs, healthcare identifiers, crypto addresses
- **Advanced Policies**: ML-powered detection, contextual rules
- **Team Management**: Centralized policy distribution
- **Compliance Reports**: One-click SOC2/HIPAA reports
- **Priority Support**: Direct access to our team

[Learn more about AI Governance Pro →](https://aigovernance.dev/pro)

## 🏆 Why AI Governance?

Unlike other solutions:

- **MCP Native**: Built specifically for Claude Desktop
- **Privacy First**: Your data never leaves your machine
- **Compliance Ready**: Audit trails that satisfy regulators
- **Open Source**: Inspect and customize the code
- **Zero Friction**: No API keys, no cloud setup

## 📞 Support

- **Documentation**: [Full docs](https://aigovernance.dev/docs)
- **Discord**: [Join our community](https://discord.gg/ai-governance)
- **Issues**: [GitHub Issues](https://github.com/yourusername/ai-governance-mcp/issues)
- **Email**: support@aigovernance.dev

---

<p align="center">
  Built with ❤️ for the AI community
  <br>
  <a href="https://aigovernance.dev">aigovernance.dev</a>
</p>