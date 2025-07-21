#!/usr/bin/env python3
"""
Local testing script for AI Governance MCP
Run this to test the MCP server without Claude Desktop
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ai_governance_mcp.server import AIGovernanceMCP
from ai_governance_mcp.patterns import detect_pii, redact_pii
from ai_governance_mcp.policies import check_policies

# Test cases
TEST_PROMPTS = [
    {
        "name": "Clean prompt",
        "prompt": "What's the weather like today?",
        "expected": "No issues"
    },
    {
        "name": "Email and phone",
        "prompt": "Contact john@example.com or call 555-123-4567",
        "expected": "PII detected"
    },
    {
        "name": "Credit card and SSN",
        "prompt": "Payment: 4532-1488-0343-6467, SSN: 123-45-6789",
        "expected": "Multiple PII"
    },
    {
        "name": "Medical advice",
        "prompt": "What medication should I take for my headache?",
        "expected": "Policy violation - blocked"
    },
    {
        "name": "API key",
        "prompt": 'My API key is sk_test_1234567890abcdef',
        "expected": "Sensitive credential"
    },
    {
        "name": "Mixed issues",
        "prompt": "I need medical advice, my email is test@example.com",
        "expected": "Both PII and policy violation"
    }
]

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text, color):
    """Print colored text"""
    print(f"{color}{text}{Colors.ENDC}")

def print_section(title):
    """Print section header"""
    print_colored(f"\n{'='*60}", Colors.BLUE)
    print_colored(f"{title:^60}", Colors.BOLD)
    print_colored(f"{'='*60}", Colors.BLUE)

async def test_basic_functionality():
    """Test basic MCP functionality"""
    print_section("Testing Basic Functionality")
    
    # Initialize server
    server = AIGovernanceMCP()
    
    for test in TEST_PROMPTS:
        print_colored(f"\n📝 Test: {test['name']}", Colors.YELLOW)
        print(f"   Prompt: \"{test['prompt']}\"")
        print(f"   Expected: {test['expected']}")
        
        # Test PII detection
        pii_matches = detect_pii(test['prompt'])
        if pii_matches:
            print_colored(f"   ✓ PII Detected: {[m.name for m in pii_matches]}", Colors.GREEN)
            
            # Test redaction
            redacted = redact_pii(test['prompt'], pii_matches)
            print(f"   Redacted: \"{redacted}\"")
        else:
            print("   ✓ No PII detected")
        
        # Test policy checking
        violations = check_policies(test['prompt'])
        if violations:
            print_colored(f"   ⚠️  Policy Violations: {[v.policy_name for v in violations]}", Colors.RED)
            for v in violations:
                print(f"      - {v.message}")
        else:
            print("   ✓ No policy violations")

async def test_mcp_tools():
    """Test MCP tool functionality"""
    print_section("Testing MCP Tools")
    
    server = AIGovernanceMCP()
    
    # Test scan_prompt
    print_colored("\n🔧 Testing scan_prompt tool", Colors.YELLOW)
    result = await server._scan_prompt({
        'prompt': 'Contact me at john@example.com about the medical diagnosis',
        'auto_redact': True
    })
    
    print(f"   Safe to send: {result['safe_to_send']}")
    print(f"   Action: {result['action']}")
    print(f"   PII found: {len(result['pii_detected'])}")
    print(f"   Violations: {len(result['policy_violations'])}")
    
    # Test compliance check
    print_colored("\n🔧 Testing check_compliance tool", Colors.YELLOW)
    result = await server._check_compliance({
        'text': 'This is a safe message with no issues'
    })
    print(f"   Compliant: {result['compliant']}")
    print(f"   Recommendation: {result['recommendation']}")
    
    # Test statistics
    print_colored("\n🔧 Testing get_statistics tool", Colors.YELLOW)
    result = await server._get_statistics({'days': 7})
    print(f"   Total scans: {result['summary']['total_scans']}")
    print(f"   PII detections: {result['summary']['total_pii_detections']}")
    print(f"   Policy violations: {result['summary']['total_policy_violations']}")

async def test_audit_trail():
    """Test audit trail functionality"""
    print_section("Testing Audit Trail")
    
    server = AIGovernanceMCP()
    
    # Submit some test prompts
    test_data = [
        "Clean prompt with no issues",
        "Email test@example.com needs redaction",
        "I need medical advice for symptoms"
    ]
    
    print_colored("\n📝 Submitting test prompts...", Colors.YELLOW)
    
    for prompt in test_data:
        result = await server._scan_prompt({'prompt': prompt})
        print(f"   ✓ Logged: {prompt[:30]}... (hash: {result.get('audit_hash', 'N/A')[:8]}...)")
    
    # Verify integrity
    print_colored("\n🔒 Verifying hash chain integrity...", Colors.YELLOW)
    integrity = await server._verify_integrity({'limit': 10})
    
    if integrity['valid']:
        print_colored(f"   ✓ Hash chain valid! Checked {integrity['entries_checked']} entries", Colors.GREEN)
    else:
        print_colored(f"   ✗ Hash chain invalid! {len(integrity['invalid_entries'])} errors", Colors.RED)
    
    # Export logs
    print_colored("\n📤 Testing log export...", Colors.YELLOW)
    export_result = await server._export_audit_logs({'format': 'json'})
    logs = json.loads(export_result['data'])
    print(f"   ✓ Exported {len(logs)} audit entries")

async def test_performance():
    """Test performance metrics"""
    print_section("Performance Testing")
    
    server = AIGovernanceMCP()
    
    # Test prompt with all features
    test_prompt = """
    Please contact our team:
    - John Doe: john@example.com, 555-123-4567
    - Jane Smith: jane@example.com, SSN: 987-65-4321
    - API Key: sk_test_1234567890abcdef
    I need medical advice about these symptoms.
    """
    
    print_colored("\n⏱️  Testing processing speed...", Colors.YELLOW)
    
    iterations = 100
    start_time = datetime.now()
    
    for _ in range(iterations):
        await server._scan_prompt({
            'prompt': test_prompt,
            'auto_redact': True
        })
    
    end_time = datetime.now()
    total_time = (end_time - start_time).total_seconds()
    avg_time = total_time / iterations * 1000  # Convert to ms
    
    print(f"   Total time: {total_time:.2f}s")
    print(f"   Average per prompt: {avg_time:.2f}ms")
    print_colored(f"   ✓ Performance: {'PASS' if avg_time < 50 else 'FAIL'}", 
                  Colors.GREEN if avg_time < 50 else Colors.RED)

async def interactive_test():
    """Interactive testing mode"""
    print_section("Interactive Test Mode")
    
    server = AIGovernanceMCP()
    
    print("\nEnter prompts to test (type 'quit' to exit):")
    
    while True:
        try:
            prompt = input("\n> ")
            
            if prompt.lower() in ['quit', 'exit', 'q']:
                break
            
            if not prompt.strip():
                continue
            
            # Process the prompt
            result = await server._scan_prompt({
                'prompt': prompt,
                'auto_redact': True
            })
            
            # Display results
            print_colored("\n📊 Results:", Colors.BLUE)
            print(f"   Safe to send: {'✓' if result['safe_to_send'] else '✗'}")
            print(f"   Action: {result['action']}")
            
            if result['pii_detected']:
                print_colored(f"\n   🔍 PII Detected:", Colors.YELLOW)
                for pii in result['pii_detected']:
                    print(f"      - {pii['name']} ({pii['severity']})")
            
            if result['policy_violations']:
                print_colored(f"\n   ⚠️  Policy Violations:", Colors.RED)
                for violation in result['policy_violations']:
                    print(f"      - {violation['message']}")
            
            if result['redacted_prompt'] and result['redacted_prompt'] != prompt:
                print_colored(f"\n   📝 Redacted version:", Colors.GREEN)
                print(f"      {result['redacted_prompt']}")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print_colored(f"   Error: {e}", Colors.RED)

async def main():
    """Run all tests"""
    print_colored("""
    🛡️  AI Governance MCP - Local Test Suite
    =========================================
    """, Colors.BOLD)
    
    # Run automated tests
    await test_basic_functionality()
    await test_mcp_tools()
    await test_audit_trail()
    await test_performance()
    
    # Summary
    print_section("Test Summary")
    print_colored("✅ All automated tests completed!", Colors.GREEN)
    
    # Ask about interactive mode
    print("\nWould you like to enter interactive test mode? (y/n): ", end='')
    
    if input().lower() == 'y':
        await interactive_test()
    
    print_colored("\n🎉 Testing complete! AI Governance MCP is ready to use.", Colors.GREEN)
    print("\nNext steps:")
    print("1. Add to Claude Desktop config")
    print("2. Restart Claude Desktop")
    print("3. Start using AI Governance tools!")

if __name__ == "__main__":
    asyncio.run(main())