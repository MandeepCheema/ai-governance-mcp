"""
PII Detection Patterns and Functions
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class PIIMatch:
    """Represents a PII match in text"""
    type: str
    name: str
    value: str
    start: int
    end: int
    severity: str
    confidence: float = 1.0

# Core PII Patterns
PII_PATTERNS = {
    'ssn': {
        'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
        'name': 'Social Security Number',
        'severity': 'high',
        'description': 'US Social Security Number'
    },
    'email': {
        'pattern': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'name': 'Email Address',
        'severity': 'medium',
        'description': 'Email addresses'
    },
    'phone_us': {
        'pattern': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'name': 'Phone Number (US)',
        'severity': 'medium',
        'description': 'US phone numbers'
    },
    'credit_card': {
        'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'name': 'Credit Card Number',
        'severity': 'high',
        'description': 'Credit card numbers'
    },
    'ip_address': {
        'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'name': 'IP Address',
        'severity': 'low',
        'description': 'IPv4 addresses'
    },
    'aws_key': {
        'pattern': r'\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b',
        'name': 'AWS Access Key',
        'severity': 'critical',
        'description': 'AWS access key IDs'
    },
    'api_key_generic': {
        'pattern': r'\b(?:api[_-]?key|apikey|api[_-]?token)["\s:=]+["\'`]?([a-zA-Z0-9_\-]{20,})["\'`]?\b',
        'name': 'API Key',
        'severity': 'high',
        'description': 'Generic API keys'
    },
    'github_token': {
        'pattern': r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b',
        'name': 'GitHub Token',
        'severity': 'critical',
        'description': 'GitHub personal access tokens'
    },
    'slack_token': {
        'pattern': r'\bxox[baprs]-[a-zA-Z0-9-]+\b',
        'name': 'Slack Token',
        'severity': 'high',
        'description': 'Slack API tokens'
    },
    'private_key': {
        'pattern': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'name': 'Private Key',
        'severity': 'critical',
        'description': 'Private cryptographic keys'
    }
}

# Extended patterns (Pro version)
EXTENDED_PATTERNS = {
    'passport': {
        'pattern': r'\b[A-Z]{1,2}\d{6,9}\b',
        'name': 'Passport Number',
        'severity': 'high',
        'description': 'Passport numbers'
    },
    'drivers_license': {
        'pattern': r'\b[A-Z]{1,2}\d{5,8}\b',
        'name': 'Driver License',
        'severity': 'medium',
        'description': 'Driver license numbers'
    },
    'iban': {
        'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
        'name': 'IBAN',
        'severity': 'high',
        'description': 'International Bank Account Number'
    },
    'bitcoin_address': {
        'pattern': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        'name': 'Bitcoin Address',
        'severity': 'medium',
        'description': 'Bitcoin wallet addresses'
    },
    'ethereum_address': {
        'pattern': r'\b0x[a-fA-F0-9]{40}\b',
        'name': 'Ethereum Address',
        'severity': 'medium',
        'description': 'Ethereum wallet addresses'
    }
}

def validate_credit_card(number: str) -> bool:
    """Validate credit card using Luhn algorithm"""
    number = re.sub(r'[-\s]', '', number)
    if not number.isdigit():
        return False
    
    total = 0
    reverse_digits = number[::-1]
    
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    
    return total % 10 == 0

def detect_pii(text: str, extended: bool = False) -> List[PIIMatch]:
    """
    Detect PII in text
    
    Args:
        text: Text to scan
        extended: Use extended pattern set (Pro feature)
    
    Returns:
        List of PIIMatch objects
    """
    patterns = PII_PATTERNS.copy()
    if extended:
        patterns.update(EXTENDED_PATTERNS)
    
    matches = []
    
    for pii_type, config in patterns.items():
        pattern_matches = re.finditer(config['pattern'], text, re.IGNORECASE)
        
        for match in pattern_matches:
            # Special validation for credit cards
            if pii_type == 'credit_card':
                if not validate_credit_card(match.group()):
                    continue
            
            # Extract the actual value (for API keys with capture groups)
            value = match.group(1) if len(match.groups()) > 0 else match.group()
            
            matches.append(PIIMatch(
                type=pii_type,
                name=config['name'],
                value=value,
                start=match.start(),
                end=match.end(),
                severity=config['severity']
            ))
    
    # Sort by position for consistent redaction
    matches.sort(key=lambda x: x.start)
    
    return matches

def redact_pii(text: str, matches: List[PIIMatch], redaction_style: str = "[REDACTED]") -> str:
    """
    Redact PII from text
    
    Args:
        text: Original text
        matches: List of PII matches
        redaction_style: How to redact (default: [REDACTED])
    
    Returns:
        Redacted text
    """
    if not matches:
        return text
    
    # Sort by position (reverse) to maintain indices
    sorted_matches = sorted(matches, key=lambda x: x.start, reverse=True)
    
    redacted = text
    for match in sorted_matches:
        if redaction_style == "[REDACTED-TYPE]":
            replacement = f"[REDACTED-{match.name.upper()}]"
        elif redaction_style == "[REDACTED-XXX]":
            # Preserve length with X's
            replacement = f"[{'X' * (match.end - match.start - 2)}]"
        else:
            replacement = redaction_style
        
        redacted = redacted[:match.start] + replacement + redacted[match.end:]
    
    return redacted

def get_pii_summary(matches: List[PIIMatch]) -> Dict[str, Any]:
    """Get summary of PII detections"""
    summary = {
        'total_count': len(matches),
        'by_type': {},
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'unique_types': set()
    }
    
    for match in matches:
        # Count by type
        if match.type not in summary['by_type']:
            summary['by_type'][match.type] = 0
        summary['by_type'][match.type] += 1
        
        # Count by severity
        summary['by_severity'][match.severity] += 1
        
        # Track unique types
        summary['unique_types'].add(match.name)
    
    summary['unique_types'] = list(summary['unique_types'])
    
    return summary