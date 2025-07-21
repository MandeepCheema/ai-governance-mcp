"""
Policy Rules and Enforcement
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

class PolicyAction(Enum):
    """Actions to take when policy is violated"""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"

@dataclass
class PolicyViolation:
    """Represents a policy violation"""
    policy_name: str
    category: str
    matched_keyword: str
    action: PolicyAction
    message: str
    severity: str
    confidence: float = 1.0

# Core Policy Rules
POLICY_RULES = {
    'medical_advice': {
        'category': 'medical',
        'keywords': [
            'medical advice', 'diagnosis', 'diagnose', 'prescribe', 'prescription',
            'treatment plan', 'medication', 'dosage', 'symptoms indicate',
            'medical opinion', 'health advice'
        ],
        'regex_patterns': [
            r'\b(?:what|which) (?:medication|medicine|drug)s?\b',
            r'\b(?:should i|do i need to) (?:take|see a doctor)\b',
            r'\bdiagnos(?:is|e) (?:my|these) symptoms?\b'
        ],
        'action': PolicyAction.BLOCK,
        'message': 'Medical advice detected. Please consult a licensed healthcare professional.',
        'severity': 'high'
    },
    'legal_advice': {
        'category': 'legal',
        'keywords': [
            'legal advice', 'legal counsel', 'lawsuit', 'sue', 'legal action',
            'legal rights', 'attorney', 'lawyer', 'legal opinion', 'contract review'
        ],
        'regex_patterns': [
            r'\b(?:can|should) i sue\b',
            r'\bis this (?:legal|illegal)\b',
            r'\bwhat are my legal (?:rights|options)\b'
        ],
        'action': PolicyAction.BLOCK,
        'message': 'Legal advice detected. Please consult a qualified attorney.',
        'severity': 'high'
    },
    'financial_advice': {
        'category': 'financial',
        'keywords': [
            'investment advice', 'stock tips', 'financial planning', 
            'buy this stock', 'invest in', 'trading strategy', 'portfolio advice',
            'retirement planning', 'tax advice'
        ],
        'regex_patterns': [
            r'\b(?:should i|when to) (?:buy|sell) (?:stock|crypto)\b',
            r'\b(?:best|good) investment (?:strategy|opportunity)\b'
        ],
        'action': PolicyAction.WARN,
        'message': 'Financial advice detected. Please consult a licensed financial advisor.',
        'severity': 'medium'
    },
    'harmful_content': {
        'category': 'safety',
        'keywords': [
            'self harm', 'suicide', 'hurt myself', 'end my life',
            'harmful', 'dangerous activity'
        ],
        'regex_patterns': [
            r'\bhow to (?:make|build|create) (?:bomb|weapon|explosive)\b',
            r'\b(?:ways to|how to) (?:harm|hurt|injure)\b'
        ],
        'action': PolicyAction.BLOCK,
        'message': 'Content policy violation. This type of content is not allowed.',
        'severity': 'critical'
    },
    'internal_data': {
        'category': 'confidential',
        'keywords': [
            'confidential', 'internal only', 'do not share', 'proprietary',
            'trade secret', 'company confidential', 'restricted'
        ],
        'regex_patterns': [
            r'\b(?:internal|confidential) (?:document|information|data)\b',
            r'\bdo not (?:share|distribute|disclose)\b'
        ],
        'action': PolicyAction.WARN,
        'message': 'Potentially confidential information detected.',
        'severity': 'medium'
    }
}

# Extended policies (Pro version)
EXTENDED_POLICIES = {
    'competitive_intel': {
        'category': 'business',
        'keywords': [
            'competitor analysis', 'competitor pricing', 'steal customers',
            'poach employees', 'competitor secrets'
        ],
        'action': PolicyAction.WARN,
        'message': 'Competitive intelligence query detected.',
        'severity': 'low'
    },
    'personal_info_request': {
        'category': 'privacy',
        'keywords': [
            'home address', 'personal phone', 'family members',
            'social security', 'date of birth', 'mothers maiden name'
        ],
        'action': PolicyAction.WARN,
        'message': 'Request for personal information detected.',
        'severity': 'medium'
    },
    'code_injection': {
        'category': 'security',
        'regex_patterns': [
            r'<script[^>]*>.*?</script>',
            r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*(?:FROM|INTO|TABLE)',
            r'(?:\$\{|\{\{)[^}]+(?:\}|\}\})'
        ],
        'action': PolicyAction.BLOCK,
        'message': 'Potential code injection detected.',
        'severity': 'high'
    }
}

def check_policies(
    text: str, 
    extended: bool = False,
    custom_policies: Dict[str, Any] = None
) -> List[PolicyViolation]:
    """
    Check text against policy rules
    
    Args:
        text: Text to check
        extended: Use extended policy set (Pro feature)
        custom_policies: Additional custom policies
    
    Returns:
        List of PolicyViolation objects
    """
    policies = POLICY_RULES.copy()
    
    if extended:
        policies.update(EXTENDED_POLICIES)
    
    if custom_policies:
        policies.update(custom_policies)
    
    violations = []
    text_lower = text.lower()
    
    for policy_name, config in policies.items():
        matched = False
        matched_keyword = None
        
        # Check keywords
        if 'keywords' in config:
            for keyword in config['keywords']:
                if keyword.lower() in text_lower:
                    matched = True
                    matched_keyword = keyword
                    break
        
        # Check regex patterns
        if not matched and 'regex_patterns' in config:
            for pattern in config['regex_patterns']:
                if re.search(pattern, text, re.IGNORECASE):
                    matched = True
                    matched_keyword = f"pattern: {pattern}"
                    break
        
        if matched:
            violations.append(PolicyViolation(
                policy_name=policy_name,
                category=config.get('category', 'general'),
                matched_keyword=matched_keyword,
                action=config.get('action', PolicyAction.WARN),
                message=config.get('message', 'Policy violation detected'),
                severity=config.get('severity', 'medium')
            ))
    
    return violations

def should_block(violations: List[PolicyViolation]) -> bool:
    """Check if any violations require blocking"""
    return any(v.action == PolicyAction.BLOCK for v in violations)

def get_policy_summary(violations: List[PolicyViolation]) -> Dict[str, Any]:
    """Get summary of policy violations"""
    summary = {
        'total_violations': len(violations),
        'should_block': should_block(violations),
        'by_category': {},
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'by_action': {'allow': 0, 'warn': 0, 'block': 0, 'redact': 0},
        'messages': []
    }
    
    for violation in violations:
        # Count by category
        if violation.category not in summary['by_category']:
            summary['by_category'][violation.category] = 0
        summary['by_category'][violation.category] += 1
        
        # Count by severity
        summary['by_severity'][violation.severity] += 1
        
        # Count by action
        summary['by_action'][violation.action.value] += 1
        
        # Collect unique messages
        if violation.message not in summary['messages']:
            summary['messages'].append(violation.message)
    
    return summary

def apply_policy_actions(
    text: str,
    violations: List[PolicyViolation]
) -> Dict[str, Any]:
    """Apply policy actions to text"""
    result = {
        'original_text': text,
        'processed_text': text,
        'blocked': False,
        'warnings': [],
        'applied_actions': []
    }
    
    for violation in violations:
        if violation.action == PolicyAction.BLOCK:
            result['blocked'] = True
            result['processed_text'] = None
            result['applied_actions'].append(f"BLOCKED: {violation.message}")
            
        elif violation.action == PolicyAction.WARN:
            result['warnings'].append(violation.message)
            result['applied_actions'].append(f"WARNING: {violation.message}")
            
        elif violation.action == PolicyAction.REDACT:
            # Redact the matched content
            if violation.matched_keyword and violation.matched_keyword.startswith('pattern:'):
                # Handle regex patterns
                pattern = violation.matched_keyword.replace('pattern: ', '')
                result['processed_text'] = re.sub(
                    pattern, 
                    '[POLICY-REDACTED]', 
                    result['processed_text'],
                    flags=re.IGNORECASE
                )
            else:
                # Handle keywords
                result['processed_text'] = result['processed_text'].replace(
                    violation.matched_keyword,
                    '[POLICY-REDACTED]'
                )
            result['applied_actions'].append(f"REDACTED: {violation.matched_keyword}")
    
    return result