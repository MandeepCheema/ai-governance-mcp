"""
Utility functions for AI Governance MCP
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict

def generate_session_id() -> str:
    """Generate unique session ID"""
    return f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

def format_response(data: Any) -> str:
    """Format response data as pretty JSON"""
    if isinstance(data, str):
        return data
    
    return json.dumps(data, indent=2, sort_keys=True, default=str)

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def calculate_risk_score(pii_matches: list, policy_violations: list) -> Dict[str, Any]:
    """Calculate overall risk score"""
    # Base scores
    pii_score = 0
    policy_score = 0
    
    # PII scoring
    severity_scores = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
    for match in pii_matches:
        pii_score += severity_scores.get(match.get('severity', 'medium'), 4)
    
    # Policy scoring
    action_scores = {'block': 10, 'warn': 5, 'allow': 0}
    for violation in policy_violations:
        policy_score += action_scores.get(violation.get('action', 'warn'), 5)
    
    # Total score (0-100)
    total_score = min(pii_score + policy_score, 100)
    
    # Risk level
    if total_score >= 70:
        risk_level = 'critical'
    elif total_score >= 40:
        risk_level = 'high'
    elif total_score >= 20:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'score': total_score,
        'level': risk_level,
        'pii_score': pii_score,
        'policy_score': policy_score,
        'recommendation': get_risk_recommendation(risk_level)
    }

def get_risk_recommendation(risk_level: str) -> str:
    """Get recommendation based on risk level"""
    recommendations = {
        'critical': 'Do not send. Multiple critical issues detected.',
        'high': 'Review and remediate before sending.',
        'medium': 'Consider reviewing sensitive information.',
        'low': 'Generally safe to send.'
    }
    return recommendations.get(risk_level, 'Review before sending.')

def sanitize_for_logging(text: str, max_length: int = 500) -> str:
    """Sanitize text for safe logging"""
    # Remove control characters
    sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
    
    # Truncate if needed
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '... [truncated]'
    
    return sanitized

def merge_configs(base_config: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """Merge configuration updates"""
    merged = base_config.copy()
    
    for key, value in updates.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key] = merge_configs(merged[key], value)
        else:
            merged[key] = value
    
    return merged