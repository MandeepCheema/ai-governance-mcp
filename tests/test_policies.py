"""
Tests for policy enforcement
"""

import pytest
from ai_governance_mcp.policies import (
    check_policies, should_block, get_policy_summary, 
    apply_policy_actions, PolicyAction, PolicyViolation
)

class TestPolicyDetection:
    """Test policy detection functionality"""
    
    def test_medical_advice_detection(self):
        """Test medical advice policy detection"""
        texts = [
            "What medication should I take for headache?",
            "Can you diagnose my symptoms?",
            "I need medical advice for my condition",
            "Please prescribe something for pain"
        ]
        
        for text in texts:
            violations = check_policies(text)
            assert len(violations) > 0
            assert any(v.category == 'medical' for v in violations)
            assert any(v.action == PolicyAction.BLOCK for v in violations)
    
    def test_legal_advice_detection(self):
        """Test legal advice policy detection"""
        texts = [
            "Should I sue my employer?",
            "I need legal advice about my contract",
            "Can you review this legal document?",
            "What are my legal rights in this case?"
        ]
        
        for text in texts:
            violations = check_policies(text)
            assert len(violations) > 0
            assert any(v.category == 'legal' for v in violations)
    
    def test_financial_advice_detection(self):
        """Test financial advice policy detection"""
        texts = [
            "Should I buy this stock?",
            "Give me investment advice",
            "What's your trading strategy?",
            "Best stocks to invest in now"
        ]
        
        for text in texts:
            violations = check_policies(text)
            assert len(violations) > 0
            assert any(v.category == 'financial' for v in violations)
            assert any(v.action == PolicyAction.WARN for v in violations)
    
    def test_harmful_content_detection(self):
        """Test harmful content detection"""
        text = "How to make explosives"
        violations = check_policies(text)
        
        assert len(violations) > 0
        assert any(v.category == 'safety' for v in violations)
        assert any(v.severity == 'critical' for v in violations)
    
    def test_no_violations(self):
        """Test text with no policy violations"""
        safe_texts = [
            "What's the weather today?",
            "Can you help me write a Python script?",
            "Explain quantum computing",
            "Tell me about machine learning"
        ]
        
        for text in safe_texts:
            violations = check_policies(text)
            assert len(violations) == 0
    
    def test_multiple_violations(self):
        """Test detection of multiple policy violations"""
        text = "I need medical advice and legal counsel about malpractice"
        violations = check_policies(text)
        
        assert len(violations) >= 2
        categories = {v.category for v in violations}
        assert 'medical' in categories
        assert 'legal' in categories
    
    def test_case_insensitive(self):
        """Test case insensitive detection"""
        texts = [
            "MEDICAL ADVICE needed",
            "Medical Advice NEEDED",
            "mEdIcAl AdViCe needed"
        ]
        
        for text in texts:
            violations = check_policies(text)
            assert len(violations) > 0

class TestPolicyActions:
    """Test policy action application"""
    
    def test_should_block(self):
        """Test blocking logic"""
        # Create violations with different actions
        violations = [
            PolicyViolation(
                policy_name="test1",
                category="test",
                matched_keyword="test",
                action=PolicyAction.WARN,
                message="Warning",
                severity="low"
            ),
            PolicyViolation(
                policy_name="test2",
                category="test",
                matched_keyword="test",
                action=PolicyAction.BLOCK,
                message="Blocked",
                severity="high"
            )
        ]
        
        assert should_block(violations) == True
        assert should_block([violations[0]]) == False
    
    def test_policy_summary(self):
        """Test policy summary generation"""
        violations = check_policies("I need medical advice and investment tips")
        summary = get_policy_summary(violations)
        
        assert summary['total_violations'] >= 2
        assert summary['should_block'] == True
        assert 'medical' in summary['by_category']
        assert 'financial' in summary['by_category']
        assert len(summary['messages']) >= 2
    
    def test_apply_policy_actions(self):
        """Test applying policy actions to text"""
        text = "This contains confidential information"
        violations = check_policies(text)
        
        result = apply_policy_actions(text, violations)
        
        assert result['original_text'] == text
        assert len(result['warnings']) > 0
        assert not result['blocked']  # Confidential is a warning, not block
    
    def test_apply_blocking_action(self):
        """Test applying blocking action"""
        text = "Please diagnose my symptoms"
        violations = check_policies(text)
        
        result = apply_policy_actions(text, violations)
        
        assert result['blocked'] == True
        assert result['processed_text'] is None
        assert any('BLOCKED' in action for action in result['applied_actions'])

class TestCustomPolicies:
    """Test custom policy functionality"""
    
    def test_custom_policy(self):
        """Test adding custom policies"""
        custom_policies = {
            'company_secret': {
                'category': 'confidential',
                'keywords': ['project phoenix', 'operation umbrella'],
                'action': PolicyAction.BLOCK,
                'message': 'Company secrets detected',
                'severity': 'critical'
            }
        }
        
        text = "Details about Project Phoenix are confidential"
        violations = check_policies(text, custom_policies=custom_policies)
        
        assert len(violations) > 0
        assert any(v.policy_name == 'company_secret' for v in violations)
    
    def test_extended_policies(self):
        """Test extended policy set"""
        text = "Looking for competitor pricing information"
        
        # Without extended
        violations_basic = check_policies(text, extended=False)
        
        # With extended
        violations_extended = check_policies(text, extended=True)
        
        assert len(violations_extended) >= len(violations_basic)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])