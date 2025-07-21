"""
Tests for PII pattern detection
"""

import pytest
from ai_governance_mcp.patterns import detect_pii, redact_pii, validate_credit_card

class TestPIIDetection:
    """Test PII detection functionality"""
    
    def test_ssn_detection(self):
        """Test SSN detection"""
        text = "My SSN is 123-45-6789 and yours is 987-65-4321"
        matches = detect_pii(text)
        
        assert len(matches) == 2
        assert all(m.type == 'ssn' for m in matches)
        assert matches[0].value == "123-45-6789"
        assert matches[1].value == "987-65-4321"
    
    def test_email_detection(self):
        """Test email detection"""
        text = "Contact john@example.com or sarah.doe@company.co.uk"
        matches = detect_pii(text)
        
        assert len(matches) == 2
        assert all(m.type == 'email' for m in matches)
        assert matches[0].value == "john@example.com"
        assert matches[1].value == "sarah.doe@company.co.uk"
    
    def test_phone_detection(self):
        """Test phone number detection"""
        text = "Call me at 555-123-4567 or (555) 987-6543 or 5559876543"
        matches = detect_pii(text)
        
        assert len(matches) >= 2  # Different formats might match differently
        assert all(m.type == 'phone_us' for m in matches)
    
    def test_credit_card_detection(self):
        """Test credit card detection with validation"""
        # Valid credit card (passes Luhn)
        valid_cc = "4532-1488-0343-6467"
        text = f"Payment card: {valid_cc}"
        matches = detect_pii(text)
        
        assert len(matches) == 1
        assert matches[0].type == 'credit_card'
        
        # Invalid credit card (fails Luhn)
        invalid_cc = "1234-5678-9012-3456"
        text = f"Payment card: {invalid_cc}"
        matches = detect_pii(text)
        
        assert len(matches) == 0  # Should not match invalid cards
    
    def test_api_key_detection(self):
        """Test API key detection"""
        text = 'api_key="sk_test_abcdef123456789012345678" and token: ghp_1234567890abcdef'
        matches = detect_pii(text)
        
        assert len(matches) >= 1
        assert any(m.type in ['api_key_generic', 'github_token'] for m in matches)
    
    def test_aws_key_detection(self):
        """Test AWS key detection"""
        text = "AWS Access Key: AKIAIOSFODNN7EXAMPLE"
        matches = detect_pii(text)
        
        assert len(matches) == 1
        assert matches[0].type == 'aws_key'
        assert matches[0].severity == 'critical'
    
    def test_mixed_pii(self):
        """Test detection of multiple PII types"""
        text = """
        Contact John Doe at john@example.com or 555-123-4567.
        His SSN is 123-45-6789 and IP is 192.168.1.1
        """
        matches = detect_pii(text)
        
        pii_types = {m.type for m in matches}
        assert 'email' in pii_types
        assert 'phone_us' in pii_types
        assert 'ssn' in pii_types
        assert 'ip_address' in pii_types
    
    def test_no_pii(self):
        """Test text with no PII"""
        text = "This is a clean text with no sensitive information."
        matches = detect_pii(text)
        
        assert len(matches) == 0
    
    def test_extended_patterns(self):
        """Test extended pattern detection"""
        text = "Passport: AB1234567, IBAN: GB82WEST12345698765432"
        matches = detect_pii(text, extended=True)
        
        pii_types = {m.type for m in matches}
        assert 'passport' in pii_types
        assert 'iban' in pii_types

class TestPIIRedaction:
    """Test PII redaction functionality"""
    
    def test_basic_redaction(self):
        """Test basic redaction"""
        text = "Email: john@example.com, SSN: 123-45-6789"
        matches = detect_pii(text)
        redacted = redact_pii(text, matches)
        
        assert "john@example.com" not in redacted
        assert "123-45-6789" not in redacted
        assert "[REDACTED]" in redacted
    
    def test_redaction_styles(self):
        """Test different redaction styles"""
        text = "SSN: 123-45-6789"
        matches = detect_pii(text)
        
        # Default style
        redacted1 = redact_pii(text, matches)
        assert redacted1 == "SSN: [REDACTED]"
        
        # Type style
        redacted2 = redact_pii(text, matches, "[REDACTED-TYPE]")
        assert redacted2 == "SSN: [REDACTED-SOCIAL SECURITY NUMBER]"
        
        # Length-preserving style
        redacted3 = redact_pii(text, matches, "[REDACTED-XXX]")
        assert "[XXXXXXXXXXX]" in redacted3
    
    def test_overlapping_redaction(self):
        """Test handling of overlapping matches"""
        text = "Contact: john@example.com (john@example.com)"
        matches = detect_pii(text)
        redacted = redact_pii(text, matches)
        
        assert "john@example.com" not in redacted
        assert redacted.count("[REDACTED]") == 2
    
    def test_empty_redaction(self):
        """Test redaction with no matches"""
        text = "This has no PII"
        redacted = redact_pii(text, [])
        
        assert redacted == text

class TestCreditCardValidation:
    """Test credit card validation"""
    
    def test_valid_cards(self):
        """Test valid credit card numbers"""
        valid_cards = [
            "4532-1488-0343-6467",  # Visa
            "5425-2334-3010-9903",  # Mastercard
            "3714-4963-5398-431",   # Amex
        ]
        
        for card in valid_cards:
            assert validate_credit_card(card) == True
    
    def test_invalid_cards(self):
        """Test invalid credit card numbers"""
        invalid_cards = [
            "1234-5678-9012-3456",
            "0000-0000-0000-0000",
            "9999-9999-9999-9999",
        ]
        
        for card in invalid_cards:
            assert validate_credit_card(card) == False
    
    def test_formatting_variations(self):
        """Test credit card validation with different formats"""
        card_variations = [
            "4532148803436467",      # No separators
            "4532 1488 0343 6467",   # Spaces
            "4532-1488-0343-6467",   # Dashes
        ]
        
        for card in card_variations:
            assert validate_credit_card(card) == True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])