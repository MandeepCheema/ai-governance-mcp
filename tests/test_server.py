"""
Tests for MCP server functionality
"""

import pytest
import asyncio
import json
from datetime import datetime
from ai_governance_mcp.server import AIGovernanceMCP
from ai_governance_mcp.database import GovernanceDatabase

class TestMCPServer:
    """Test MCP server functionality"""
    
    @pytest.fixture
    async def server(self, tmp_path):
        """Create test server instance"""
        config = {
            'pii_detection_enabled': True,
            'policy_enforcement_enabled': True,
            'audit_logging_enabled': True,
            'auto_redact': True
        }
        
        # Use temporary database
        db_path = str(tmp_path / "test_governance.db")
        server = AIGovernanceMCP(config)
        server.db = GovernanceDatabase(db_path)
        
        return server
    
    @pytest.mark.asyncio
    async def test_scan_prompt_clean(self, server):
        """Test scanning clean prompt"""
        args = {
            'prompt': 'What is the weather today?',
            'auto_redact': True
        }
        
        result = await server._scan_prompt(args)
        
        assert result['safe_to_send'] == True
        assert result['action'] == 'allowed'
        assert len(result['pii_detected']) == 0
        assert len(result['policy_violations']) == 0
    
    @pytest.mark.asyncio
    async def test_scan_prompt_with_pii(self, server):
        """Test scanning prompt with PII"""
        args = {
            'prompt': 'My email is john@example.com and SSN is 123-45-6789',
            'auto_redact': True
        }
        
        result = await server._scan_prompt(args)
        
        assert result['safe_to_send'] == True
        assert result['action'] == 'allowed'
        assert len(result['pii_detected']) > 0
        assert '[REDACTED]' in result['redacted_prompt']
        assert 'john@example.com' not in result['redacted_prompt']
    
    @pytest.mark.asyncio
    async def test_scan_prompt_with_policy_violation(self, server):
        """Test scanning prompt with policy violation"""
        args = {
            'prompt': 'I need medical advice for my symptoms',
            'auto_redact': True
        }
        
        result = await server._scan_prompt(args)
        
        assert result['safe_to_send'] == False
        assert result['action'] == 'blocked'
        assert len(result['policy_violations']) > 0
        assert result['redacted_prompt'] is None
    
    @pytest.mark.asyncio
    async def test_check_compliance(self, server):
        """Test compliance checking"""
        args = {
            'text': 'This is a safe text with no issues'
        }
        
        result = await server._check_compliance(args)
        
        assert result['compliant'] == True
        assert result['recommendation'] == 'Safe to send'
    
    @pytest.mark.asyncio
    async def test_redact_pii_tool(self, server):
        """Test PII redaction tool"""
        args = {
            'text': 'Contact john@example.com or 555-123-4567',
            'style': '[REDACTED-TYPE]'
        }
        
        result = await server._redact_pii(args)
        
        assert result['pii_found'] > 0
        assert '[REDACTED-EMAIL ADDRESS]' in result['redacted']
        assert 'john@example.com' not in result['redacted']
    
    @pytest.mark.asyncio
    async def test_audit_logging(self, server):
        """Test audit logging functionality"""
        # Submit a prompt
        args = {
            'prompt': 'Test prompt with john@example.com',
            'auto_redact': True,
            'context': {'user_id': 'test_user'}
        }
        
        result = await server._scan_prompt(args)
        assert 'audit_hash' in result
        
        # Check audit logs
        logs = server.db.get_audit_logs(limit=10)
        assert len(logs) > 0
        
        latest_log = logs[0]
        assert latest_log['original_text'] == args['prompt']
        assert latest_log['user_id'] == 'test_user'
        assert latest_log['hash'] == result['audit_hash']
    
    @pytest.mark.asyncio
    async def test_statistics(self, server):
        """Test statistics generation"""
        # Submit some prompts
        prompts = [
            'Clean prompt',
            'Email: test@example.com',
            'I need medical advice'
        ]
        
        for prompt in prompts:
            await server._scan_prompt({'prompt': prompt})
        
        # Get statistics
        result = await server._get_statistics({'days': 7})
        
        assert 'summary' in result
        assert result['summary']['total_scans'] >= 3
        assert result['summary']['total_pii_detections'] >= 1
        assert result['summary']['total_policy_violations'] >= 1
    
    @pytest.mark.asyncio
    async def test_configuration_update(self, server):
        """Test configuration updates"""
        args = {
            'auto_redact': False,
            'extended_patterns': True
        }
        
        result = await server._configure(args)
        
        assert result['status'] == 'updated'
        assert server.config['auto_redact'] == False
        assert server.config['extended_patterns'] == True
    
    @pytest.mark.asyncio
    async def test_verify_integrity(self, server):
        """Test hash chain integrity verification"""
        # Add some entries
        for i in range(5):
            await server._scan_prompt({'prompt': f'Test prompt {i}'})
        
        # Verify integrity
        result = await server._verify_integrity({'limit': 10})
        
        assert result['valid'] == True
        assert result['entries_checked'] >= 5
        assert len(result['invalid_entries']) == 0
    
    @pytest.mark.asyncio
    async def test_export_logs(self, server):
        """Test log export functionality"""
        # Add some entries
        await server._scan_prompt({'prompt': 'Test for export'})
        
        # Export as JSON
        result = await server._export_audit_logs({'format': 'json'})
        
        assert result['format'] == 'json'
        assert 'data' in result
        
        # Verify JSON is valid
        logs = json.loads(result['data'])
        assert isinstance(logs, list)
        assert len(logs) > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, server):
        """Test rate limiting functionality"""
        # Enable rate limiting
        server.config['rate_limit'] = {
            'enabled': True,
            'max_per_minute': 2
        }
        
        # This is a placeholder for rate limiting logic
        # In production, you'd implement actual rate limiting
        assert server.config['rate_limit']['enabled'] == True

class TestDatabase:
    """Test database functionality"""
    
    def test_database_creation(self, tmp_path):
        """Test database creation"""
        db_path = str(tmp_path / "test.db")
        db = GovernanceDatabase(db_path)
        
        # Verify tables exist
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        assert 'audit_log' in tables
        assert 'statistics' in tables
        assert 'configuration' in tables
        
        conn.close()
    
    def test_hash_chain(self, tmp_path):
        """Test hash chain functionality"""
        db = GovernanceDatabase(str(tmp_path / "test.db"))
        
        # Add entries
        entries = []
        for i in range(3):
            entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'test',
                'original_text': f'Test {i}',
                'action_taken': 'allowed'
            }
            hash_val = db.add_audit_entry(entry)
            entries.append(hash_val)
        
        # Verify chain
        result = db.verify_hash_chain()
        assert result['valid'] == True
        
        # Get logs and verify hashes
        logs = db.get_audit_logs()
        assert len(logs) >= 3
        
        # Verify each entry links to previous
        for i in range(1, len(logs)):
            assert logs[i]['prev_hash'] == logs[i-1]['hash']

if __name__ == "__main__":
    pytest.main([__file__, "-v"])