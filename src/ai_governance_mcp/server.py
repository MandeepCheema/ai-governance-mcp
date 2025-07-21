#!/usr/bin/env python3
"""
AI Governance MCP Server
Main server implementation
"""

import asyncio
import json
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from .patterns import detect_pii, redact_pii, get_pii_summary
from .policies import check_policies, should_block, get_policy_summary, apply_policy_actions
from .database import GovernanceDatabase
from .utils import generate_session_id, format_response

class AIGovernanceMCP:
    """MCP Server for AI Governance"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.server = Server("ai-governance")
        self.db = GovernanceDatabase()
        self.config = config or self._default_config()
        self.session_id = generate_session_id()
        self.setup_handlers()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'pii_detection_enabled': True,
            'policy_enforcement_enabled': True,
            'audit_logging_enabled': True,
            'auto_redact': True,
            'extended_patterns': False,
            'extended_policies': False,
            'redaction_style': '[REDACTED]',
            'max_prompt_length': 10000,
            'rate_limit': {
                'enabled': False,
                'max_per_minute': 60
            }
        }
    
    def setup_handlers(self):
        """Setup all MCP handlers"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> List[types.Resource]:
            """List available resources"""
            return [
                types.Resource(
                    uri="governance://audit-logs",
                    name="Audit Logs",
                    description="View complete audit trail of all processed prompts",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="governance://statistics",
                    name="Statistics Dashboard",
                    description="Governance statistics and metrics",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="governance://configuration",
                    name="Current Configuration",
                    description="View and manage governance settings",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="governance://patterns",
                    name="PII Patterns",
                    description="List of active PII detection patterns",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="governance://policies",
                    name="Policy Rules",
                    description="List of active policy rules",
                    mimeType="application/json"
                )
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read resource content"""
            if uri == "governance://audit-logs":
                logs = self.db.get_audit_logs(limit=50)
                return json.dumps({
                    'logs': logs,
                    'total_count': len(logs),
                    'exported_at': datetime.now().isoformat()
                }, indent=2)
            
            elif uri == "governance://statistics":
                stats = self.db.get_statistics(days=30)
                return json.dumps(stats, indent=2)
            
            elif uri == "governance://configuration":
                return json.dumps(self.config, indent=2)
            
            elif uri == "governance://patterns":
                from .patterns import PII_PATTERNS, EXTENDED_PATTERNS
                patterns = PII_PATTERNS.copy()
                if self.config.get('extended_patterns'):
                    patterns.update(EXTENDED_PATTERNS)
                
                return json.dumps({
                    'patterns': patterns,
                    'total_count': len(patterns),
                    'extended_enabled': self.config.get('extended_patterns', False)
                }, indent=2)
            
            elif uri == "governance://policies":
                from .policies import POLICY_RULES, EXTENDED_POLICIES
                policies = POLICY_RULES.copy()
                if self.config.get('extended_policies'):
                    policies.update(EXTENDED_POLICIES)
                
                return json.dumps({
                    'policies': policies,
                    'total_count': len(policies),
                    'extended_enabled': self.config.get('extended_policies', False)
                }, indent=2)
            
            else:
                raise ValueError(f"Unknown resource: {uri}")
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """List available tools"""
            return [
                types.Tool(
                    name="scan_prompt",
                    description="Scan text for PII and policy violations before sending to LLM",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "prompt": {
                                "type": "string",
                                "description": "The text to scan for PII and policy violations"
                            },
                            "auto_redact": {
                                "type": "boolean",
                                "description": "Automatically redact detected PII",
                                "default": True
                            },
                            "context": {
                                "type": "object",
                                "description": "Optional context (user_id, metadata)",
                                "default": {}
                            }
                        },
                        "required": ["prompt"]
                    }
                ),
                types.Tool(
                    name="check_compliance",
                    description="Quick compliance check without logging",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to check for compliance"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                types.Tool(
                    name="redact_pii",
                    description="Redact PII from text",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text containing PII to redact"
                            },
                            "style": {
                                "type": "string",
                                "description": "Redaction style",
                                "enum": ["[REDACTED]", "[REDACTED-TYPE]", "[REDACTED-XXX]"],
                                "default": "[REDACTED]"
                            }
                        },
                        "required": ["text"]
                    }
                ),
                types.Tool(
                    name="get_statistics",
                    description="Get governance statistics",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "days": {
                                "type": "integer",
                                "description": "Number of days to include",
                                "default": 7,
                                "minimum": 1,
                                "maximum": 365
                            }
                        }
                    }
                ),
                types.Tool(
                    name="export_audit_logs",
                    description="Export audit logs for compliance reporting",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "format": {
                                "type": "string",
                                "description": "Export format",
                                "enum": ["json", "csv"],
                                "default": "json"
                            },
                            "start_date": {
                                "type": "string",
                                "description": "Start date (ISO format)"
                            },
                            "end_date": {
                                "type": "string",
                                "description": "End date (ISO format)"
                            }
                        }
                    }
                ),
                types.Tool(
                    name="verify_integrity",
                    description="Verify audit log hash chain integrity",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Number of entries to verify",
                                "default": 100
                            }
                        }
                    }
                ),
                types.Tool(
                    name="configure",
                    description="Update governance configuration",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "pii_detection_enabled": {"type": "boolean"},
                            "policy_enforcement_enabled": {"type": "boolean"},
                            "audit_logging_enabled": {"type": "boolean"},
                            "auto_redact": {"type": "boolean"},
                            "extended_patterns": {"type": "boolean"},
                            "extended_policies": {"type": "boolean"},
                            "redaction_style": {
                                "type": "string",
                                "enum": ["[REDACTED]", "[REDACTED-TYPE]", "[REDACTED-XXX]"]
                            }
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str, 
            arguments: Dict[str, Any]
        ) -> List[types.TextContent]:
            """Handle tool calls"""
            
            try:
                if name == "scan_prompt":
                    result = await self._scan_prompt(arguments)
                
                elif name == "check_compliance":
                    result = await self._check_compliance(arguments)
                
                elif name == "redact_pii":
                    result = await self._redact_pii(arguments)
                
                elif name == "get_statistics":
                    result = await self._get_statistics(arguments)
                
                elif name == "export_audit_logs":
                    result = await self._export_audit_logs(arguments)
                
                elif name == "verify_integrity":
                    result = await self._verify_integrity(arguments)
                
                elif name == "configure":
                    result = await self._configure(arguments)
                
                else:
                    raise ValueError(f"Unknown tool: {name}")
                
                return [types.TextContent(
                    type="text",
                    text=format_response(result)
                )]
                
            except Exception as e:
                error_result = {
                    'error': str(e),
                    'tool': name,
                    'timestamp': datetime.now().isoformat()
                }
                return [types.TextContent(
                    type="text",
                    text=json.dumps(error_result, indent=2)
                )]
    
    async def _scan_prompt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Scan prompt for PII and policy violations"""
        prompt = args.get('prompt', '')
        auto_redact = args.get('auto_redact', self.config.get('auto_redact', True))
        context = args.get('context', {})
        
        # Check length
        if len(prompt) > self.config.get('max_prompt_length', 10000):
            return {
                'error': 'Prompt exceeds maximum length',
                'max_length': self.config.get('max_prompt_length')
            }
        
        # Detect PII
        pii_matches = []
        if self.config.get('pii_detection_enabled', True):
            pii_matches = detect_pii(
                prompt, 
                extended=self.config.get('extended_patterns', False)
            )
        
        # Check policies
        policy_violations = []
        if self.config.get('policy_enforcement_enabled', True):
            policy_violations = check_policies(
                prompt,
                extended=self.config.get('extended_policies', False)
            )
        
        # Apply redaction if needed
        redacted_prompt = prompt
        if auto_redact and pii_matches:
            redacted_prompt = redact_pii(
                prompt, 
                pii_matches,
                self.config.get('redaction_style', '[REDACTED]')
            )
        
        # Determine action
        action = 'allowed'
        if should_block(policy_violations):
            action = 'blocked'
        elif policy_violations:
            action = 'warned'
        
        # Create response
        result = {
            'original_prompt': prompt,
            'redacted_prompt': redacted_prompt if action != 'blocked' else None,
            'pii_detected': [
                {
                    'type': match.type,
                    'name': match.name,
                    'severity': match.severity
                } for match in pii_matches
            ],
            'policy_violations': [
                {
                    'policy': v.policy_name,
                    'category': v.category,
                    'action': v.action.value,
                    'message': v.message
                } for v in policy_violations
            ],
            'action': action,
            'safe_to_send': action != 'blocked',
            'summaries': {
                'pii': get_pii_summary(pii_matches),
                'policy': get_policy_summary(policy_violations)
            }
        }
        
        # Log if enabled
        if self.config.get('audit_logging_enabled', True):
            audit_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'scan',
                'original_text': prompt,
                'redacted_text': redacted_prompt,
                'pii_detected': result['pii_detected'],
                'policy_violations': result['policy_violations'],
                'action_taken': action,
                'user_id': context.get('user_id'),
                'session_id': self.session_id,
                'metadata': context
            }
            
            entry_hash = self.db.add_audit_entry(audit_entry)
            result['audit_hash'] = entry_hash
        
        return result
    
    async def _check_compliance(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Quick compliance check without logging"""
        text = args.get('text', '')
        
        pii_matches = detect_pii(text, extended=self.config.get('extended_patterns', False))
        policy_violations = check_policies(text, extended=self.config.get('extended_policies', False))
        
        return {
            'compliant': len(pii_matches) == 0 and len(policy_violations) == 0,
            'issues': {
                'pii': get_pii_summary(pii_matches),
                'policy': get_policy_summary(policy_violations)
            },
            'recommendation': 'Safe to send' if len(pii_matches) == 0 and len(policy_violations) == 0 else 'Review and remediate issues'
        }
    
    async def _redact_pii(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Redact PII from text"""
        text = args.get('text', '')
        style = args.get('style', self.config.get('redaction_style', '[REDACTED]'))
        
        pii_matches = detect_pii(text, extended=self.config.get('extended_patterns', False))
        redacted = redact_pii(text, pii_matches, style)
        
        return {
            'original': text,
            'redacted': redacted,
            'pii_found': len(pii_matches),
            'pii_types': list(set(m.type for m in pii_matches))
        }
    
    async def _get_statistics(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get governance statistics"""
        days = args.get('days', 7)
        return self.db.get_statistics(days=days)
    
    async def _export_audit_logs(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export audit logs"""
        format_type = args.get('format', 'json')
        filters = {}
        
        if 'start_date' in args:
            filters['start_date'] = args['start_date']
        if 'end_date' in args:
            filters['end_date'] = args['end_date']
        
        export_data = self.db.export_logs(format=format_type, filters=filters)
        
        return {
            'format': format_type,
            'data': export_data,
            'exported_at': datetime.now().isoformat()
        }
    
    async def _verify_integrity(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Verify audit log integrity"""
        limit = args.get('limit', 100)
        return self.db.verify_hash_chain(limit=limit)
    
    async def _configure(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Update configuration"""
        for key, value in args.items():
            if key in self.config:
                self.config[key] = value
        
        return {
            'status': 'updated',
            'configuration': self.config
        }
    
    async def run(self):
        """Run the MCP server"""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="AI Governance",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

async def main():
    """Main entry point"""
    print("Starting AI Governance MCP Server...", file=sys.stderr)
    server = AIGovernanceMCP()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())