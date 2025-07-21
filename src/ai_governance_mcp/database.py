"""
Database and Audit Logging
"""

import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import threading
import os

class GovernanceDatabase:
    """SQLite database for audit logging with hash chain integrity"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to user's home directory
            home = Path.home()
            db_dir = home / '.ai_governance_mcp'
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / 'governance.db')
        
        self.db_path = db_path
        self.lock = threading.Lock()
        self._connection = None
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
            conn.execute("PRAGMA busy_timeout=5000")  # Wait up to 5 seconds for locks
            cursor = conn.cursor()
            
            # Main audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    original_text TEXT,
                    redacted_text TEXT,
                    pii_detected TEXT,
                    policy_violations TEXT,
                    action_taken TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    metadata TEXT,
                    hash TEXT NOT NULL,
                    prev_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON audit_log(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_event_type 
                ON audit_log(event_type)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_hash 
                ON audit_log(hash)
            ''')
            
            # Statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    total_scans INTEGER DEFAULT 0,
                    pii_detections INTEGER DEFAULT 0,
                    policy_violations INTEGER DEFAULT 0,
                    blocked_prompts INTEGER DEFAULT 0,
                    unique_users INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(date)
                )
            ''')
            
            # Configuration table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
    
    def calculate_hash(self, data: Dict[str, Any], prev_hash: str) -> str:
        """Calculate SHA256 hash for audit entry"""
        # Create deterministic string representation
        hash_data = {
            'timestamp': data.get('timestamp'),
            'event_type': data.get('event_type'),
            'original_text': data.get('original_text'),
            'action_taken': data.get('action_taken'),
            'prev_hash': prev_hash
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def add_audit_entry(self, entry: Dict[str, Any]) -> str:
        """Add audit log entry with hash chain"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            cursor = conn.cursor()
            
            # Get previous hash
            cursor.execute('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1')
            prev_hash_row = cursor.fetchone()
            prev_hash = prev_hash_row[0] if prev_hash_row else "genesis"
            
            # Calculate hash
            entry_hash = self.calculate_hash(entry, prev_hash)
            
            # Prepare data
            pii_json = json.dumps(entry.get('pii_detected', []))
            violations_json = json.dumps(entry.get('policy_violations', []))
            metadata_json = json.dumps(entry.get('metadata', {}))
            
            cursor.execute('''
                INSERT INTO audit_log (
                    timestamp, event_type, original_text, redacted_text,
                    pii_detected, policy_violations, action_taken,
                    user_id, session_id, metadata, hash, prev_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.get('timestamp', datetime.now().isoformat()),
                entry.get('event_type', 'scan'),
                entry.get('original_text'),
                entry.get('redacted_text'),
                pii_json,
                violations_json,
                entry.get('action_taken', 'allowed'),
                entry.get('user_id'),
                entry.get('session_id'),
                metadata_json,
                entry_hash,
                prev_hash
            ))
            
            # Update statistics
            self._update_statistics(entry)
            
            conn.commit()
            conn.close()
            
            return entry_hash
    
    def _update_statistics(self, entry: Dict[str, Any]):
        """Update daily statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        today = datetime.now().date().isoformat()
        
        # Get current stats
        cursor.execute('SELECT * FROM statistics WHERE date = ?', (today,))
        stats = cursor.fetchone()
        
        if stats:
            # Update existing
            cursor.execute('''
                UPDATE statistics SET
                    total_scans = total_scans + 1,
                    pii_detections = pii_detections + ?,
                    policy_violations = policy_violations + ?,
                    blocked_prompts = blocked_prompts + ?
                WHERE date = ?
            ''', (
                len(entry.get('pii_detected', [])),
                len(entry.get('policy_violations', [])),
                1 if entry.get('action_taken') == 'blocked' else 0,
                today
            ))
        else:
            # Insert new
            cursor.execute('''
                INSERT INTO statistics (
                    date, total_scans, pii_detections, 
                    policy_violations, blocked_prompts
                ) VALUES (?, 1, ?, ?, ?)
            ''', (
                today,
                len(entry.get('pii_detected', [])),
                len(entry.get('policy_violations', [])),
                1 if entry.get('action_taken') == 'blocked' else 0
            ))
        
        conn.commit()
    
    def get_audit_logs(
        self, 
        limit: int = 100,
        offset: int = 0,
        filters: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve audit logs with optional filtering"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM audit_log'
            params = []
            
            if filters:
                conditions = []
                
                if 'start_date' in filters:
                    conditions.append('timestamp >= ?')
                    params.append(filters['start_date'])
                
                if 'end_date' in filters:
                    conditions.append('timestamp <= ?')
                    params.append(filters['end_date'])
                
                if 'event_type' in filters:
                    conditions.append('event_type = ?')
                    params.append(filters['event_type'])
                
                if 'action_taken' in filters:
                    conditions.append('action_taken = ?')
                    params.append(filters['action_taken'])
                
                if conditions:
                    query += ' WHERE ' + ' AND '.join(conditions)
            
            query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                log = dict(row)
                # Parse JSON fields
                log['pii_detected'] = json.loads(log['pii_detected'])
                log['policy_violations'] = json.loads(log['policy_violations'])
                log['metadata'] = json.loads(log['metadata'])
                logs.append(log)
            
            conn.close()
            return logs
    
    def verify_hash_chain(self, limit: int = None) -> Dict[str, Any]:
        """Verify the integrity of the hash chain"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            query = 'SELECT * FROM audit_log ORDER BY id'
            if limit:
                query += f' LIMIT {limit}'
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            valid = True
            invalid_entries = []
            prev_hash = "genesis"
            
            for row in rows:
                # Recalculate hash
                entry_data = {
                    'timestamp': row[1],
                    'event_type': row[2],
                    'original_text': row[3],
                    'action_taken': row[7]
                }
                
                expected_hash = self.calculate_hash(entry_data, prev_hash)
                actual_hash = row[11]  # hash column
                
                if expected_hash != actual_hash:
                    valid = False
                    invalid_entries.append({
                        'id': row[0],
                        'expected_hash': expected_hash,
                        'actual_hash': actual_hash
                    })
                
                prev_hash = actual_hash
            
            conn.close()
            
            return {
                'valid': valid,
                'entries_checked': len(rows),
                'invalid_entries': invalid_entries,
                'message': 'Hash chain is intact' if valid else f'Found {len(invalid_entries)} invalid entries'
            }
    
    def get_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get statistics for the last N days"""
        with self.lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.cursor()
            
            # Get date range
            from datetime import timedelta
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days-1)
            
            cursor.execute('''
                SELECT 
                    SUM(total_scans) as total_scans,
                    SUM(pii_detections) as total_pii,
                    SUM(policy_violations) as total_violations,
                    SUM(blocked_prompts) as total_blocked,
                    COUNT(DISTINCT date) as days_active
                FROM statistics
                WHERE date >= ? AND date <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            
            stats = cursor.fetchone()
            
            # Get daily breakdown
            cursor.execute('''
                SELECT date, total_scans, pii_detections, 
                       policy_violations, blocked_prompts
                FROM statistics
                WHERE date >= ? AND date <= ?
                ORDER BY date DESC
            ''', (start_date.isoformat(), end_date.isoformat()))
            
            daily_stats = []
            for row in cursor.fetchall():
                daily_stats.append({
                    'date': row[0],
                    'scans': row[1],
                    'pii': row[2],
                    'violations': row[3],
                    'blocked': row[4]
                })
            
            conn.close()
            
            return {
                'summary': {
                    'total_scans': stats[0] or 0,
                    'total_pii_detections': stats[1] or 0,
                    'total_policy_violations': stats[2] or 0,
                    'total_blocked': stats[3] or 0,
                    'days_active': stats[4] or 0
                },
                'daily_breakdown': daily_stats,
                'period': f'Last {days} days'
            }
    
    def export_logs(self, format: str = 'json', filters: Dict[str, Any] = None) -> str:
        """Export audit logs in various formats"""
        logs = self.get_audit_logs(limit=10000, filters=filters)
        
        if format == 'json':
            return json.dumps(logs, indent=2)
        
        elif format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            
            if logs:
                fieldnames = [
                    'id', 'timestamp', 'event_type', 'action_taken',
                    'pii_count', 'violation_count', 'hash'
                ]
                
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for log in logs:
                    writer.writerow({
                        'id': log['id'],
                        'timestamp': log['timestamp'],
                        'event_type': log['event_type'],
                        'action_taken': log['action_taken'],
                        'pii_count': len(log['pii_detected']),
                        'violation_count': len(log['policy_violations']),
                        'hash': log['hash']
                    })
            
            return output.getvalue()
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def cleanup_old_logs(self, days_to_keep: int = 90):
        """Remove logs older than specified days"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            cursor.execute('DELETE FROM audit_log WHERE timestamp < ?', (cutoff_date,))
            deleted = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return deleted