"""
Database module for ScamShield
Handles SQLite database operations for storing analysis history
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import os


class Database:
    """Database handler for ScamShield system"""
    
    def __init__(self, db_path: str = "scamshield.db"):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path)
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Create call analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS call_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT,
                duration INTEGER,
                call_frequency INTEGER,
                is_unknown INTEGER,
                is_international INTEGER,
                risk_score REAL,
                risk_level TEXT,
                is_scam INTEGER,
                timestamp TEXT,
                features TEXT
            )
        ''')
        
        # Create SMS analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                message_text TEXT,
                has_url INTEGER,
                urls TEXT,
                risk_score REAL,
                risk_level TEXT,
                is_scam INTEGER,
                timestamp TEXT,
                features TEXT
            )
        ''')
        
        # Create risk statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_type TEXT,
                total_analyzed INTEGER,
                scam_detected INTEGER,
                date TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_call_analysis(self, data: Dict[str, Any]) -> int:
        """
        Save call analysis result to database
        
        Args:
            data: Analysis data dictionary
            
        Returns:
            ID of inserted record
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO call_analysis 
            (phone_number, duration, call_frequency, is_unknown, is_international,
             risk_score, risk_level, is_scam, timestamp, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('phone_number'),
            data.get('duration'),
            data.get('call_frequency'),
            data.get('is_unknown', 0),
            data.get('is_international', 0),
            data.get('risk_score'),
            data.get('risk_level'),
            data.get('is_scam', 0),
            datetime.now().isoformat(),
            json.dumps(data.get('features', {}))
        ))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.update_statistics('call', data.get('is_scam', 0))
        return record_id
    
    def save_sms_analysis(self, data: Dict[str, Any]) -> int:
        """
        Save SMS analysis result to database
        
        Args:
            data: Analysis data dictionary
            
        Returns:
            ID of inserted record
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sms_analysis 
            (sender, message_text, has_url, urls, risk_score, risk_level, 
             is_scam, timestamp, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('sender'),
            data.get('message_text'),
            data.get('has_url', 0),
            json.dumps(data.get('urls', [])),
            data.get('risk_score'),
            data.get('risk_level'),
            data.get('is_scam', 0),
            datetime.now().isoformat(),
            json.dumps(data.get('features', {}))
        ))
        
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        self.update_statistics('sms', data.get('is_scam', 0))
        return record_id
    
    def update_statistics(self, analysis_type: str, is_scam: int):
        """
        Update risk statistics
        
        Args:
            analysis_type: Type of analysis (call/sms)
            is_scam: 1 if scam detected, 0 otherwise
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        today = datetime.now().date().isoformat()
        
        # Check if record exists for today
        cursor.execute('''
            SELECT id, total_analyzed, scam_detected 
            FROM risk_statistics 
            WHERE analysis_type = ? AND date = ?
        ''', (analysis_type, today))
        
        result = cursor.fetchone()
        
        if result:
            # Update existing record
            cursor.execute('''
                UPDATE risk_statistics 
                SET total_analyzed = total_analyzed + 1,
                    scam_detected = scam_detected + ?
                WHERE id = ?
            ''', (is_scam, result[0]))
        else:
            # Create new record
            cursor.execute('''
                INSERT INTO risk_statistics 
                (analysis_type, total_analyzed, scam_detected, date)
                VALUES (?, 1, ?, ?)
            ''', (analysis_type, is_scam, today))
        
        conn.commit()
        conn.close()
    
    def get_recent_analyses(self, analysis_type: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent analysis records
        
        Args:
            analysis_type: Type of analysis (call/sms)
            limit: Number of records to retrieve
            
        Returns:
            List of analysis records
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if analysis_type == 'call':
            cursor.execute('''
                SELECT * FROM call_analysis 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = ['id', 'phone_number', 'duration', 'call_frequency', 
                      'is_unknown', 'is_international', 'risk_score', 
                      'risk_level', 'is_scam', 'timestamp', 'features']
        else:
            cursor.execute('''
                SELECT * FROM sms_analysis 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = ['id', 'sender', 'message_text', 'has_url', 'urls',
                      'risk_score', 'risk_level', 'is_scam', 'timestamp', 'features']
        
        rows = cursor.fetchall()
        conn.close()
        
        results = []
        for row in rows:
            record = dict(zip(columns, row))
            # Parse JSON fields
            if 'features' in record:
                record['features'] = json.loads(record['features'])
            if 'urls' in record and isinstance(record['urls'], str):
                record['urls'] = json.loads(record['urls'])
            results.append(record)
        
        return results
    
    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        Get statistics for the past N days
        
        Args:
            days: Number of days to look back
            
        Returns:
            Statistics dictionary
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT analysis_type, 
                   SUM(total_analyzed) as total,
                   SUM(scam_detected) as scams
            FROM risk_statistics 
            WHERE date >= date('now', '-' || ? || ' days')
            GROUP BY analysis_type
        ''', (days,))
        
        stats = {}
        for row in cursor.fetchall():
            analysis_type, total, scams = row
            stats[analysis_type] = {
                'total': total,
                'scams': scams,
                'safe': total - scams,
                'scam_rate': (scams / total * 100) if total > 0 else 0
            }
        
        conn.close()
        return stats
    
    def get_risk_distribution(self) -> Dict[str, int]:
        """
        Get distribution of risk levels
        
        Returns:
            Dictionary with risk level counts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        # Get call distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count
            FROM call_analysis
            GROUP BY risk_level
        ''')
        
        for row in cursor.fetchall():
            if row[0] in distribution:
                distribution[row[0]] += row[1]
        
        # Get SMS distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) as count
            FROM sms_analysis
            GROUP BY risk_level
        ''')
        
        for row in cursor.fetchall():
            if row[0] in distribution:
                distribution[row[0]] += row[1]
        
        conn.close()
        return distribution
    
    def clear_old_records(self, days: int = 30):
        """
        Clear records older than specified days
        
        Args:
            days: Number of days to keep
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM call_analysis 
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        
        cursor.execute('''
            DELETE FROM sms_analysis 
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        
        conn.commit()
        conn.close()
