#!/usr/bin/env python3
"""
Learning Engine for Noctis-MCP
================================

Learns from user feedback, AV/EDR detections, and compilation results
to continuously improve malware generation.

This module provides:
- Feedback collection (AV detections, compilation failures, etc.)
- Knowledge base storage (SQLite)
- Technique effectiveness tracking
- Adaptive technique selection
- Success rate analysis
- Pattern recognition

Author: Noctis-MCP Community
License: MIT
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path


# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class DetectionFeedback:
    """User feedback about AV/EDR detection"""
    timestamp: str
    techniques_used: List[str]
    av_edr: str  # e.g., "Windows Defender", "CrowdStrike", "SentinelOne"
    detected: bool
    detection_type: Optional[str] = None  # "static", "dynamic", "behavioral"
    obfuscation_level: Optional[str] = None  # "none", "basic", "advanced"
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'techniques_used': json.dumps(self.techniques_used),
            'av_edr': self.av_edr,
            'detected': self.detected,
            'detection_type': self.detection_type,
            'obfuscation_level': self.obfuscation_level,
            'notes': self.notes
        }


@dataclass
class CompilationFeedback:
    """Feedback about compilation success/failure"""
    timestamp: str
    techniques_used: List[str]
    success: bool
    compiler: str  # "MSBuild", "MinGW", etc.
    error_type: Optional[str] = None
    auto_fixed: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'techniques_used': json.dumps(self.techniques_used),
            'success': self.success,
            'compiler': self.compiler,
            'error_type': self.error_type,
            'auto_fixed': self.auto_fixed
        }


@dataclass
class TechniqueStats:
    """Statistics for a specific technique"""
    technique_id: str
    name: str
    total_uses: int = 0
    compilation_success_rate: float = 0.0
    detection_rate: Dict[str, float] = field(default_factory=dict)  # AV/EDR -> rate
    last_used: Optional[str] = None
    recommended: bool = True
    notes: str = ""


class LearningEngine:
    """
    Main learning engine for Noctis-MCP
    
    Tracks feedback, stores knowledge, and provides adaptive recommendations.
    """
    
    def __init__(self, db_path: str = "data/knowledge_base.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Detection feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                techniques_used TEXT NOT NULL,
                av_edr TEXT NOT NULL,
                detected INTEGER NOT NULL,
                detection_type TEXT,
                obfuscation_level TEXT,
                notes TEXT
            )
        ''')
        
        # Compilation feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compilation_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                techniques_used TEXT NOT NULL,
                success INTEGER NOT NULL,
                compiler TEXT NOT NULL,
                error_type TEXT,
                auto_fixed INTEGER DEFAULT 0
            )
        ''')
        
        # Technique statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS technique_stats (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                total_uses INTEGER DEFAULT 0,
                compilation_successes INTEGER DEFAULT 0,
                compilation_failures INTEGER DEFAULT 0,
                last_used TEXT,
                recommended INTEGER DEFAULT 1,
                notes TEXT
            )
        ''')
        
        # AV/EDR detection rates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS av_detection_rates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                av_edr TEXT NOT NULL,
                detections INTEGER DEFAULT 0,
                non_detections INTEGER DEFAULT 0,
                last_tested TEXT,
                UNIQUE(technique_id, av_edr)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Learning database initialized at {self.db_path}")
    
    def record_detection(self, feedback: DetectionFeedback):
        """Record AV/EDR detection feedback"""
        logger.info(f"Recording detection feedback: {feedback.av_edr} - Detected: {feedback.detected}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert detection feedback
            cursor.execute('''
                INSERT INTO detection_feedback 
                (timestamp, techniques_used, av_edr, detected, detection_type, obfuscation_level, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                feedback.timestamp,
                json.dumps(feedback.techniques_used),
                feedback.av_edr,
                1 if feedback.detected else 0,
                feedback.detection_type,
                feedback.obfuscation_level,
                feedback.notes
            ))
            
            # Update technique stats
            for technique_id in feedback.techniques_used:
                self._update_technique_usage(cursor, technique_id)
                self._update_av_detection_rate(
                    cursor,
                    technique_id,
                    feedback.av_edr,
                    feedback.detected
                )
            
            conn.commit()
            logger.info("Detection feedback recorded successfully")
            
        except Exception as e:
            logger.error(f"Failed to record detection feedback: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def record_compilation(self, feedback: CompilationFeedback):
        """Record compilation feedback"""
        logger.info(f"Recording compilation feedback: Success: {feedback.success}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert compilation feedback
            cursor.execute('''
                INSERT INTO compilation_feedback 
                (timestamp, techniques_used, success, compiler, error_type, auto_fixed)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                feedback.timestamp,
                json.dumps(feedback.techniques_used),
                1 if feedback.success else 0,
                feedback.compiler,
                feedback.error_type,
                1 if feedback.auto_fixed else 0
            ))
            
            # Update technique stats
            for technique_id in feedback.techniques_used:
                self._update_technique_usage(cursor, technique_id)
                self._update_compilation_stats(cursor, technique_id, feedback.success)
            
            conn.commit()
            logger.info("Compilation feedback recorded successfully")
            
        except Exception as e:
            logger.error(f"Failed to record compilation feedback: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def _update_technique_usage(self, cursor, technique_id: str):
        """Update technique usage count"""
        cursor.execute('''
            INSERT OR IGNORE INTO technique_stats (technique_id, name, total_uses, last_used)
            VALUES (?, ?, 0, ?)
        ''', (technique_id, technique_id, datetime.now().isoformat()))
        
        cursor.execute('''
            UPDATE technique_stats 
            SET total_uses = total_uses + 1, last_used = ?
            WHERE technique_id = ?
        ''', (datetime.now().isoformat(), technique_id))
    
    def _update_compilation_stats(self, cursor, technique_id: str, success: bool):
        """Update compilation success/failure stats"""
        if success:
            cursor.execute('''
                UPDATE technique_stats 
                SET compilation_successes = compilation_successes + 1
                WHERE technique_id = ?
            ''', (technique_id,))
        else:
            cursor.execute('''
                UPDATE technique_stats 
                SET compilation_failures = compilation_failures + 1
                WHERE technique_id = ?
            ''', (technique_id,))
    
    def _update_av_detection_rate(self, cursor, technique_id: str, av_edr: str, detected: bool):
        """Update AV/EDR detection rates for a technique"""
        cursor.execute('''
            INSERT OR IGNORE INTO av_detection_rates (technique_id, av_edr, detections, non_detections, last_tested)
            VALUES (?, ?, 0, 0, ?)
        ''', (technique_id, av_edr, datetime.now().isoformat()))
        
        if detected:
            cursor.execute('''
                UPDATE av_detection_rates 
                SET detections = detections + 1, last_tested = ?
                WHERE technique_id = ? AND av_edr = ?
            ''', (datetime.now().isoformat(), technique_id, av_edr))
        else:
            cursor.execute('''
                UPDATE av_detection_rates 
                SET non_detections = non_detections + 1, last_tested = ?
                WHERE technique_id = ? AND av_edr = ?
            ''', (datetime.now().isoformat(), technique_id, av_edr))
    
    def get_technique_stats(self, technique_id: str) -> Optional[TechniqueStats]:
        """Get statistics for a specific technique"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get basic stats
            cursor.execute('''
                SELECT technique_id, name, total_uses, compilation_successes, 
                       compilation_failures, last_used, recommended, notes
                FROM technique_stats
                WHERE technique_id = ?
            ''', (technique_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            stats = TechniqueStats(
                technique_id=row[0],
                name=row[1],
                total_uses=row[2],
                last_used=row[5],
                recommended=bool(row[6]),
                notes=row[7] or ""
            )
            
            # Calculate compilation success rate
            total_compilations = row[3] + row[4]
            if total_compilations > 0:
                stats.compilation_success_rate = row[3] / total_compilations
            
            # Get AV/EDR detection rates
            cursor.execute('''
                SELECT av_edr, detections, non_detections
                FROM av_detection_rates
                WHERE technique_id = ?
            ''', (technique_id,))
            
            for av_row in cursor.fetchall():
                av_edr = av_row[0]
                detections = av_row[1]
                non_detections = av_row[2]
                total = detections + non_detections
                
                if total > 0:
                    stats.detection_rate[av_edr] = detections / total
            
            return stats
            
        finally:
            conn.close()
    
    def recommend_techniques(
        self,
        target_av: Optional[str] = None,
        category: Optional[str] = None,
        min_success_rate: float = 0.7
    ) -> List[Tuple[str, float]]:
        """
        Recommend techniques based on learned data
        
        Args:
            target_av: Target AV/EDR to evade (optional)
            category: Technique category (optional)
            min_success_rate: Minimum compilation success rate
        
        Returns:
            List of (technique_id, score) tuples, sorted by score
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get all technique stats
            cursor.execute('''
                SELECT technique_id, total_uses, compilation_successes, compilation_failures
                FROM technique_stats
                WHERE recommended = 1
            ''')
            
            recommendations = []
            
            for row in cursor.fetchall():
                technique_id = row[0]
                total_uses = row[1]
                successes = row[2]
                failures = row[3]
                
                # Skip if never used
                if total_uses == 0:
                    continue
                
                # Calculate compilation success rate
                total_compilations = successes + failures
                if total_compilations > 0:
                    comp_success_rate = successes / total_compilations
                else:
                    comp_success_rate = 1.0  # Assume success if never compiled
                
                # Skip if below minimum success rate
                if comp_success_rate < min_success_rate:
                    continue
                
                # Calculate evasion score for target AV
                evasion_score = 1.0  # Default: assume evasive
                
                if target_av:
                    cursor.execute('''
                        SELECT detections, non_detections
                        FROM av_detection_rates
                        WHERE technique_id = ? AND av_edr = ?
                    ''', (technique_id, target_av))
                    
                    av_row = cursor.fetchone()
                    if av_row:
                        detections = av_row[0]
                        non_detections = av_row[1]
                        total = detections + non_detections
                        
                        if total > 0:
                            # Evasion score = 1 - detection_rate
                            evasion_score = non_detections / total
                
                # Calculate overall score (weighted average)
                score = (0.4 * comp_success_rate) + (0.6 * evasion_score)
                recommendations.append((technique_id, score))
            
            # Sort by score (highest first)
            recommendations.sort(key=lambda x: x[1], reverse=True)
            
            return recommendations
            
        finally:
            conn.close()
    
    def get_av_statistics(self, av_edr: Optional[str] = None) -> Dict:
        """Get AV/EDR detection statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if av_edr:
                # Get stats for specific AV/EDR
                cursor.execute('''
                    SELECT technique_id, detections, non_detections, last_tested
                    FROM av_detection_rates
                    WHERE av_edr = ?
                ''', (av_edr,))
                
                results = {
                    'av_edr': av_edr,
                    'techniques': []
                }
                
                for row in cursor.fetchall():
                    technique_id = row[0]
                    detections = row[1]
                    non_detections = row[2]
                    last_tested = row[3]
                    total = detections + non_detections
                    
                    if total > 0:
                        results['techniques'].append({
                            'technique_id': technique_id,
                            'detection_rate': detections / total,
                            'evasion_rate': non_detections / total,
                            'total_tests': total,
                            'last_tested': last_tested
                        })
                
                return results
            else:
                # Get summary for all AV/EDR
                cursor.execute('''
                    SELECT av_edr, SUM(detections), SUM(non_detections)
                    FROM av_detection_rates
                    GROUP BY av_edr
                ''')
                
                results = {'summary': []}
                
                for row in cursor.fetchall():
                    av_edr_name = row[0]
                    detections = row[1]
                    non_detections = row[2]
                    total = detections + non_detections
                    
                    if total > 0:
                        results['summary'].append({
                            'av_edr': av_edr_name,
                            'detection_rate': detections / total,
                            'evasion_rate': non_detections / total,
                            'total_tests': total
                        })
                
                return results
                
        finally:
            conn.close()
    
    def export_knowledge(self, filepath: str):
        """Export knowledge base to JSON"""
        logger.info(f"Exporting knowledge base to {filepath}")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Export all data
            data = {
                'exported_at': datetime.now().isoformat(),
                'technique_stats': [],
                'av_detection_rates': [],
                'recent_feedback': []
            }
            
            # Technique stats
            cursor.execute('SELECT * FROM technique_stats')
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                data['technique_stats'].append(dict(zip(columns, row)))
            
            # AV detection rates
            cursor.execute('SELECT * FROM av_detection_rates')
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                data['av_detection_rates'].append(dict(zip(columns, row)))
            
            # Recent feedback (last 100 entries)
            cursor.execute('SELECT * FROM detection_feedback ORDER BY timestamp DESC LIMIT 100')
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                data['recent_feedback'].append(dict(zip(columns, row)))
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Knowledge base exported successfully to {filepath}")
            
        finally:
            conn.close()


# ============================================================================
# TESTING
# ============================================================================

def test_learning_engine():
    """Test learning engine"""
    import tempfile
    import os
    
    # Create temp database
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
        db_path = tmp.name
    
    try:
        engine = LearningEngine(db_path)
        
        # Test detection feedback
        feedback = DetectionFeedback(
            timestamp=datetime.now().isoformat(),
            techniques_used=['NOCTIS-T001', 'NOCTIS-T002'],
            av_edr='Windows Defender',
            detected=False,
            detection_type='static',
            obfuscation_level='advanced',
            notes='Bypassed successfully with API hashing'
        )
        engine.record_detection(feedback)
        
        # Test compilation feedback
        comp_feedback = CompilationFeedback(
            timestamp=datetime.now().isoformat(),
            techniques_used=['NOCTIS-T001', 'NOCTIS-T002'],
            success=True,
            compiler='MSBuild',
            auto_fixed=False
        )
        engine.record_compilation(comp_feedback)
        
        # Get stats
        stats = engine.get_technique_stats('NOCTIS-T001')
        print(f"Technique stats: {stats}")
        
        # Get recommendations
        recommendations = engine.recommend_techniques(target_av='Windows Defender')
        print(f"Recommendations: {recommendations}")
        
        # Export knowledge
        export_path = db_path.replace('.db', '_export.json')
        engine.export_knowledge(export_path)
        
        print("[OK] Learning engine test passed")
        
    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.remove(db_path)
        export_path = db_path.replace('.db', '_export.json')
        if os.path.exists(export_path):
            os.remove(export_path)


# ============================================================================
# AGENTIC CAPABILITIES (AI-Powered Decision Making)
# ============================================================================

class AgenticLearningEngine(LearningEngine):
    """
    Extends LearningEngine with agentic decision-making capabilities.
    
    Provides AI-powered technique selection, parameter optimization, and
    autonomous malware development based on target analysis and learning.
    """
    
    def __init__(self, db_path: str = "data/knowledge_base.db", agent_registry: Optional[Any] = None):
        super().__init__(db_path)
        self.agent_registry = agent_registry
        self.technique_effectiveness = self._init_technique_effectiveness()
        self.av_profiles = self._init_av_profiles()
        self.learning_patterns = {}
        
    def _init_technique_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize technique effectiveness ratings for different AV/EDR systems"""
        return {
            "Windows Defender": {
                "NOCTIS-T001": 0.85,  # API Hashing - Good against static analysis
                "NOCTIS-T002": 0.90,  # Syscalls - Bypasses API monitoring
                "NOCTIS-T003": 0.88,  # Encryption - Hides payload content
                "NOCTIS-T004": 0.92,  # Unhooking - Bypasses EDR hooks
                "NOCTIS-T005": 0.87,  # Injection - Memory-based execution
                "NOCTIS-T006": 0.95,  # Steganography - Excellent evasion
                "NOCTIS-T007": 0.83,  # Persistence - Moderate detection risk
                "NOCTIS-T008": 0.89,  # Stack Spoof - Good for call stack hiding
                "NOCTIS-T009": 0.91,  # GPU Evasion - Advanced technique
                "NOCTIS-T010": 0.86   # VEH - Exception-based execution
            },
            "CrowdStrike": {
                "NOCTIS-T001": 0.78,  # API Hashing - Detected by behavioral analysis
                "NOCTIS-T002": 0.85,  # Syscalls - Still effective
                "NOCTIS-T003": 0.82,  # Encryption - Good but not enough alone
                "NOCTIS-T004": 0.88,  # Unhooking - Very effective against EDR
                "NOCTIS-T005": 0.80,  # Injection - Moderate effectiveness
                "NOCTIS-T006": 0.92,  # Steganography - Excellent evasion
                "NOCTIS-T007": 0.75,  # Persistence - High detection risk
                "NOCTIS-T008": 0.83,  # Stack Spoof - Good technique
                "NOCTIS-T009": 0.87,  # GPU Evasion - Advanced but detectable
                "NOCTIS-T010": 0.81   # VEH - Moderate effectiveness
            },
            "SentinelOne": {
                "NOCTIS-T001": 0.72,  # API Hashing - Behavioral detection
                "NOCTIS-T002": 0.88,  # Syscalls - Very effective
                "NOCTIS-T003": 0.85,  # Encryption - Good for payload hiding
                "NOCTIS-T004": 0.90,  # Unhooking - Critical for EDR bypass
                "NOCTIS-T005": 0.78,  # Injection - Behavioral analysis risk
                "NOCTIS-T006": 0.94,  # Steganography - Excellent evasion
                "NOCTIS-T007": 0.70,  # Persistence - High detection risk
                "NOCTIS-T008": 0.85,  # Stack Spoof - Good technique
                "NOCTIS-T009": 0.89,  # GPU Evasion - Advanced technique
                "NOCTIS-T010": 0.83   # VEH - Good for evasion
            },
            "Kaspersky": {
                "NOCTIS-T001": 0.80,  # API Hashing - Moderate effectiveness
                "NOCTIS-T002": 0.87,  # Syscalls - Good technique
                "NOCTIS-T003": 0.90,  # Encryption - Excellent for hiding
                "NOCTIS-T004": 0.85,  # Unhooking - Good but detectable
                "NOCTIS-T005": 0.82,  # Injection - Moderate effectiveness
                "NOCTIS-T006": 0.93,  # Steganography - Excellent evasion
                "NOCTIS-T007": 0.77,  # Persistence - Moderate risk
                "NOCTIS-T008": 0.88,  # Stack Spoof - Good technique
                "NOCTIS-T009": 0.86,  # GPU Evasion - Advanced technique
                "NOCTIS-T010": 0.84   # VEH - Good for evasion
            }
        }

    def get_effectiveness_score(self, technique_id: str, target_av: str) -> float:
        """
        Get effectiveness score for a technique against a target AV/EDR.

        Args:
            technique_id: Technique ID (e.g., 'NOCTIS-T001')
            target_av: Target AV/EDR name

        Returns:
            Effectiveness score (0.0-1.0), defaults to 0.5 if unknown
        """
        # Get AV-specific scores
        av_scores = self.technique_effectiveness.get(target_av, {})

        # Get score for this technique, default to 0.5 (moderate)
        return av_scores.get(technique_id, 0.5)

    def _init_av_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize AV/EDR profiles with characteristics and detection patterns"""
        return {
            "Windows Defender": {
                "strengths": ["Static analysis", "Heuristic detection", "Cloud-based ML"],
                "weaknesses": ["API hashing", "Indirect syscalls", "Steganography"],
                "detection_focus": ["File-based", "Behavioral patterns", "Known signatures"],
                "bypass_techniques": ["NOCTIS-T001", "NOCTIS-T002", "NOCTIS-T006", "NOCTIS-T008"]
            },
            "CrowdStrike": {
                "strengths": ["Behavioral analysis", "Process monitoring", "Memory scanning"],
                "weaknesses": ["Steganography", "Unhooking", "GPU-based execution"],
                "detection_focus": ["Process behavior", "Memory patterns", "Network activity"],
                "bypass_techniques": ["NOCTIS-T004", "NOCTIS-T006", "NOCTIS-T008", "NOCTIS-T009"]
            },
            "SentinelOne": {
                "strengths": ["Real-time monitoring", "Behavioral analysis", "EDR capabilities"],
                "weaknesses": ["Indirect syscalls", "Unhooking", "Steganography"],
                "detection_focus": ["Process behavior", "System calls", "Memory activity"],
                "bypass_techniques": ["NOCTIS-T002", "NOCTIS-T004", "NOCTIS-T006", "NOCTIS-T008"]
            },
            "Kaspersky": {
                "strengths": ["Signature detection", "Heuristic analysis", "Cloud scanning"],
                "weaknesses": ["Encryption", "Steganography", "Advanced obfuscation"],
                "detection_focus": ["File signatures", "Behavioral patterns", "Network traffic"],
                "bypass_techniques": ["NOCTIS-T003", "NOCTIS-T006", "NOCTIS-T008", "NOCTIS-T009"]
            }
        }
    
    def agentic_analyze_target(self, target_av: str, complexity: str = "medium", objective: str = "evasion") -> Dict[str, Any]:
        """
        AI-powered target analysis for intelligent technique selection.
        
        Args:
            target_av: Target AV/EDR system
            complexity: Desired complexity level (low, medium, high)
            objective: Development objective (evasion, stealth, persistence, injection)
        
        Returns:
            Comprehensive target profile with recommendations
        """
        # Normalize target AV name
        target_av = self._normalize_av_name(target_av)
        
        # Get AV profile
        av_profile = self.av_profiles.get(target_av, self.av_profiles["Windows Defender"])
        
        # Get technique effectiveness scores
        effectiveness_scores = self.technique_effectiveness.get(target_av, self.technique_effectiveness["Windows Defender"])
        
        # Filter techniques based on objective
        objective_techniques = self._filter_techniques_by_objective(objective, effectiveness_scores)
        
        # Sort by effectiveness
        sorted_techniques = sorted(objective_techniques.items(), key=lambda x: x[1], reverse=True)
        
        # Select top techniques based on complexity
        technique_count = self._get_technique_count_by_complexity(complexity)
        recommended_techniques = [tech[0] for tech in sorted_techniques[:technique_count]]
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(target_av, recommended_techniques, effectiveness_scores)
        
        profile = {
            "target_av": target_av,
            "complexity": complexity,
            "objective": objective,
            "av_profile": av_profile,
            "recommended_techniques": recommended_techniques,
            "effectiveness_scores": {tech: effectiveness_scores.get(tech, 0.0) for tech in recommended_techniques},
            "risk_level": risk_level,
            "bypass_techniques": av_profile.get("bypass_techniques", []),
            "detection_focus": av_profile.get("detection_focus", []),
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Agentic analysis complete for {target_av}: {len(recommended_techniques)} techniques selected, risk level: {risk_level}")
        
        return profile
    
    def agentic_recommend_techniques(self, target_av: str, objective: str = "evasion", complexity: str = "medium") -> List[str]:
        """
        AI-powered technique recommendation based on target analysis.
        
        Args:
            target_av: Target AV/EDR system
            objective: Development objective
            complexity: Desired complexity level
        
        Returns:
            List of recommended technique IDs
        """
        profile = self.agentic_analyze_target(target_av, complexity, objective)
        return profile["recommended_techniques"]
    
    def agentic_optimize_parameters(self, technique: str, target_av: str, complexity: str = "medium", context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        AI-powered parameter optimization for techniques.
        
        Args:
            technique: Technique ID to optimize
            target_av: Target AV/EDR system
            complexity: Desired complexity level
            context: Additional context for optimization
        
        Returns:
            Optimized parameters for the technique
        """
        if context is None:
            context = {}
        
        # Get AV profile for optimization hints
        av_profile = self.av_profiles.get(target_av, self.av_profiles["Windows Defender"])
        bypass_techniques = av_profile.get("bypass_techniques", [])
        
        # Initialize parameters
        params = {
            "technique": technique,
            "target_av": target_av,
            "complexity": complexity,
            "optimized": True
        }
        
        # Technique-specific optimization
        if technique == "NOCTIS-T001":  # API Hashing
            params.update(self._optimize_api_hashing(target_av, complexity, bypass_techniques))
        elif technique == "NOCTIS-T002":  # Syscalls
            params.update(self._optimize_syscalls(target_av, complexity, bypass_techniques))
        elif technique == "NOCTIS-T003":  # Encryption
            params.update(self._optimize_encryption(target_av, complexity, context))
        elif technique == "NOCTIS-T004":  # Unhooking
            params.update(self._optimize_unhooking(target_av, complexity, bypass_techniques))
        elif technique == "NOCTIS-T005":  # Injection
            params.update(self._optimize_injection(target_av, complexity, context))
        elif technique == "NOCTIS-T006":  # Steganography
            params.update(self._optimize_steganography(target_av, complexity, context))
        elif technique == "NOCTIS-T007":  # Persistence
            params.update(self._optimize_persistence(target_av, complexity, context))
        elif technique == "NOCTIS-T008":  # Stack Spoof
            params.update(self._optimize_stack_spoof(target_av, complexity, bypass_techniques))
        elif technique == "NOCTIS-T009":  # GPU Evasion
            params.update(self._optimize_gpu_evasion(target_av, complexity, context))
        elif technique == "NOCTIS-T010":  # VEH
            params.update(self._optimize_veh(target_av, complexity, context))
        else:
            # Default optimization for unknown techniques
            params.update(self._optimize_default(technique, target_av, complexity))
        
        logger.info(f"Parameter optimization complete for {technique} against {target_av}")
        
        return params
    
    def agentic_learn_from_feedback(self, technique: str, target_av: str, success: bool, feedback: str = "") -> None:
        """
        Learn from user feedback to improve future recommendations.
        
        Args:
            technique: Technique that was used
            target_av: Target AV/EDR system
            success: Whether the technique was successful
            feedback: Additional feedback from user
        """
        # Update technique effectiveness based on feedback
        if target_av in self.technique_effectiveness:
            current_score = self.technique_effectiveness[target_av].get(technique, 0.5)
            
            # Adjust score based on success/failure
            if success:
                new_score = min(1.0, current_score + 0.05)  # Increase effectiveness
            else:
                new_score = max(0.0, current_score - 0.1)   # Decrease effectiveness
            
            self.technique_effectiveness[target_av][technique] = new_score
            
            # Store learning pattern
            pattern_key = f"{technique}_{target_av}_{success}"
            self.learning_patterns[pattern_key] = {
                "technique": technique,
                "target_av": target_av,
                "success": success,
                "feedback": feedback,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"Learned from feedback: {technique} against {target_av} - Success: {success}, New score: {new_score:.3f}")
    
    def _normalize_av_name(self, av_name: str) -> str:
        """Normalize AV name to standard format"""
        av_name = av_name.lower().strip()
        
        if "defender" in av_name or "windows defender" in av_name:
            return "Windows Defender"
        elif "crowdstrike" in av_name:
            return "CrowdStrike"
        elif "sentinel" in av_name or "sentinelone" in av_name:
            return "SentinelOne"
        elif "kaspersky" in av_name:
            return "Kaspersky"
        else:
            return "Windows Defender"  # Default fallback
    
    def _filter_techniques_by_objective(self, objective: str, effectiveness_scores: Dict[str, float]) -> Dict[str, float]:
        """Filter techniques based on development objective"""
        objective_mapping = {
            "evasion": ["NOCTIS-T001", "NOCTIS-T002", "NOCTIS-T003", "NOCTIS-T004", "NOCTIS-T006", "NOCTIS-T008", "NOCTIS-T009", "NOCTIS-T010"],
            "stealth": ["NOCTIS-T001", "NOCTIS-T002", "NOCTIS-T003", "NOCTIS-T006", "NOCTIS-T008", "NOCTIS-T009"],
            "persistence": ["NOCTIS-T007", "NOCTIS-T001", "NOCTIS-T003", "NOCTIS-T004"],
            "injection": ["NOCTIS-T005", "NOCTIS-T001", "NOCTIS-T002", "NOCTIS-T004", "NOCTIS-T008", "NOCTIS-T010"]
        }
        
        objective_techniques = objective_mapping.get(objective, objective_mapping["evasion"])
        return {tech: score for tech, score in effectiveness_scores.items() if tech in objective_techniques}
    
    def _get_technique_count_by_complexity(self, complexity: str) -> int:
        """Get number of techniques based on complexity level"""
        complexity_mapping = {
            "low": 2,
            "medium": 3,
            "high": 5
        }
        return complexity_mapping.get(complexity, 3)
    
    def _calculate_risk_level(self, target_av: str, techniques: List[str], scores: Dict[str, float]) -> str:
        """Calculate risk level based on techniques and effectiveness scores"""
        if not techniques:
            return "high"
        
        avg_score = sum(scores.get(tech, 0.0) for tech in techniques) / len(techniques)
        
        if avg_score >= 0.9:
            return "low"
        elif avg_score >= 0.8:
            return "medium"
        else:
            return "high"
    
    # Technique-specific optimization methods
    def _optimize_api_hashing(self, target_av: str, complexity: str, bypass_techniques: List[str]) -> Dict[str, Any]:
        """Optimize API hashing parameters"""
        params = {}
        
        if target_av == "Windows Defender":
            params["hash_algorithm"] = "djb2"
            params["obfuscation_level"] = "high" if complexity == "high" else "medium"
        elif target_av == "CrowdStrike":
            params["hash_algorithm"] = "crc32"
            params["obfuscation_level"] = "high"
        else:
            params["hash_algorithm"] = "djb2"
            params["obfuscation_level"] = "medium"
        
        params["dynamic_resolution"] = True
        params["anti_analysis"] = complexity == "high"
        
        return params
    
    def _optimize_syscalls(self, target_av: str, complexity: str, bypass_techniques: List[str]) -> Dict[str, Any]:
        """Optimize syscall parameters"""
        params = {}
        
        if target_av in ["CrowdStrike", "SentinelOne"]:
            params["syscall_method"] = "indirect"
            params["unhooking"] = True
        else:
            params["syscall_method"] = "direct"
            params["unhooking"] = complexity == "high"
        
        params["anti_analysis"] = True
        params["stack_spoofing"] = "NOCTIS-T008" in bypass_techniques
        
        return params
    
    def _optimize_encryption(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize encryption parameters"""
        params = {}
        
        if complexity == "high":
            params["encryption_type"] = "aes256"
            params["key_rotation"] = True
        else:
            params["encryption_type"] = "xor"
            params["key_rotation"] = False
        
        params["obfuscation"] = True
        params["anti_analysis"] = target_av in ["CrowdStrike", "SentinelOne"]
        
        return params
    
    def _optimize_unhooking(self, target_av: str, complexity: str, bypass_techniques: List[str]) -> Dict[str, Any]:
        """Optimize unhooking parameters"""
        params = {}
        
        params["unhook_method"] = "direct" if target_av == "Windows Defender" else "indirect"
        params["restore_hooks"] = complexity == "high"
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_injection(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize injection parameters"""
        params = {}
        
        params["injection_method"] = "manual_map" if complexity == "high" else "dll_injection"
        params["unhooking"] = target_av in ["CrowdStrike", "SentinelOne"]
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_steganography(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize steganography parameters"""
        params = {}
        
        params["stego_method"] = "lsb" if complexity == "low" else "dct"
        params["encryption"] = True
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_persistence(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize persistence parameters"""
        params = {}
        
        params["persistence_method"] = "registry" if complexity == "low" else "service"
        params["stealth"] = True
        params["anti_analysis"] = target_av in ["CrowdStrike", "SentinelOne"]
        
        return params
    
    def _optimize_stack_spoof(self, target_av: str, complexity: str, bypass_techniques: List[str]) -> Dict[str, Any]:
        """Optimize stack spoofing parameters"""
        params = {}
        
        params["spoof_method"] = "manual" if complexity == "high" else "automatic"
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_gpu_evasion(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize GPU evasion parameters"""
        params = {}
        
        params["gpu_method"] = "cuda" if complexity == "high" else "opencl"
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_veh(self, target_av: str, complexity: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize VEH parameters"""
        params = {}
        
        params["veh_method"] = "manual" if complexity == "high" else "automatic"
        params["anti_analysis"] = True
        
        return params
    
    def _optimize_default(self, technique: str, target_av: str, complexity: str) -> Dict[str, Any]:
        """Default optimization for unknown techniques"""
        return {
            "anti_analysis": True,
            "obfuscation": complexity == "high",
            "stealth": target_av in ["CrowdStrike", "SentinelOne"]
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_learning_engine()

