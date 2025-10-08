#!/usr/bin/env python3
"""
Live Detection Testing with VirusTotal
=======================================

Integrates with VirusTotal to test malware against 70+ AV/EDR engines.

Features:
- Upload binaries to VirusTotal
- Test against 70+ AV engines simultaneously
- Get detection verdicts in seconds (not minutes)
- Calculate OPSEC scores based on results
- Smart caching to avoid redundant uploads
- Automated recommendations for OPSEC improvements

API Documentation: https://docs.virustotal.com/reference/overview

Usage:
    from server.detection_testing import DetectionTester

    tester = DetectionTester(api_key="your_api_key")
    result = tester.test_binary("malware.exe", target_av="CrowdStrike Falcon")

    print(f"Detected: {result['detected']}")
    print(f"OPSEC Score: {result['opsec_score']}/10")
"""

import os
import time
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


class VirusTotalAPI:
    """Client for VirusTotal API v3"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal API client

        Args:
            api_key: VirusTotal API key (or use VT_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("VT_API_KEY")
        if not self.api_key:
            logger.warning("No VirusTotal API key provided. Set VT_API_KEY env variable.")

        # Rate limiting (Free tier: 4 requests per minute)
        self.rate_limit_delay = 15  # seconds between requests (4/min = 15s)
        self.last_request_time = 0

        # Cache directory for results
        self.cache_dir = Path("data/detection_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _rate_limit(self):
        """Enforce rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            wait_time = self.rate_limit_delay - elapsed
            logger.info(f"Rate limiting: waiting {wait_time:.1f}s")
            time.sleep(wait_time)
        self.last_request_time = time.time()

    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _load_cache(self, file_hash: str) -> Optional[Dict]:
        """Load cached result if available and recent (< 7 days)"""
        cache_file = self.cache_dir / f"{file_hash}.json"

        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)

                # Check if cache is still valid (7 days)
                cached_at = cached.get("cached_at")
                if not cached_at:
                    logger.warning(f"Cache missing timestamp for {file_hash[:8]}, treating as expired")
                    return None

                try:
                    cache_date = datetime.fromisoformat(cached_at)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid cache timestamp '{cached_at}' for {file_hash[:8]}: {e}")
                    return None

                if datetime.now() - cache_date < timedelta(days=7):
                    logger.info(f"Using cached result for {file_hash[:8]}...")
                    return cached
                else:
                    logger.info(f"Cache expired for {file_hash[:8]} (age: {(datetime.now() - cache_date).days} days)")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        return None

    def _save_cache(self, file_hash: str, result: Dict):
        """Save result to cache"""
        cache_file = self.cache_dir / f"{file_hash}.json"
        result["cached_at"] = datetime.now().isoformat()

        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Cached result for {file_hash[:8]}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def submit_file(self, file_path: str) -> Optional[Dict]:
        """
        Submit file to VirusTotal for scanning

        Args:
            file_path: Path to binary file

        Returns:
            Scan results with detection data
        """
        if not self.api_key:
            logger.error("No API key configured")
            return None

        # Check cache first
        file_hash = self._get_file_hash(file_path)
        cached_result = self._load_cache(file_hash)
        if cached_result:
            return cached_result

        logger.info(f"Submitting {Path(file_path).name} to VirusTotal...")

        try:
            import vt

            # Rate limit
            self._rate_limit()

            # Check if file already scanned
            with vt.Client(self.api_key) as client:
                try:
                    # Try to get existing analysis
                    logger.info(f"Checking for existing scan: {file_hash}")
                    file_obj = client.get_object(f"/files/{file_hash}")

                    logger.info(f"Found existing scan - returning cached result")
                    return {
                        'sha256': file_hash,
                        'stats': file_obj.last_analysis_stats,
                        'results': file_obj.last_analysis_results,
                        'scan_date': file_obj.last_analysis_date
                    }

                except vt.APIError:
                    # File not seen before, need to upload
                    logger.info(f"File not seen before - uploading...")
                    self._rate_limit()

                    with open(file_path, 'rb') as f:
                        analysis = client.scan_file(f)

                    # Wait for analysis to complete
                    logger.info("Waiting for analysis to complete...")
                    analysis_id = analysis.id

                    # Poll for results (usually takes 10-30 seconds)
                    max_wait = 120  # 2 minutes max
                    start_time = time.time()

                    while time.time() - start_time < max_wait:
                        self._rate_limit()

                        analysis_obj = client.get_object(f"/analyses/{analysis_id}")

                        if analysis_obj.status == "completed":
                            # Get full file report
                            self._rate_limit()
                            file_obj = client.get_object(f"/files/{file_hash}")

                            result = {
                                'sha256': file_hash,
                                'stats': file_obj.last_analysis_stats,
                                'results': file_obj.last_analysis_results,
                                'scan_date': file_obj.last_analysis_date
                            }

                            # Cache result
                            self._save_cache(file_hash, result)
                            return result

                        logger.info(f"Analysis status: {analysis_obj.status}... waiting")
                        time.sleep(10)

                    logger.error(f"Analysis timeout for {analysis_id} after {max_wait}s (hash: {file_hash[:8]}...)")
                    return {
                        'success': False,
                        'error': f'Analysis timeout after {max_wait}s',
                        'analysis_id': analysis_id,
                        'file_hash': file_hash
                    }

        except ImportError:
            logger.error("vt-py not installed. Run: pip install vt-py")
            return None
        except Exception as e:
            logger.exception(f"Error submitting file: {e}")
            return None


class DetectionTester:
    """High-level detection testing orchestrator"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize detection tester

        Args:
            api_key: VirusTotal API key
        """
        self.virustotal = VirusTotalAPI(api_key)
        self.results_dir = Path("data/detection_results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def test_binary(
        self,
        binary_path: str,
        target_av: Optional[str] = None,
        environment: str = "Windows 10 64-bit"
    ) -> Dict:
        """
        Test binary against 70+ AV engines via VirusTotal

        Args:
            binary_path: Path to compiled binary
            target_av: Target AV name (for OPSEC score calculation)
            environment: Ignored (kept for API compatibility)

        Returns:
            Detection results with OPSEC score
        """
        logger.info(f"Testing {Path(binary_path).name} against 70+ AV engines")

        if not Path(binary_path).exists():
            return {
                "success": False,
                "error": f"File not found: {binary_path}"
            }

        # Submit file
        result = self.virustotal.submit_file(binary_path)

        if not result:
            return {
                "success": False,
                "error": "Submission failed. Check API key and rate limits."
            }

        # Parse results
        detection_result = self._parse_detection_results(result, target_av)

        # Save detailed report
        self._save_report(binary_path, detection_result, result)

        return detection_result

    def _parse_detection_results(self, vt_result: Dict, target_av: Optional[str]) -> Dict:
        """Parse VirusTotal result into detection results"""

        stats = vt_result.get('stats', {})
        results = vt_result.get('results', {})

        # Extract detection counts
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        total_engines = malicious + suspicious + undetected + stats.get('harmless', 0)

        # Extract which AVs detected it
        detected_by = []
        target_detected = False

        for av_name, av_data in results.items():
            if av_data.get('category') in ['malicious', 'suspicious']:
                detected_by.append({
                    'name': av_name,
                    'category': av_data.get('category'),
                    'result': av_data.get('result', 'unknown')
                })

                # Check if target AV detected it
                if target_av and target_av.lower() in av_name.lower():
                    target_detected = True

        # Calculate OPSEC score
        opsec_score = self._calculate_opsec_score(
            malicious=malicious,
            suspicious=suspicious,
            total_engines=total_engines,
            target_detected=target_detected
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            detected_by=detected_by,
            target_detected=target_detected,
            detection_rate=malicious / total_engines if total_engines > 0 else 0
        )

        return {
            "success": True,
            "detected": malicious > 0 or suspicious > 0,
            "verdict": "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean"),
            "opsec_score": opsec_score,
            "detection_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total_engines,
            "detection_rate": f"{(malicious / total_engines * 100):.1f}%" if total_engines > 0 else "0%",
            "detected_by": detected_by,
            "target_av": target_av,
            "target_detected": target_detected,
            "recommendations": recommendations,
            "scan_date": vt_result.get('scan_date'),
            "sha256": vt_result.get('sha256')
        }

    def _calculate_opsec_score(
        self,
        malicious: int,
        suspicious: int,
        total_engines: int,
        target_detected: bool
    ) -> int:
        """
        Calculate OPSEC score (1-10)

        10 = Undetected
        8-9 = Low detections (1-10%)
        5-7 = Moderate detections (10-30%)
        3-4 = High detections (30-60%)
        1-2 = Heavily detected (>60%)
        """
        if total_engines == 0:
            return 1

        detection_rate = malicious / total_engines

        # Start with base score
        if detection_rate == 0:
            score = 10
        elif detection_rate < 0.05:  # <5%
            score = 9
        elif detection_rate < 0.10:  # <10%
            score = 8
        elif detection_rate < 0.20:  # <20%
            score = 7
        elif detection_rate < 0.30:  # <30%
            score = 6
        elif detection_rate < 0.50:  # <50%
            score = 5
        elif detection_rate < 0.70:  # <70%
            score = 4
        else:
            score = 2

        # Penalty for suspicious detections
        if suspicious > 5:
            score -= 1

        # Critical penalty if target AV detected it
        if target_detected:
            score -= 2

        return max(1, min(10, score))

    def _generate_recommendations(
        self,
        detected_by: List[Dict],
        target_detected: bool,
        detection_rate: float
    ) -> List[str]:
        """Generate OPSEC improvement recommendations"""
        recommendations = []

        if target_detected:
            recommendations.append(
                f"🚨 CRITICAL: Target AV detected the binary. Different evasion technique required."
            )

        if detection_rate > 0.5:
            recommendations.append(
                f"⚠️  High detection rate ({detection_rate*100:.0f}%). Add obfuscation and anti-analysis."
            )
        elif detection_rate > 0.2:
            recommendations.append(
                f"⚠️  Moderate detection rate ({detection_rate*100:.0f}%). Consider additional evasion."
            )
        elif detection_rate > 0.05:
            recommendations.append(
                f"✓ Low detection rate ({detection_rate*100:.0f}%). Good OPSEC baseline."
            )
        else:
            recommendations.append(
                f"✅ Excellent! Very low detection rate ({detection_rate*100:.0f}%)."
            )

        # Check for specific AV detections and suggest fixes
        av_names = [av['name'].lower() for av in detected_by]

        if any('defender' in name or 'windows' in name for name in av_names):
            recommendations.append(
                "💡 Windows Defender detected: Use indirect syscalls and sleep obfuscation"
            )

        if any('crowdstrike' in name or 'falcon' in name for name in av_names):
            recommendations.append(
                "💡 CrowdStrike detected: Avoid user-mode hooks, use NTDLL direct calls"
            )

        if any('kaspersky' in name for name in av_names):
            recommendations.append(
                "💡 Kaspersky detected: Add more string obfuscation and API hashing"
            )

        if any('sophos' in name for name in av_names):
            recommendations.append(
                "💡 Sophos detected: Avoid obvious process injection, use thread pool injection"
            )

        if len(detected_by) > 10 and not recommendations:
            recommendations.append(
                "💡 Multiple detections: Implement SysWhispers3, API hashing, and string encryption"
            )

        if not recommendations:
            recommendations.append(
                "✅ Excellent OPSEC! Binary shows very low detection."
            )

        return recommendations

    def _save_report(self, binary_path: str, result: Dict, full_result: Dict):
        """Save detection report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        binary_name = Path(binary_path).stem
        report_file = self.results_dir / f"{binary_name}_{timestamp}.json"

        report_data = {
            "binary": str(binary_path),
            "timestamp": datetime.now().isoformat(),
            "result": result,
            "full_vt_result": full_result
        }

        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"Report saved: {report_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


# Convenience function for quick testing
def test_file(binary_path: str, target_av: Optional[str] = None) -> Dict:
    """
    Quick test function

    Usage:
        from server.detection_testing import test_file
        result = test_file("malware.exe", "CrowdStrike")
    """
    tester = DetectionTester()
    return tester.test_binary(binary_path, target_av=target_av)
