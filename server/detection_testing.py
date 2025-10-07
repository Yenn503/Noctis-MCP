#!/usr/bin/env python3
"""
Live Detection Testing with Hybrid Analysis
============================================

Integrates with Hybrid Analysis sandbox to test malware against real AV/EDR.

Features:
- Upload binaries to Hybrid Analysis
- Test against specific AV/EDR configurations
- Get detection verdicts and signatures
- Calculate OPSEC scores based on results
- Smart caching to avoid redundant uploads

API Documentation: https://www.hybrid-analysis.com/docs/api/v2

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
import requests
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class HybridAnalysisAPI:
    """Client for Hybrid Analysis API v2"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Hybrid Analysis API client

        Args:
            api_key: Hybrid Analysis API key (or use HYBRID_ANALYSIS_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("HYBRID_ANALYSIS_API_KEY")
        if not self.api_key:
            logger.warning("No Hybrid Analysis API key provided. Set HYBRID_ANALYSIS_API_KEY env variable.")

        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.headers = {
            "api-key": self.api_key,
            "User-Agent": "Noctis-MCP-Detection-Testing",
            "Accept": "application/json"
        }

        # Rate limiting (100 requests per hour for free tier)
        self.rate_limit_delay = 36  # seconds between requests
        self.last_request_time = 0

        # Cache directory for results
        self.cache_dir = Path("data/detection_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Environment IDs (Hybrid Analysis environment codes)
        self.environments = {
            "Windows 7 32-bit": 100,
            "Windows 7 64-bit": 110,
            "Windows 10 64-bit": 120,
            "Windows 11 64-bit": 160,
            "Linux (Ubuntu 16.04, 64-bit)": 300,
        }

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
                cache_date = datetime.fromisoformat(cached.get("cached_at", "2000-01-01"))
                if datetime.now() - cache_date < timedelta(days=7):
                    logger.info(f"Using cached result for {file_hash[:8]}...")
                    return cached
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

    def submit_file(
        self,
        file_path: str,
        environment: str = "Windows 10 64-bit",
        comment: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Submit file to Hybrid Analysis for scanning

        Args:
            file_path: Path to binary file
            environment: Target OS environment
            comment: Optional comment for submission

        Returns:
            Submission data with job_id for status checking
        """
        if not self.api_key:
            logger.error("No API key configured")
            return None

        # Check cache first
        file_hash = self._get_file_hash(file_path)
        cached_result = self._load_cache(file_hash)
        if cached_result:
            return cached_result

        # Rate limit
        self._rate_limit()

        # Get environment ID
        env_id = self.environments.get(environment, 120)  # Default to Win10

        logger.info(f"Submitting {Path(file_path).name} to Hybrid Analysis...")
        logger.info(f"Environment: {environment} (ID: {env_id})")

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (Path(file_path).name, f, 'application/octet-stream')}
                data = {
                    'environment_id': env_id,
                    'comment': comment or f"Noctis-MCP Detection Test - {datetime.now().isoformat()}"
                }

                response = requests.post(
                    f"{self.base_url}/submit/file",
                    headers=self.headers,
                    files=files,
                    data=data,
                    timeout=60
                )

                if response.status_code == 201:
                    result = response.json()
                    logger.info(f"Submission successful! Job ID: {result.get('job_id')}")
                    return result
                elif response.status_code == 429:
                    logger.error("Rate limit exceeded. Wait before retrying.")
                    return None
                else:
                    logger.error(f"Submission failed: {response.status_code} - {response.text}")
                    return None

        except Exception as e:
            logger.exception(f"Error submitting file: {e}")
            return None

    def get_report(self, job_id: str, max_wait: int = 600) -> Optional[Dict]:
        """
        Get analysis report for submitted file

        Args:
            job_id: Job ID from submission
            max_wait: Maximum seconds to wait for analysis (default: 10 minutes)

        Returns:
            Full analysis report
        """
        if not self.api_key:
            logger.error("No API key configured")
            return None

        logger.info(f"Waiting for analysis to complete (Job ID: {job_id})...")
        start_time = time.time()

        while time.time() - start_time < max_wait:
            self._rate_limit()

            try:
                response = requests.get(
                    f"{self.base_url}/report/{job_id}/state",
                    headers=self.headers,
                    timeout=10
                )

                if response.status_code == 200:
                    state = response.json()
                    status = state.get("state", "unknown")

                    logger.info(f"Analysis status: {status}")

                    if status == "SUCCESS":
                        # Get full report
                        return self._fetch_full_report(job_id)
                    elif status in ["ERROR", "FAILED"]:
                        logger.error(f"Analysis failed: {state}")
                        return None
                    else:
                        # Still processing
                        time.sleep(30)  # Check every 30 seconds
                else:
                    logger.error(f"Status check failed: {response.status_code}")
                    return None

            except Exception as e:
                logger.exception(f"Error checking status: {e}")
                return None

        logger.error(f"Analysis timeout after {max_wait}s")
        return None

    def _fetch_full_report(self, job_id: str) -> Optional[Dict]:
        """Fetch complete analysis report"""
        self._rate_limit()

        try:
            response = requests.get(
                f"{self.base_url}/report/{job_id}/summary",
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Report fetch failed: {response.status_code}")
                return None

        except Exception as e:
            logger.exception(f"Error fetching report: {e}")
            return None

    def search_hash(self, file_hash: str) -> Optional[List[Dict]]:
        """
        Search for existing analysis by file hash
        Useful to check if file was already analyzed

        Args:
            file_hash: SHA256 hash of file

        Returns:
            List of existing analysis reports
        """
        if not self.api_key:
            logger.error("No API key configured")
            return None

        self._rate_limit()

        try:
            response = requests.post(
                f"{self.base_url}/search/hash",
                headers=self.headers,
                data={"hash": file_hash},
                timeout=10
            )

            if response.status_code == 200:
                results = response.json()
                return results
            else:
                logger.warning(f"Hash search failed: {response.status_code}")
                return None

        except Exception as e:
            logger.exception(f"Error searching hash: {e}")
            return None


class DetectionTester:
    """High-level detection testing orchestrator"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize detection tester

        Args:
            api_key: Hybrid Analysis API key
        """
        self.hybrid_analysis = HybridAnalysisAPI(api_key)
        self.results_dir = Path("data/detection_results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def test_binary(
        self,
        binary_path: str,
        target_av: Optional[str] = None,
        environment: str = "Windows 10 64-bit"
    ) -> Dict:
        """
        Test binary against AV/EDR in sandbox

        Args:
            binary_path: Path to compiled binary
            target_av: Target AV name (for OPSEC score calculation)
            environment: Target OS environment

        Returns:
            Detection results with OPSEC score
        """
        logger.info(f"Testing {Path(binary_path).name} in {environment}")

        if not Path(binary_path).exists():
            return {
                "success": False,
                "error": f"File not found: {binary_path}"
            }

        # Check if already analyzed
        file_hash = self.hybrid_analysis._get_file_hash(binary_path)
        cached = self.hybrid_analysis._load_cache(file_hash)

        if cached and "detection_result" in cached:
            logger.info("Using cached detection result")
            return cached["detection_result"]

        # Submit file
        submission = self.hybrid_analysis.submit_file(
            binary_path,
            environment=environment,
            comment=f"Noctis-MCP Test - Target: {target_av or 'General'}"
        )

        if not submission:
            return {
                "success": False,
                "error": "Submission failed. Check API key and rate limits."
            }

        # Wait for analysis
        job_id = submission.get("job_id")
        if not job_id:
            return {
                "success": False,
                "error": "No job ID received from submission"
            }

        report = self.hybrid_analysis.get_report(job_id, max_wait=600)

        if not report:
            return {
                "success": False,
                "error": "Analysis failed or timed out"
            }

        # Parse results
        result = self._parse_detection_results(report, target_av)

        # Cache result
        self.hybrid_analysis._save_cache(file_hash, {"detection_result": result})

        # Save detailed report
        self._save_report(binary_path, result, report)

        return result

    def _parse_detection_results(self, report: Dict, target_av: Optional[str]) -> Dict:
        """Parse Hybrid Analysis report into detection results"""

        # Extract key indicators
        verdict = report.get("verdict", "unknown")
        threat_score = report.get("threat_score", 0)  # 0-100
        av_detections = report.get("av_detect", 0)  # Number of AV detections
        total_signatures = report.get("total_signatures", 0)

        # Extract AV results
        av_results = report.get("av_results", [])
        detected_by = [av["av_name"] for av in av_results if av.get("is_detected")]

        # Check if target AV detected it
        target_detected = False
        if target_av:
            target_detected = any(
                target_av.lower() in av.lower() for av in detected_by
            )

        # Calculate OPSEC score (1-10, higher = better evasion)
        opsec_score = self._calculate_opsec_score(
            verdict=verdict,
            threat_score=threat_score,
            av_detections=av_detections,
            target_detected=target_detected
        )

        # Extract triggered signatures
        signatures = []
        for sig in report.get("signatures", []):
            signatures.append({
                "name": sig.get("name"),
                "severity": sig.get("severity"),
                "threat_level": sig.get("threat_level")
            })

        return {
            "success": True,
            "detected": verdict in ["malicious", "suspicious"],
            "verdict": verdict,
            "threat_score": threat_score,
            "opsec_score": opsec_score,
            "av_detections": av_detections,
            "detected_by": detected_by,
            "target_av": target_av,
            "target_detected": target_detected,
            "signatures": signatures[:10],  # Top 10 signatures
            "behavioral_alerts": self._extract_behavioral_alerts(report),
            "recommendations": self._generate_recommendations(
                signatures, detected_by, target_detected
            ),
            "analysis_time": report.get("analysis_start_time"),
            "environment": report.get("environment_description"),
            "sha256": report.get("sha256")
        }

    def _calculate_opsec_score(
        self,
        verdict: str,
        threat_score: int,
        av_detections: int,
        target_detected: bool
    ) -> int:
        """
        Calculate OPSEC score (1-10)

        10 = Undetected, clean
        8-9 = Low detections, suspicious only
        5-7 = Some detections, malicious verdict
        1-4 = Heavily detected
        """
        score = 10

        # Verdict penalty
        if verdict == "malicious":
            score -= 3
        elif verdict == "suspicious":
            score -= 1

        # Threat score penalty (0-100 scale)
        if threat_score >= 80:
            score -= 3
        elif threat_score >= 50:
            score -= 2
        elif threat_score >= 20:
            score -= 1

        # AV detection penalty
        if av_detections >= 10:
            score -= 3
        elif av_detections >= 5:
            score -= 2
        elif av_detections >= 1:
            score -= 1

        # Target AV detection (critical)
        if target_detected:
            score -= 2

        return max(1, min(10, score))

    def _extract_behavioral_alerts(self, report: Dict) -> List[Dict]:
        """Extract behavioral detection alerts"""
        alerts = []

        for process in report.get("processes", []):
            if process.get("normalized_path"):
                alerts.append({
                    "type": "process",
                    "action": "created",
                    "path": process["normalized_path"]
                })

        for network_call in report.get("network", []):
            alerts.append({
                "type": "network",
                "action": network_call.get("protocol"),
                "destination": network_call.get("url")
            })

        return alerts[:10]  # Top 10 alerts

    def _generate_recommendations(
        self,
        signatures: List[Dict],
        detected_by: List[str],
        target_detected: bool
    ) -> List[str]:
        """Generate OPSEC improvement recommendations"""
        recommendations = []

        if target_detected:
            recommendations.append(
                f"CRITICAL: Target AV detected the binary. Consider different evasion technique."
            )

        if len(detected_by) > 5:
            recommendations.append(
                "Multiple AV detections. Add obfuscation and anti-analysis techniques."
            )

        # Signature-based recommendations
        sig_names = [s["name"].lower() for s in signatures if s.get("name")]

        if any("createremotethread" in s for s in sig_names):
            recommendations.append(
                "Avoid CreateRemoteThread - use NtCreateThreadEx or thread hijacking instead"
            )

        if any("rwx" in s or "executable memory" in s for s in sig_names):
            recommendations.append(
                "RWX memory detected - use RW → RX pattern with VirtualProtect"
            )

        if any("suspicious" in s and "api" in s for s in sig_names):
            recommendations.append(
                "Suspicious API usage - implement API hashing or indirect syscalls"
            )

        if any("string" in s for s in sig_names):
            recommendations.append(
                "String signatures detected - encrypt strings at compile time"
            )

        if not recommendations:
            recommendations.append(
                "Good OPSEC! Binary shows low detection rates."
            )

        return recommendations

    def _save_report(self, binary_path: str, result: Dict, full_report: Dict):
        """Save detection report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        binary_name = Path(binary_path).stem
        report_file = self.results_dir / f"{binary_name}_{timestamp}.json"

        report_data = {
            "binary": str(binary_path),
            "timestamp": datetime.now().isoformat(),
            "result": result,
            "full_report": full_report
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
