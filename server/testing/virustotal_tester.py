"""
VirusTotal Binary Testing Module
=================================
Test compiled binaries against 70+ antivirus engines via VirusTotal API.

Rate Limits (Free API):
- 4 requests/minute
- 500 requests/day
- 15.5K requests/month

Perfect for testing individual compiled binaries.
"""

import os
import time
import hashlib
import logging
import requests
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class VirusTotalTester:
    """Test binaries against VirusTotal's 70+ AV engines"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal tester.

        Args:
            api_key: VirusTotal API key (or set VIRUSTOTAL_API_KEY env var)
        """
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'

        # Rate limiting: 4 requests/min
        self.rate_limit = 4
        self.rate_window = 60  # seconds
        self.request_times = []

        if not self.api_key:
            logger.warning("[VT] No API key configured - testing disabled")

    def is_available(self) -> bool:
        """Check if VirusTotal is configured and available"""
        return bool(self.api_key)

    def _wait_for_rate_limit(self):
        """Enforce rate limit: 4 requests per minute"""
        now = time.time()

        # Remove requests older than rate_window
        self.request_times = [t for t in self.request_times if now - t < self.rate_window]

        # If at limit, wait
        if len(self.request_times) >= self.rate_limit:
            oldest = self.request_times[0]
            wait_time = self.rate_window - (now - oldest) + 1
            if wait_time > 0:
                logger.info(f"[VT] Rate limit reached, waiting {wait_time:.1f}s...")
                time.sleep(wait_time)

        # Record this request
        self.request_times.append(time.time())

    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Check if file hash already exists in VirusTotal database.

        Args:
            file_hash: SHA256 hash of file

        Returns:
            Analysis results if found, None otherwise
        """
        if not self.is_available():
            return None

        self._wait_for_rate_limit()

        headers = {
            'x-apikey': self.api_key
        }

        try:
            response = requests.get(
                f'{self.base_url}/files/{file_hash}',
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return self._parse_analysis(data)
            elif response.status_code == 404:
                logger.info(f"[VT] Hash not found in VT database: {file_hash[:16]}...")
                return None
            else:
                logger.error(f"[VT] API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"[VT] Check hash failed: {e}")
            return None

    def upload_file(self, file_path: str) -> Optional[str]:
        """
        Upload file to VirusTotal for analysis.

        Args:
            file_path: Path to binary file

        Returns:
            Analysis ID if successful, None otherwise
        """
        if not self.is_available():
            return None

        self._wait_for_rate_limit()

        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"[VT] File not found: {file_path}")
            return None

        # Check file size (max 32MB for free API)
        file_size = file_path.stat().st_size
        if file_size > 32 * 1024 * 1024:
            logger.error(f"[VT] File too large: {file_size / (1024*1024):.1f}MB (max 32MB)")
            return None

        headers = {
            'x-apikey': self.api_key
        }

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}

                logger.info(f"[VT] Uploading file: {file_path.name} ({file_size / 1024:.1f} KB)")

                response = requests.post(
                    f'{self.base_url}/files',
                    headers=headers,
                    files=files,
                    timeout=300  # 5 min timeout for upload
                )

            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']
                logger.info(f"[VT] Upload successful, analysis ID: {analysis_id}")
                return analysis_id
            else:
                logger.error(f"[VT] Upload failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"[VT] Upload error: {e}")
            return None

    def get_analysis(self, analysis_id: str, max_wait: int = 300) -> Optional[Dict[str, Any]]:
        """
        Get analysis results, waiting for completion if needed.

        Args:
            analysis_id: VirusTotal analysis ID
            max_wait: Maximum seconds to wait for analysis (default: 300)

        Returns:
            Analysis results dict
        """
        if not self.is_available():
            return None

        start_time = time.time()
        poll_interval = 15  # seconds

        while time.time() - start_time < max_wait:
            self._wait_for_rate_limit()

            headers = {'x-apikey': self.api_key}

            try:
                response = requests.get(
                    f'{self.base_url}/analyses/{analysis_id}',
                    headers=headers,
                    timeout=30
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data['data']['attributes']['status']

                    if status == 'completed':
                        logger.info(f"[VT] Analysis completed")
                        return self._parse_analysis(data)
                    else:
                        logger.info(f"[VT] Analysis status: {status}, waiting {poll_interval}s...")
                        time.sleep(poll_interval)
                else:
                    logger.error(f"[VT] Get analysis failed: {response.status_code}")
                    return None

            except Exception as e:
                logger.error(f"[VT] Get analysis error: {e}")
                return None

        logger.warning(f"[VT] Analysis timeout after {max_wait}s")
        return None

    def _parse_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal analysis response into clean format"""
        try:
            attrs = data['data']['attributes']
            stats = attrs.get('last_analysis_stats', {})
            results = attrs.get('last_analysis_results', {})

            # Extract per-AV results
            av_results = {}
            for av_name, av_data in results.items():
                av_results[av_name] = {
                    'detected': av_data['category'] in ['malicious', 'suspicious'],
                    'category': av_data['category'],
                    'result': av_data.get('result', 'clean')
                }

            # Calculate detection rate
            total = sum(stats.values())
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
            detection_rate = (detected / total * 100) if total > 0 else 0

            return {
                'success': True,
                'file_hash': data['data']['id'],
                'scan_date': attrs.get('last_analysis_date'),
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'failure': stats.get('failure', 0),
                    'total_engines': total,
                    'detection_rate': round(detection_rate, 1)
                },
                'av_results': av_results,
                'detected': detected > 0
            }

        except Exception as e:
            logger.error(f"[VT] Parse error: {e}")
            return {'success': False, 'error': str(e)}

    def test_binary(self, file_path: str, max_wait: int = 300) -> Dict[str, Any]:
        """
        Complete workflow: Check hash → Upload if needed → Get results.

        Args:
            file_path: Path to binary file
            max_wait: Maximum seconds to wait for analysis

        Returns:
            Dict with analysis results
        """
        if not self.is_available():
            return {
                'success': False,
                'error': 'VirusTotal API key not configured',
                'setup_instructions': 'Set VIRUSTOTAL_API_KEY in .env file'
            }

        file_path = Path(file_path)
        if not file_path.exists():
            return {
                'success': False,
                'error': f'File not found: {file_path}'
            }

        logger.info(f"[VT] Testing binary: {file_path.name}")

        # Step 1: Calculate hash
        file_hash = self._get_file_hash(str(file_path))
        logger.info(f"[VT] SHA256: {file_hash}")

        # Step 2: Check if hash exists
        logger.info(f"[VT] Checking if file already scanned...")
        existing = self.check_hash(file_hash)

        if existing and existing.get('success'):
            logger.info(f"[VT] File already in database - using cached results")
            existing['cached'] = True
            return existing

        # Step 3: Upload file for analysis
        logger.info(f"[VT] File not in database - uploading for analysis...")
        analysis_id = self.upload_file(str(file_path))

        if not analysis_id:
            return {
                'success': False,
                'error': 'Failed to upload file to VirusTotal'
            }

        # Step 4: Wait for analysis
        logger.info(f"[VT] Waiting for analysis to complete (max {max_wait}s)...")
        results = self.get_analysis(analysis_id, max_wait)

        if results:
            results['cached'] = False
            return results
        else:
            return {
                'success': False,
                'error': 'Analysis timed out or failed',
                'analysis_id': analysis_id,
                'manual_check': f'https://www.virustotal.com/gui/file/{file_hash}'
            }
