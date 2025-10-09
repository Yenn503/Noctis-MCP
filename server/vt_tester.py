"""VirusTotal Binary Tester"""
import requests
import hashlib
import time
import os
from pathlib import Path

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VT_URL_SCAN = "https://www.virustotal.com/api/v3/files"
VT_URL_REPORT = "https://www.virustotal.com/api/v3/analyses/{}"


def test_on_virustotal(binary_path, target_edr):
    """
    Test binary on VirusTotal

    Args:
        binary_path: Path to binary
        target_edr: Check this specific EDR

    Returns:
        dict with detection results
    """

    if not VT_API_KEY:
        return {
            "success": False,
            "error": "VirusTotal API key not configured"
        }

    binary_path = Path(binary_path)
    if not binary_path.exists():
        return {
            "success": False,
            "error": f"Binary not found: {binary_path}"
        }

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Upload file
        with open(binary_path, 'rb') as f:
            files = {"file": (binary_path.name, f)}
            response = requests.post(VT_URL_SCAN, headers=headers, files=files, timeout=60)

        if response.status_code != 200:
            return {
                "success": False,
                "error": f"VT upload failed: {response.status_code}"
            }

        analysis_id = response.json()['data']['id']

        # Wait for analysis (max 5 minutes)
        for _ in range(30):  # 30 * 10s = 5 minutes
            time.sleep(10)

            report_response = requests.get(
                VT_URL_REPORT.format(analysis_id),
                headers=headers,
                timeout=30
            )

            if report_response.status_code == 200:
                report = report_response.json()
                status = report['data']['attributes']['status']

                if status == 'completed':
                    stats = report['data']['attributes']['stats']
                    results = report['data']['attributes']['results']

                    # Check target EDR
                    target_result = "Not found"
                    for av_name, av_data in results.items():
                        if target_edr.lower() in av_name.lower():
                            if av_data['category'] in ['malicious', 'suspicious']:
                                target_result = f"✗ DETECTED ({av_data['result']})"
                            else:
                                target_result = "✓ CLEAN"
                            break

                    # Get top detections
                    top_detections = []
                    for av_name, av_data in results.items():
                        if av_data['category'] in ['malicious', 'suspicious']:
                            top_detections.append(f"{av_name}: {av_data['result']}")
                        if len(top_detections) >= 5:
                            break

                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    detection_rate = f"{malicious}/{total}"

                    return {
                        "success": True,
                        "binary": binary_path.name,
                        "detection_rate": detection_rate,
                        "target_edr_result": target_result,
                        "top_detections": top_detections
                    }

        return {
            "success": False,
            "error": "VT analysis timed out (5 minutes)"
        }

    except requests.RequestException as e:
        return {
            "success": False,
            "error": f"VT request failed: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
