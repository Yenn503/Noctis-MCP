"""
Metrics collection and monitoring for Noctis-MCP server
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Thread-safe metrics collector for API endpoint monitoring
    Tracks request counts, response times, and errors
    """

    def __init__(self):
        """Initialize metrics collector"""
        self.lock = threading.Lock()

        # Request counters
        self.request_counts = defaultdict(int)
        self.error_counts = defaultdict(int)

        # Response time tracking
        self.response_times = defaultdict(list)

        # Start time
        self.start_time = datetime.now()

        logger.info("[Metrics] Collector initialized")

    def track_request(self, endpoint: str, duration: float, success: bool = True) -> None:
        """
        Track API request metrics

        Args:
            endpoint: API endpoint name
            duration: Request duration in seconds
            success: Whether request succeeded
        """
        with self.lock:
            self.request_counts[endpoint] += 1

            if not success:
                self.error_counts[endpoint] += 1

            # Store response time
            self.response_times[endpoint].append(duration)

            # Keep only last 100 samples per endpoint to avoid memory bloat
            if len(self.response_times[endpoint]) > 100:
                self.response_times[endpoint] = self.response_times[endpoint][-100:]

    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive metrics statistics

        Returns:
            Dictionary with metrics data
        """
        with self.lock:
            # Calculate total requests
            total_requests = sum(self.request_counts.values())
            total_errors = sum(self.error_counts.values())

            # Calculate average response times
            avg_response_times = {}
            for endpoint, times in self.response_times.items():
                if times:
                    avg_response_times[endpoint] = round(sum(times) / len(times) * 1000, 2)  # Convert to ms

            # Find slowest endpoints
            slowest = sorted(
                [(k, max(v) * 1000) for k, v in self.response_times.items() if v],
                key=lambda x: x[1],
                reverse=True
            )[:5]

            # Find most used endpoints
            most_used = sorted(
                self.request_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]

            # Calculate uptime
            uptime = (datetime.now() - self.start_time).total_seconds()
            uptime_hours = uptime / 3600

            return {
                'uptime_hours': round(uptime_hours, 2),
                'total_requests': total_requests,
                'total_errors': total_errors,
                'error_rate': round((total_errors / total_requests * 100) if total_requests > 0 else 0, 2),
                'requests_by_endpoint': dict(self.request_counts),
                'errors_by_endpoint': dict(self.error_counts),
                'avg_response_time_ms': avg_response_times,
                'slowest_endpoints_ms': slowest,
                'most_used_endpoints': most_used
            }

    def get_endpoint_stats(self, endpoint: str) -> Dict[str, Any]:
        """
        Get detailed stats for specific endpoint

        Args:
            endpoint: Endpoint name

        Returns:
            Endpoint-specific metrics
        """
        with self.lock:
            times = self.response_times.get(endpoint, [])

            if not times:
                return {
                    'endpoint': endpoint,
                    'requests': 0,
                    'errors': 0,
                    'stats': None
                }

            return {
                'endpoint': endpoint,
                'requests': self.request_counts.get(endpoint, 0),
                'errors': self.error_counts.get(endpoint, 0),
                'error_rate': round(
                    (self.error_counts.get(endpoint, 0) / self.request_counts.get(endpoint, 1) * 100),
                    2
                ),
                'stats': {
                    'avg_ms': round(sum(times) / len(times) * 1000, 2),
                    'min_ms': round(min(times) * 1000, 2),
                    'max_ms': round(max(times) * 1000, 2),
                    'median_ms': round(sorted(times)[len(times) // 2] * 1000, 2),
                    'samples': len(times)
                }
            }

    def reset(self) -> None:
        """Reset all metrics (useful for testing)"""
        with self.lock:
            self.request_counts.clear()
            self.error_counts.clear()
            self.response_times.clear()
            self.start_time = datetime.now()
            logger.info("[Metrics] Reset all metrics")


# Global metrics instance
_metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """
    Get global metrics collector instance (singleton pattern)

    Returns:
        MetricsCollector instance
    """
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector
