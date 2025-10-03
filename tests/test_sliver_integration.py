"""
Integration Tests for Sliver C2 Adapter
========================================

Tests for Sliver adapter functionality with real Sliver C2 installation.

Requirements:
- Sliver C2 framework must be installed
- Sliver server must be running
- sliver-client must be in PATH

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 2 - Sliver Integration
"""

import unittest
import sys
import time
import subprocess
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from c2_adapters.sliver_adapter import SliverAdapter, generate_sliver_beacon, SliverBeaconInfo
from c2_adapters.config import SliverConfig, Protocol, Architecture, OutputFormat


def check_sliver_installed() -> bool:
    """Check if Sliver is installed"""
    try:
        result = subprocess.run(['which', 'sliver-client'], capture_output=True, timeout=2)
        return result.returncode == 0
    except:
        return False


# Skip all tests if Sliver not installed
SLIVER_AVAILABLE = check_sliver_installed()
skip_msg = "Sliver C2 not installed. Install from: https://github.com/BishopFox/sliver"


@unittest.skipUnless(SLIVER_AVAILABLE, skip_msg)
class TestSliverAdapter(unittest.TestCase):
    """Test Sliver adapter functionality"""
    
    def setUp(self):
        """Set up test configuration"""
        self.config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=443,
            protocol=Protocol.HTTPS,
            architecture=Architecture.X64,
            beacon_name="test_beacon"
        )
    
    def test_adapter_initialization(self):
        """Test adapter initialization"""
        adapter = SliverAdapter(self.config, verbose=False)
        self.assertEqual(adapter.config, self.config)
        self.assertIsNone(adapter.beacon_info)
    
    @unittest.skip("Requires running Sliver server")
    def test_adapter_connection_real_mode(self):
        """Test connection to real Sliver server"""
        adapter = SliverAdapter(self.config, verbose=False)
        result = adapter.connect()
        self.assertTrue(result)
    
    def test_adapter_validate_config(self):
        """Test configuration validation"""
        adapter = SliverAdapter(self.config)
        is_valid, error = adapter.validate_config()
        self.assertTrue(is_valid)
        self.assertIsNone(error)
    
    def test_adapter_supported_protocols(self):
        """Test supported protocols"""
        adapter = SliverAdapter(self.config)
        protocols = adapter.get_supported_protocols()
        self.assertIn('https', protocols)
        self.assertIn('http', protocols)
        self.assertIn('dns', protocols)
        self.assertIn('tcp', protocols)
        self.assertIn('mtls', protocols)
    
    def test_adapter_framework_info(self):
        """Test framework info"""
        adapter = SliverAdapter(self.config)
        info = adapter.get_framework_info()
        self.assertEqual(info['framework'], 'Sliver')
        self.assertIn('protocols', info)
        self.assertIn('features', info)
    
    @unittest.skip("Requires running Sliver server and listener")
    def test_generate_real_shellcode(self):
        """Test real shellcode generation from Sliver"""
        adapter = SliverAdapter(self.config, verbose=True)
        adapter.connect()
        
        shellcode = adapter.generate_shellcode()
        
        self.assertIsInstance(shellcode, bytes)
        self.assertGreater(len(shellcode), 1000)
        self.assertIsNotNone(adapter.beacon_info)
    
    @unittest.skip("Requires running Sliver server and listener")
    def test_generate_beacon_no_obfuscation(self):
        """Test beacon generation without obfuscation"""
        adapter = SliverAdapter(self.config, verbose=False)
        
        result = adapter.generate_beacon(obfuscate=False)
        
        self.assertTrue(result.success)
        self.assertIsNone(result.error_message)
        self.assertIsNotNone(result.shellcode_path)
        self.assertGreater(result.beacon_size, 0)
        self.assertGreater(result.compilation_time, 0)
    
    @unittest.skip("Requires running Sliver server and listener")
    def test_generate_beacon_with_obfuscation(self):
        """Test beacon generation with obfuscation"""
        adapter = SliverAdapter(self.config, verbose=True)
        
        result = adapter.generate_beacon(
            techniques=[],
            obfuscate=True
        )
        
        self.assertTrue(result.success)
        self.assertIsNone(result.error_message)
        self.assertIsNotNone(result.beacon_path)
        self.assertGreater(result.beacon_size, 0)
        self.assertGreater(result.opsec_score, 0)
        self.assertIsNotNone(result.obfuscation_summary)
    
    @unittest.skip("Requires running Sliver server and listener")
    def test_generate_beacon_with_techniques(self):
        """Test beacon generation with Noctis techniques"""
        adapter = SliverAdapter(self.config, verbose=False)
        
        techniques = ['NOCTIS-T124', 'NOCTIS-T118']
        result = adapter.generate_beacon(
            techniques=techniques,
            obfuscate=True
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.techniques_applied, techniques)
    
    @unittest.skip("Requires running Sliver server and listener")
    def test_convenience_function(self):
        """Test generate_sliver_beacon convenience function"""
        result = generate_sliver_beacon(
            listener_host="192.168.1.100",
            listener_port=8443,
            protocol="https",
            architecture="x64",
            obfuscate=True,
            verbose=False
        )
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.metadata)
        self.assertEqual(result.metadata['framework'], 'Sliver')


@unittest.skipUnless(SLIVER_AVAILABLE, skip_msg)
class TestSliverProtocols(unittest.TestCase):
    """Test different Sliver protocols"""
    
    def test_https_protocol_config(self):
        """Test HTTPS protocol configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=443,
            protocol=Protocol.HTTPS
        )
        adapter = SliverAdapter(config)
        is_valid, _ = adapter.validate_config()
        self.assertTrue(is_valid)
    
    def test_http_protocol_config(self):
        """Test HTTP protocol configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=80,
            protocol=Protocol.HTTP
        )
        adapter = SliverAdapter(config)
        is_valid, _ = adapter.validate_config()
        self.assertTrue(is_valid)
    
    def test_dns_protocol_config(self):
        """Test DNS protocol configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=53,
            protocol=Protocol.DNS,
            dns_parent_domain="example.com"
        )
        adapter = SliverAdapter(config)
        is_valid, _ = adapter.validate_config()
        self.assertTrue(is_valid)
    
    def test_tcp_protocol_config(self):
        """Test TCP protocol configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=4444,
            protocol=Protocol.TCP
        )
        adapter = SliverAdapter(config)
        is_valid, _ = adapter.validate_config()
        self.assertTrue(is_valid)
    
    def test_mtls_protocol_config(self):
        """Test mTLS protocol configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=8888,
            protocol=Protocol.MTLS,
            mtls_ca_cert="/tmp/ca.crt",
            mtls_cert="/tmp/client.crt",
            mtls_key="/tmp/client.key"
        )
        adapter = SliverAdapter(config)
        is_valid, _ = adapter.validate_config()
        self.assertTrue(is_valid)


@unittest.skipUnless(SLIVER_AVAILABLE, skip_msg)
class TestSliverArchitectures(unittest.TestCase):
    """Test different architectures"""
    
    def test_x64_architecture_config(self):
        """Test x64 architecture configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=443,
            architecture=Architecture.X64
        )
        adapter = SliverAdapter(config)
        self.assertEqual(config.architecture, Architecture.X64)
    
    def test_x86_architecture_config(self):
        """Test x86 architecture configuration"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=443,
            architecture=Architecture.X86
        )
        adapter = SliverAdapter(config)
        self.assertEqual(config.architecture, Architecture.X86)


class TestSliverBeaconInfo(unittest.TestCase):
    """Test beacon info dataclass"""
    
    def test_beacon_info_creation(self):
        """Test beacon info creation"""
        info = SliverBeaconInfo(
            name="test_beacon",
            protocol="https",
            arch="x64",
            format="shellcode",
            size=50000,
            c2_url="https://c2.example.com:443"
        )
        
        self.assertEqual(info.name, "test_beacon")
        self.assertEqual(info.protocol, "https")
        self.assertEqual(info.size, 50000)
    
    def test_beacon_info_to_dict(self):
        """Test beacon info serialization"""
        info = SliverBeaconInfo(
            name="test_beacon",
            protocol="https",
            arch="x64",
            format="exe",
            size=100000,
            c2_url="https://c2.example.com:443",
            shellcode_path="/tmp/beacon.bin"
        )
        
        data = info.to_dict()
        
        self.assertIsInstance(data, dict)
        self.assertEqual(data['name'], "test_beacon")
        self.assertEqual(data['protocol'], "https")
        self.assertEqual(data['shellcode_path'], "/tmp/beacon.bin")


class TestSliverConfigValidation(unittest.TestCase):
    """Test Sliver configuration validation"""
    
    def test_dns_requires_parent_domain(self):
        """Test DNS protocol requires parent domain"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=53,
            protocol=Protocol.DNS
            # Missing dns_parent_domain
        )
        
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("dns_parent_domain", error.lower())
    
    def test_mtls_requires_certificates(self):
        """Test mTLS requires certificates"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=8888,
            protocol=Protocol.MTLS
            # Missing certificates
        )
        
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("mtls", error.lower())


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

