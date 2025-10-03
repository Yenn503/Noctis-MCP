#!/usr/bin/env python3
"""
Tests for Havoc C2 Integration
================================

Integration tests for Havoc adapter.
"""

import unittest
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from c2_adapters.havoc_adapter import HavocAdapter
from c2_adapters.config import HavocConfig, Protocol, Architecture


class TestHavocAdapter(unittest.TestCase):
    """Test Havoc adapter functionality"""
    
    def test_adapter_initialization(self):
        """Test basic adapter initialization"""
        config = HavocConfig(
            listener_host="192.168.1.100",
            listener_port=443,
            protocol="https"
        )
        
        adapter = HavocAdapter(config, verbose=False)
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.config.listener_host, "192.168.1.100")
        self.assertEqual(adapter.config.listener_port, 443)
    
    def test_adapter_supported_protocols(self):
        """Test that adapter reports correct protocols"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443
        )
        
        adapter = HavocAdapter(config)
        protocols = adapter.get_supported_protocols()
        
        self.assertIn('https', protocols)
        self.assertIn('http', protocols)
        self.assertIn('smb', protocols)
    
    def test_adapter_framework_info(self):
        """Test framework information"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443
        )
        
        adapter = HavocAdapter(config)
        info = adapter.get_framework_info()
        
        self.assertEqual(info['framework'], 'Havoc')
        self.assertEqual(info['status'], 'implemented')
        self.assertIn('Ekko', info['sleep_techniques'])
        self.assertIn('Foliage', info['sleep_techniques'])
    
    def test_adapter_validate_config(self):
        """Test configuration validation"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            protocol="https",
            sleep_technique="Ekko"
        )
        
        adapter = HavocAdapter(config)
        is_valid, errors = adapter.validate_config()
        
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)


class TestHavocProtocols(unittest.TestCase):
    """Test different Havoc protocols"""
    
    def test_https_protocol_config(self):
        """Test HTTPS protocol configuration"""
        config = HavocConfig(
            listener_host="c2.example.com",
            listener_port=443,
            protocol="https"
        )
        
        self.assertEqual(config.protocol, "https")
        self.assertEqual(config.listener_port, 443)
    
    def test_http_protocol_config(self):
        """Test HTTP protocol configuration"""
        config = HavocConfig(
            listener_host="c2.example.com",
            listener_port=80,
            protocol="http"
        )
        
        self.assertEqual(config.protocol, "http")
    
    def test_smb_protocol_config(self):
        """Test SMB protocol configuration"""
        config = HavocConfig(
            listener_host="192.168.1.10",
            listener_port=445,
            protocol="smb"
        )
        
        self.assertEqual(config.protocol, "smb")
        self.assertEqual(config.listener_port, 445)


class TestHavocSleepTechniques(unittest.TestCase):
    """Test Havoc sleep obfuscation techniques"""
    
    def test_ekko_sleep_technique(self):
        """Test Ekko sleep technique configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            sleep_technique="Ekko"
        )
        
        self.assertEqual(config.sleep_technique, "Ekko")
    
    def test_foliage_sleep_technique(self):
        """Test Foliage sleep technique configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            sleep_technique="Foliage"
        )
        
        self.assertEqual(config.sleep_technique, "Foliage")
    
    def test_waitforsingleobject_sleep_technique(self):
        """Test WaitForSingleObjectEx sleep technique"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            sleep_technique="WaitForSingleObjectEx"
        )
        
        self.assertEqual(config.sleep_technique, "WaitForSingleObjectEx")


class TestHavocEvasion(unittest.TestCase):
    """Test Havoc evasion features"""
    
    def test_indirect_syscalls_config(self):
        """Test indirect syscalls configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            indirect_syscalls=True
        )
        
        self.assertTrue(config.indirect_syscalls)
    
    def test_stack_duplication_config(self):
        """Test stack duplication configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            stack_duplication=True
        )
        
        self.assertTrue(config.stack_duplication)
    
    def test_sleep_mask_config(self):
        """Test sleep mask configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            sleep_mask=True
        )
        
        self.assertTrue(config.sleep_mask)


class TestHavocArchitectures(unittest.TestCase):
    """Test different architectures"""
    
    def test_x64_architecture_config(self):
        """Test x64 architecture configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            architecture=Architecture.X64
        )
        
        self.assertEqual(config.architecture, Architecture.X64)
    
    def test_x86_architecture_config(self):
        """Test x86 architecture configuration"""
        config = HavocConfig(
            listener_host="test.com",
            listener_port=443,
            architecture=Architecture.X86
        )
        
        self.assertEqual(config.architecture, Architecture.X86)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)

