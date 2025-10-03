#!/usr/bin/env python3
"""
Tests for Mythic C2 Integration
================================

Integration tests for Mythic adapter.
"""

import unittest
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from c2_adapters.mythic_adapter import MythicAdapter
from c2_adapters.config import MythicConfig, Protocol, Architecture


class TestMythicAdapter(unittest.TestCase):
    """Test Mythic adapter functionality"""
    
    def test_adapter_initialization(self):
        """Test basic adapter initialization"""
        config = MythicConfig(
            listener_host="192.168.1.100",
            listener_port=80,
            protocol="http",
            payload_type="apollo",
            c2_profile="http",
            api_key="test_token"
        )
        
        adapter = MythicAdapter(config, verbose=False)
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.config.listener_host, "192.168.1.100")
        self.assertEqual(adapter.config.listener_port, 80)
        self.assertEqual(adapter.config.payload_type, "apollo")
    
    def test_adapter_supported_protocols(self):
        """Test that adapter reports correct protocols"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=443,
            api_key="test"
        )
        
        adapter = MythicAdapter(config)
        protocols = adapter.get_supported_protocols()
        
        self.assertIn('https', protocols)
        self.assertIn('http', protocols)
        self.assertIn('dns', protocols)
        self.assertIn('smb', protocols)
        self.assertIn('websocket', protocols)
    
    def test_adapter_framework_info(self):
        """Test framework information"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=443,
            api_key="test"
        )
        
        adapter = MythicAdapter(config)
        info = adapter.get_framework_info()
        
        self.assertEqual(info['framework'], 'Mythic')
        self.assertEqual(info['status'], 'implemented')
        self.assertIn('Apollo', info['agent_types'])
        self.assertIn('Poseidon', info['agent_types'])
        self.assertIn('x64', info['architectures'])
    
    def test_adapter_validate_config(self):
        """Test configuration validation"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            protocol="http",
            payload_type="apollo",
            c2_profile="http",
            api_key="test_token"
        )
        
        adapter = MythicAdapter(config)
        is_valid, errors = adapter.validate_config()
        
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_adapter_validate_config_invalid_payload(self):
        """Test configuration validation with invalid payload type"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            payload_type="invalid_agent",
            c2_profile="http",
            api_key="test"
        )
        
        adapter = MythicAdapter(config)
        is_valid, errors = adapter.validate_config()
        
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)


class TestMythicProtocols(unittest.TestCase):
    """Test different Mythic protocols"""
    
    def test_http_protocol_config(self):
        """Test HTTP protocol configuration"""
        config = MythicConfig(
            listener_host="c2.example.com",
            listener_port=80,
            protocol="http",
            c2_profile="http",
            api_key="test"
        )
        
        self.assertEqual(config.protocol, "http")
        self.assertEqual(config.c2_profile, "http")
    
    def test_https_protocol_config(self):
        """Test HTTPS protocol configuration"""
        config = MythicConfig(
            listener_host="c2.example.com",
            listener_port=443,
            protocol="https",
            c2_profile="https",
            api_key="test"
        )
        
        self.assertEqual(config.protocol, "https")
        self.assertEqual(config.listener_port, 443)
    
    def test_websocket_protocol_config(self):
        """Test WebSocket protocol configuration"""
        config = MythicConfig(
            listener_host="c2.example.com",
            listener_port=8080,
            protocol="websocket",
            c2_profile="websocket",
            api_key="test"
        )
        
        self.assertEqual(config.c2_profile, "websocket")


class TestMythicAgentTypes(unittest.TestCase):
    """Test different Mythic agent types"""
    
    def test_apollo_agent_config(self):
        """Test Apollo agent configuration"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            payload_type="apollo",
            c2_profile="http",
            api_key="test"
        )
        
        self.assertEqual(config.payload_type, "apollo")
    
    def test_poseidon_agent_config(self):
        """Test Poseidon agent configuration"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            payload_type="poseidon",
            c2_profile="http",
            api_key="test"
        )
        
        self.assertEqual(config.payload_type, "poseidon")
    
    def test_merlin_agent_config(self):
        """Test Merlin agent configuration"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            payload_type="merlin",
            c2_profile="http",
            api_key="test"
        )
        
        self.assertEqual(config.payload_type, "merlin")


class TestMythicArchitectures(unittest.TestCase):
    """Test different architectures"""
    
    def test_x64_architecture_config(self):
        """Test x64 architecture configuration"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            architecture=Architecture.X64,
            api_key="test"
        )
        
        self.assertEqual(config.architecture, Architecture.X64)
    
    def test_x86_architecture_config(self):
        """Test x86 architecture configuration"""
        config = MythicConfig(
            listener_host="test.com",
            listener_port=80,
            architecture=Architecture.X86,
            api_key="test"
        )
        
        self.assertEqual(config.architecture, Architecture.X86)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)

