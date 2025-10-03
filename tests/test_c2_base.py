"""
Unit Tests for C2 Base Framework
=================================

Tests for base adapter, configuration system, and shellcode wrapper.

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 1 - Base Framework
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from c2_adapters.base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from c2_adapters.config import (
    C2Config, SliverConfig, HavocConfig, MythicConfig, CustomC2Config,
    Protocol, Architecture, OutputFormat, create_c2_config
)
from c2_adapters.shellcode_wrapper import ShellcodeWrapper, WrapperConfig


class TestC2Config(unittest.TestCase):
    """Test C2 configuration classes"""
    
    def test_base_config_creation(self):
        """Test basic C2Config creation"""
        config = C2Config(
            listener_host="192.168.1.100",
            listener_port=443,
            protocol=Protocol.HTTPS
        )
        self.assertEqual(config.listener_host, "192.168.1.100")
        self.assertEqual(config.listener_port, 443)
        self.assertEqual(config.protocol, Protocol.HTTPS)
    
    def test_base_config_validation_success(self):
        """Test valid configuration passes validation"""
        config = C2Config(
            listener_host="c2.example.com",
            listener_port=8080
        )
        is_valid, error = config.validate()
        self.assertTrue(is_valid)
        self.assertIsNone(error)
    
    def test_base_config_validation_invalid_port(self):
        """Test invalid port fails validation"""
        config = C2Config(
            listener_host="c2.example.com",
            listener_port=70000  # Invalid port
        )
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIsNotNone(error)
        self.assertIn("port", error.lower())
    
    def test_base_config_validation_invalid_jitter(self):
        """Test invalid jitter fails validation"""
        config = C2Config(
            listener_host="c2.example.com",
            listener_port=443,
            jitter=150  # Invalid jitter > 100
        )
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("jitter", error.lower())
    
    def test_sliver_config_creation(self):
        """Test SliverConfig creation"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=443,
            protocol=Protocol.HTTPS,
            sliver_host="127.0.0.1",
            sliver_port=31337,
            obfuscate_symbols=True
        )
        self.assertEqual(config.sliver_host, "127.0.0.1")
        self.assertEqual(config.sliver_port, 31337)
        self.assertTrue(config.obfuscate_symbols)
    
    def test_sliver_config_dns_validation(self):
        """Test Sliver DNS protocol requires parent domain"""
        config = SliverConfig(
            listener_host="c2.example.com",
            listener_port=53,
            protocol=Protocol.DNS
            # Missing dns_parent_domain
        )
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("dns_parent_domain", error.lower())
    
    def test_havoc_config_creation(self):
        """Test HavocConfig creation"""
        config = HavocConfig(
            listener_host="c2.example.com",
            listener_port=443,
            havoc_host="127.0.0.1",
            havoc_port=40056,
            sleep_technique="Ekko",
            indirect_syscalls=True
        )
        self.assertEqual(config.sleep_technique, "Ekko")
        self.assertTrue(config.indirect_syscalls)
    
    def test_havoc_config_invalid_sleep_technique(self):
        """Test Havoc invalid sleep technique fails validation"""
        config = HavocConfig(
            listener_host="c2.example.com",
            listener_port=443,
            sleep_technique="InvalidTechnique"
        )
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("sleep_technique", error.lower())
    
    def test_mythic_config_creation(self):
        """Test MythicConfig creation"""
        config = MythicConfig(
            listener_host="c2.example.com",
            listener_port=443,
            mythic_host="127.0.0.1",
            mythic_port=7443,
            api_key="test-api-key",
            payload_type="apollo"
        )
        self.assertEqual(config.api_key, "test-api-key")
        self.assertEqual(config.payload_type, "apollo")
    
    def test_mythic_config_validation_missing_api_key(self):
        """Test Mythic config fails without API key"""
        config = MythicConfig(
            listener_host="c2.example.com",
            listener_port=443,
            api_key=""  # Empty API key
        )
        is_valid, error = config.validate()
        self.assertFalse(is_valid)
        self.assertIn("api key", error.lower())
    
    def test_custom_config_creation(self):
        """Test CustomC2Config creation"""
        config = CustomC2Config(
            listener_host="c2.example.com",
            listener_port=8080,
            custom_protocol="custom-http",
            beacon_type="reverse",
            encryption_algorithm="aes256"
        )
        self.assertEqual(config.custom_protocol, "custom-http")
        self.assertEqual(config.beacon_type, "reverse")
    
    def test_config_factory_sliver(self):
        """Test config factory creates SliverConfig"""
        config = create_c2_config(
            'sliver',
            listener_host="c2.example.com",
            listener_port=443
        )
        self.assertIsInstance(config, SliverConfig)
    
    def test_config_factory_havoc(self):
        """Test config factory creates HavocConfig"""
        config = create_c2_config(
            'havoc',
            listener_host="c2.example.com",
            listener_port=443
        )
        self.assertIsInstance(config, HavocConfig)
    
    def test_config_factory_invalid_framework(self):
        """Test config factory raises error for invalid framework"""
        with self.assertRaises(ValueError) as context:
            create_c2_config('invalid_framework', listener_host="test", listener_port=443)
        self.assertIn("unsupported", str(context.exception).lower())


class MockC2Adapter(C2Adapter):
    """Mock C2 adapter for testing base class"""
    
    def __init__(self, *args, should_fail=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.should_fail = should_fail
        self.connected = False
    
    def connect(self) -> bool:
        if self.should_fail:
            return False
        self.connected = True
        return True
    
    def generate_shellcode(self) -> bytes:
        if self.should_fail:
            raise Exception("Shellcode generation failed")
        return b'\x90' * 100  # NOP sled for testing
    
    def validate_config(self) -> tuple:
        return self.config.validate()
    
    def get_supported_protocols(self) -> list:
        return ['https', 'http', 'tcp']
    
    def get_framework_info(self) -> dict:
        return {
            'name': 'MockC2',
            'version': '1.0.0',
            'protocols': self.get_supported_protocols()
        }


class TestC2Adapter(unittest.TestCase):
    """Test C2Adapter base class"""
    
    def test_adapter_initialization(self):
        """Test adapter initialization"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, verbose=True)
        self.assertEqual(adapter.config, config)
        self.assertTrue(adapter.verbose)
        self.assertEqual(adapter.get_status(), BeaconStatus.PENDING)
    
    def test_adapter_connect_success(self):
        """Test successful connection"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=False)
        result = adapter.connect()
        self.assertTrue(result)
        self.assertTrue(adapter.connected)
    
    def test_adapter_connect_failure(self):
        """Test failed connection"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=True)
        result = adapter.connect()
        self.assertFalse(result)
    
    def test_adapter_generate_shellcode_success(self):
        """Test successful shellcode generation"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=False)
        shellcode = adapter.generate_shellcode()
        self.assertIsInstance(shellcode, bytes)
        self.assertEqual(len(shellcode), 100)
    
    def test_adapter_generate_shellcode_failure(self):
        """Test shellcode generation failure"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=True)
        with self.assertRaises(Exception):
            adapter.generate_shellcode()
    
    def test_adapter_generate_beacon_success(self):
        """Test successful beacon generation"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=False)
        result = adapter.generate_beacon()
        self.assertIsInstance(result, C2GenerationResult)
        self.assertTrue(result.success)
        self.assertEqual(result.beacon_size, 100)
    
    def test_adapter_generate_beacon_validation_failure(self):
        """Test beacon generation with invalid config"""
        config = C2Config(listener_host="", listener_port=443)  # Invalid host
        adapter = MockC2Adapter(config)
        result = adapter.generate_beacon()
        self.assertFalse(result.success)
        self.assertIn("validation", result.error_message.lower())
    
    def test_adapter_generate_beacon_connection_failure(self):
        """Test beacon generation with connection failure"""
        config = C2Config(listener_host="test.com", listener_port=443)
        adapter = MockC2Adapter(config, should_fail=True)
        result = adapter.generate_beacon()
        self.assertFalse(result.success)
        self.assertIn("connect", result.error_message.lower())
    
    def test_generation_result_to_dict(self):
        """Test C2GenerationResult serialization"""
        result = C2GenerationResult(
            success=True,
            beacon_path="/tmp/beacon.exe",
            beacon_size=50000,
            opsec_score=8.5,
            techniques_applied=["NOCTIS-T124", "NOCTIS-T095"]
        )
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertTrue(result_dict['success'])
        self.assertEqual(result_dict['beacon_path'], "/tmp/beacon.exe")
        self.assertEqual(result_dict['opsec_score'], 8.5)
        self.assertEqual(len(result_dict['techniques_applied']), 2)


class TestShellcodeWrapper(unittest.TestCase):
    """Test shellcode wrapper functionality"""
    
    def test_wrapper_initialization(self):
        """Test wrapper initialization"""
        config = WrapperConfig()
        wrapper = ShellcodeWrapper(config, verbose=True)
        self.assertEqual(wrapper.config, config)
        self.assertTrue(wrapper.verbose)
    
    def test_wrapper_config_defaults(self):
        """Test wrapper config default values"""
        config = WrapperConfig()
        self.assertTrue(config.encrypt_strings)
        self.assertTrue(config.hash_apis)
        self.assertEqual(config.loader_type, "direct")
        self.assertEqual(config.shellcode_encryption, "aes256")
    
    def test_encrypt_shellcode_xor(self):
        """Test XOR shellcode encryption"""
        config = WrapperConfig(shellcode_encryption="xor", shellcode_key="42")
        wrapper = ShellcodeWrapper(config)
        
        original = b'\x90\x90\x90\x90'
        encrypted, key = wrapper.encrypt_shellcode(original)
        
        self.assertIsInstance(encrypted, bytes)
        self.assertEqual(len(encrypted), len(original))
        self.assertNotEqual(encrypted, original)
        self.assertEqual(key, "42")
    
    def test_generate_loader_code(self):
        """Test loader code generation"""
        config = WrapperConfig(loader_type="direct")
        wrapper = ShellcodeWrapper(config)
        
        shellcode = b'\x90\x90\x90\x90'
        key = "42"
        
        loader = wrapper.generate_loader_code(shellcode, key, [])
        
        self.assertIsInstance(loader, str)
        self.assertIn("payload[]", loader)
        self.assertIn("DecryptPayload", loader)
        self.assertIn("ExecuteShellcode", loader)
        self.assertIn("VirtualAlloc", loader)
    
    def test_generate_loader_with_injection(self):
        """Test loader with process injection"""
        config = WrapperConfig(
            loader_type="process_injection",
            injection_target="C:\\Windows\\System32\\notepad.exe"
        )
        wrapper = ShellcodeWrapper(config)
        
        shellcode = b'\x90\x90\x90\x90'
        loader = wrapper.generate_loader_code(shellcode, "42", [])
        
        self.assertIn("CreateProcessA", loader)
        self.assertIn("VirtualAllocEx", loader)
        self.assertIn("WriteProcessMemory", loader)
        self.assertIn("notepad.exe", loader)
    
    def test_wrap_shellcode_basic(self):
        """Test basic shellcode wrapping"""
        config = WrapperConfig(
            shellcode_encryption="xor",
            check_opsec=False  # Skip OPSEC check for test
        )
        wrapper = ShellcodeWrapper(config)
        
        shellcode = b'\x90' * 100
        result = wrapper.wrap_shellcode(shellcode)
        
        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])
        self.assertEqual(result['original_size'], 100)
        self.assertGreater(result['wrapped_size'], 100)


class TestEnumTypes(unittest.TestCase):
    """Test enum types"""
    
    def test_protocol_enum(self):
        """Test Protocol enum values"""
        self.assertEqual(Protocol.HTTPS.value, "https")
        self.assertEqual(Protocol.DNS.value, "dns")
        self.assertEqual(Protocol.TCP.value, "tcp")
    
    def test_architecture_enum(self):
        """Test Architecture enum values"""
        self.assertEqual(Architecture.X64.value, "x64")
        self.assertEqual(Architecture.X86.value, "x86")
    
    def test_output_format_enum(self):
        """Test OutputFormat enum values"""
        self.assertEqual(OutputFormat.EXE.value, "exe")
        self.assertEqual(OutputFormat.SHELLCODE.value, "shellcode")
        self.assertEqual(OutputFormat.DLL.value, "dll")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)

