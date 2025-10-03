"""
Embeds files into PNG images using Discrete Wavelet Transform (DWT) with QIM and ECC
The input can be: PNG/JPG/JPEG/BMP/GIF 
But the output is always PNG 
"""

import sys
import os
import json
import argparse
import struct
import zlib
import subprocess
from pathlib import Path
from typing import Optional, Dict, Tuple, Any
from dataclasses import dataclass

# Auto-install dependencies
def ensure_dependencies():
    """Install required packages if not available"""
    packages = {
        "numpy": "numpy",
        "PyWavelets": "pywt", 
        "pillow": "PIL",
        "reedsolo": "reedsolo"
    }
    
    for pkg_name, import_name in packages.items():
        try:
            __import__(import_name)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                print(f"[-] Failed to install {pkg_name}. Install manually: pip install {pkg_name}")
                sys.exit(1)

ensure_dependencies()

import numpy as np
import pywt
from PIL import Image
from reedsolo import RSCodec, ReedSolomonError

# Windows compression support
try:
    import ctypes
    from ctypes import wintypes
    HAS_WINDOWS_COMPRESSION = True
except ImportError:
    HAS_WINDOWS_COMPRESSION = False

# Configuration constants
@dataclass
class Config:
    # Sync marker for robust header detection
    MARKER: str = '11111111000000001111111100000000'
    
    # Wavelet parameters
    WAVELET: str = 'db1'
    WT_MODE: str = 'periodization'
    
    # Embedding levels and quantization
    LEVEL_PILOT: int = 1      # Header level
    LEVEL_DATA: int = 2       # Data level
    QSTEP_PILOT: float = 24.0 # Pilot quantization step
    QSTEP_DATA: float = 14.0  # Data quantization step
    
    # Repetition coding
    REP_HEADER: int = 9       # Header repetition
    REP_META: int = 3         # Metadata repetition
    
    # Error correction
    ECC_NSYM: int = 32        # Reed-Solomon parity bytes
    
    # Misc
    FORMAT_VERSION: int = 1
    PNG_COMPRESS_LEVEL: int = 1
    HEADER_DUP_AT_L2: bool = True

config = Config()

class Colors:
    """ANSI color codes for terminal output"""
    def __init__(self):
        # Enable colors for TTY terminals
        if sys.stdout.isatty():
            # Try to enable Windows color support
            if os.name == 'nt':
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                except:
                    pass  # Fall back to basic colors
            
            self.BLUE = '\033[94m'
            self.GREEN = '\033[92m' 
            self.YELLOW = '\033[93m'
            self.RED = '\033[91m'
            self.CYAN = '\033[96m'
            self.MAGENTA = '\033[95m'
            self.BOLD = '\033[1m'
            self.GRAY = '\033[90m'
            self.WHITE = '\033[97m'
            self.END = '\033[0m'
        else:
            # Disable colors for non-TTY
            for attr in ['BLUE', 'GREEN', 'YELLOW', 'RED', 'CYAN', 'MAGENTA', 
                        'BOLD', 'GRAY', 'WHITE', 'END']:
                setattr(self, attr, '')

colors = Colors()

def print_banner(title: str):
    """Print a styled banner"""
    border = "=" * 60
    print(f"\n{colors.MAGENTA}{border}{colors.END}")
    print(f"{colors.BOLD}{colors.CYAN}        {title}{colors.END}")
    print(f"{colors.MAGENTA}{border}{colors.END}")

def print_status(message: str, status: str = "info"):
    """Print colored status messages"""
    status_colors = {
        "info": colors.BLUE,
        "success": colors.GREEN, 
        "warning": colors.YELLOW,
        "error": colors.RED
    }
    status_symbols = {
        "info": "[*]",
        "success": "[+]", 
        "warning": "[!]",
        "error": "[-]"
    }
    color = status_colors.get(status, colors.BLUE)
    symbol = status_symbols.get(status, "[i]")
    print(f"{color}{symbol} {message}{colors.END}")

def print_stats(stats: Dict[str, Any]):
    """Print formatted statistics"""
    print(f"\n{colors.BOLD}{colors.BLUE}Statistics:{colors.END}")
    for key, value in stats.items():
        if isinstance(value, (int, float)):
            if key.endswith('_bytes') or key.endswith('_size'):
                print(f"  {colors.GRAY}{key.replace('_', ' ').title()}:{colors.END} {colors.CYAN}{value:,}{colors.END} bytes")
            elif key.endswith('_bits'):
                print(f"  {colors.GRAY}{key.replace('_', ' ').title()}:{colors.END} {colors.YELLOW}{value:,}{colors.END} bits")
            elif key.endswith('_ratio') or key.endswith('_percent'):
                print(f"  {colors.GRAY}{key.replace('_', ' ').title()}:{colors.END} {colors.GREEN}{value:.1f}%{colors.END}")
            else:
                print(f"  {colors.GRAY}{key.replace('_', ' ').title()}:{colors.END} {colors.CYAN}{value}{colors.END}")
        else:
            print(f"  {colors.GRAY}{key.replace('_', ' ').title()}:{colors.END} {colors.WHITE}{value}{colors.END}")

# Windows compression wrapper
class WindowsCompressor:
    """Windows Cabinet compression API wrapper"""
    
    def __init__(self):
        if not HAS_WINDOWS_COMPRESSION or os.name != 'nt':
            raise RuntimeError("Windows compression requires Windows OS and ctypes support")
        
        self._setup_api()
    
    def _setup_api(self):
        """Setup Windows compression API bindings"""
        try:
            self.cabinet = ctypes.WinDLL("Cabinet.dll", use_last_error=True)
        except OSError:
            raise RuntimeError("Cabinet.dll not found. Windows compression APIs unavailable.")
        
        # Function signatures
        self.cabinet.CreateCompressor.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        self.cabinet.CreateCompressor.restype = wintypes.BOOL
        
        self.cabinet.Compress.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.cabinet.Compress.restype = wintypes.BOOL
        
        self.cabinet.CloseCompressor.argtypes = [ctypes.c_void_p]
        self.cabinet.CloseCompressor.restype = None
        
        # Add decompressor functions
        self.cabinet.CreateDecompressor.argtypes = [
            wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        self.cabinet.CreateDecompressor.restype = wintypes.BOOL
        
        self.cabinet.Decompress.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.cabinet.Decompress.restype = wintypes.BOOL
        
        self.cabinet.CloseDecompressor.argtypes = [ctypes.c_void_p]
        self.cabinet.CloseDecompressor.restype = None
    
    def compress(self, data: bytes, algorithm: str = "XPRESS_HUFF") -> bytes:
        """Compress data using Windows compression"""
        alg_map = {"MSZIP": 2, "XPRESS": 3, "XPRESS_HUFF": 4, "LZMS": 5}
        alg_id = alg_map.get(algorithm.upper(), 4)
        
        handle = ctypes.c_void_p()
        if not self.cabinet.CreateCompressor(alg_id, None, ctypes.byref(handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        
        try:
            input_buffer = ctypes.create_string_buffer(data, len(data))
            
            # Get required size
            needed = ctypes.c_size_t(0)
            self.cabinet.Compress(handle, input_buffer, len(data), None, 0, ctypes.byref(needed))
            
            # Compress
            output_buffer = ctypes.create_string_buffer(needed.value)
            actual_size = ctypes.c_size_t(0)
            
            if not self.cabinet.Compress(handle, input_buffer, len(data), 
                                       output_buffer, needed, ctypes.byref(actual_size)):
                raise ctypes.WinError(ctypes.get_last_error())
            
            return output_buffer.raw[:actual_size.value]
        
        finally:
            if handle:
                self.cabinet.CloseCompressor(handle)
    
    def decompress(self, data: bytes, algorithm: str = "XPRESS_HUFF") -> bytes:
        """Decompress data using Windows compression"""
        alg_map = {"MSZIP": 2, "XPRESS": 3, "XPRESS_HUFF": 4, "LZMS": 5}
        alg_id = alg_map.get(algorithm.upper(), 4)
        
        handle = ctypes.c_void_p()
        if not self.cabinet.CreateDecompressor(alg_id, None, ctypes.byref(handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        
        try:
            input_buffer = ctypes.create_string_buffer(data, len(data))
            
            # Get required size
            needed = ctypes.c_size_t(0)
            self.cabinet.Decompress(handle, input_buffer, len(data), None, 0, ctypes.byref(needed))
            
            # Decompress
            output_buffer = ctypes.create_string_buffer(needed.value)
            actual_size = ctypes.c_size_t(0)
            
            if not self.cabinet.Decompress(handle, input_buffer, len(data),
                                         output_buffer, needed, ctypes.byref(actual_size)):
                raise ctypes.WinError(ctypes.get_last_error())
            
            return output_buffer.raw[:actual_size.value]
        
        finally:
            if handle:
                self.cabinet.CloseDecompressor(handle)

# Utility functions
class BitUtils:
    """Bit manipulation utilities"""
    
    @staticmethod
    def bytes_to_bits(data: bytes) -> np.ndarray:
        """Convert bytes to bit array"""
        if not data:
            return np.zeros(0, dtype=np.uint8)
        return np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    
    @staticmethod
    def bits_to_bytes(bits: np.ndarray) -> bytes:
        """Convert bit array to bytes"""
        if bits.size == 0:
            return b""
        # Pad to byte boundary
        padding = 8 - (bits.size % 8) if bits.size % 8 else 0
        if padding:
            bits = np.concatenate([bits, np.zeros(padding, dtype=np.uint8)])
        return np.packbits(bits).tobytes()
    
    @staticmethod
    def string_to_bits(s: str) -> np.ndarray:
        """Convert binary string to bit array"""
        return np.frombuffer(bytearray(s, 'ascii'), dtype=np.uint8) - 48

class CRCUtils:
    """CRC calculation utilities"""
    
    @staticmethod
    def crc16_ccitt(data: bytes) -> int:
        """Calculate CRC16-CCITT"""
        crc = 0xFFFF
        poly = 0x1021
        
        for byte in data:
            crc ^= (byte << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ poly) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        
        return crc

class Header:
    """Header management for steganographic data"""
    
    STRUCT_FORMAT = '<BBBBfIIIH'  # version, rep_meta, ecc_nsym, level_data, qstep_data, meta_len, data_len, data_crc, header_crc
    SIZE = struct.calcsize(STRUCT_FORMAT)
    BITS_SIZE = SIZE * 8
    
    def __init__(self, version: int, rep_meta: int, ecc_nsym: int, level_data: int,
                 qstep_data: float, meta_len_bits: int, data_len_bits: int, data_crc32: int):
        self.version = version
        self.rep_meta = rep_meta
        self.ecc_nsym = ecc_nsym
        self.level_data = level_data
        self.qstep_data = qstep_data
        self.meta_len_bits = meta_len_bits
        self.data_len_bits = data_len_bits
        self.data_crc32 = data_crc32
    
    def pack(self) -> bytes:
        """Pack header to bytes with CRC"""
        body = struct.pack('<BBBBfIII', 
                          self.version, self.rep_meta, self.ecc_nsym, self.level_data,
                          self.qstep_data, self.meta_len_bits, self.data_len_bits, self.data_crc32)
        header_crc = CRCUtils.crc16_ccitt(body)
        print(f"[dbg] Header bytes (hex): {' '.join(f'{b:02X}' for b in body[:8])}")
        return body + struct.pack('<H', header_crc)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'Header':
        """Unpack header from bytes with CRC verification"""
        if len(data) != cls.SIZE:
            raise ValueError(f"Invalid header size: {len(data)} != {cls.SIZE}")
        
        body = data[:-2]
        stored_crc = struct.unpack('<H', data[-2:])[0]
        calculated_crc = CRCUtils.crc16_ccitt(body)
        
        if stored_crc != calculated_crc:
            raise ValueError(f"Header CRC mismatch: {stored_crc:04X} != {calculated_crc:04X}")
        
        values = struct.unpack('<BBBBfIII', body)
        return cls(*values)

class QIMSteganography:
    """Quantization Index Modulation steganography"""
    
    def __init__(self, wavelet: str = 'db1', mode: str = 'periodization'):
        self.wavelet = wavelet
        self.mode = mode
    
    def get_dwt_details(self, coeffs: list, level: int) -> Tuple[Tuple, int, int]:
        """Get detail coefficients for specified level"""
        total_levels = len(coeffs) - 1
        if total_levels < 1:
            raise ValueError("No detail levels available")
        
        level = max(1, min(level, total_levels))
        idx = 1 + (total_levels - level)
        return coeffs[idx], idx, total_levels
    
    def calculate_capacity(self, image: np.ndarray, level: int) -> Tuple[int, int]:
        """Calculate embedding capacity for given level"""
        if image.ndim == 2:
            test_channel = image.astype(float)
        else:
            test_channel = image[:, :, 0].astype(float)
        
        coeffs = pywt.wavedec2(test_channel, self.wavelet, level=level, mode=self.mode)
        (cH, cV, cD), _, _ = self.get_dwt_details(coeffs, level)
        
        per_channel = cH.size + cV.size + cD.size
        channels = min(3, image.shape[2] if image.ndim == 3 else 1)
        
        return per_channel * channels, per_channel
    
    def embed_qim(self, detail: np.ndarray, bits: np.ndarray, start_idx: int, qstep: float) -> Tuple[int, int]:
        """Embed bits into detail coefficients using QIM"""
        flat = detail.ravel()
        remaining = bits.size - start_idx
        if remaining <= 0:
            return start_idx, 0
        
        count = min(flat.size, remaining)
        coeffs = flat[:count]
        bit_values = bits[start_idx:start_idx + count]
        
        # QIM embedding
        base = np.floor(coeffs / qstep) * qstep
        d0, d1 = qstep / 4.0, 3.0 * qstep / 4.0
        
        targets = np.where(bit_values == 0, base + d0, base + d1)
        
        # Adjust for quantization boundaries
        diff = coeffs - targets
        targets += np.where(diff > qstep/2, qstep, 0.0)
        targets -= np.where(diff < -qstep/2, qstep, 0.0)
        
        flat[:count] = targets
        detail[:] = flat.reshape(detail.shape)
        
        return start_idx + count, count
    
    def extract_qim(self, detail: np.ndarray, qstep: float, max_bits: Optional[int] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Extract bits from detail coefficients using QIM"""
        flat = detail.ravel()
        if max_bits is not None:
            flat = flat[:max_bits]
        
        remainder = flat - np.floor(flat / qstep) * qstep
        d0, d1 = qstep / 4.0, 3.0 * qstep / 4.0
        
        # Calculate decision scores
        scores = np.abs(remainder - d1) - np.abs(remainder - d0)
        bits = (scores < 0).astype(np.uint8)
        
        return bits, scores

class RepetitionCoder:
    """Repetition coding for error resilience"""
    
    @staticmethod
    def encode(bits: np.ndarray, repetitions: int) -> np.ndarray:
        """Encode bits with repetition"""
        if repetitions <= 1 or bits.size == 0:
            return bits
        return np.repeat(bits, repetitions)
    
    @staticmethod
    def decode_soft(scores: np.ndarray, repetitions: int, invert: bool = False) -> np.ndarray:
        """Soft decode using scores (majority voting)"""
        if repetitions <= 1:
            return (scores < 0).astype(np.uint8) if not invert else (scores > 0).astype(np.uint8)
        
        # Reshape and sum scores
        valid_length = (scores.size // repetitions) * repetitions
        if valid_length == 0:
            return np.zeros(0, dtype=np.uint8)
        
        summed_scores = scores[:valid_length].reshape(-1, repetitions).sum(axis=1)
        return (summed_scores < 0).astype(np.uint8) if not invert else (summed_scores > 0).astype(np.uint8)

class SteganographyEngine:
    """Main steganography processing engine"""
    
    def __init__(self):
        self.qim = QIMSteganography(config.WAVELET, config.WT_MODE)
        self.marker_bits = BitUtils.string_to_bits(config.MARKER)
        
        # Try to initialize Windows compressor (required)
        try:
            self.compressor = WindowsCompressor()
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Windows compressor: {e}. This tool requires Windows OS.")
    
    def load_image(self, path: str) -> Tuple[np.ndarray, str]:
        """Load PNG image as array"""
        img = Image.open(path)
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGBA')
        return np.array(img), img.mode
    
    def save_image(self, array: np.ndarray, path: str):
        """Save array as PNG image"""
        if array.ndim == 3:
            mode = 'RGBA' if array.shape[2] == 4 else 'RGB'
        else:
            mode = 'L'
        
        Image.fromarray(array.astype(np.uint8), mode).save(
            path, 'PNG', compress_level=config.PNG_COMPRESS_LEVEL)
    
    def compress_file(self, file_path: str) -> Tuple[bytes, bytes]:
        """Read and compress file using Windows compression only"""
        with open(file_path, 'rb') as f:
            original = f.read()
        
        if not self.compressor:
            raise RuntimeError("Windows compression not available. This tool requires Windows OS.")
        
        compressed = self.compressor.compress(original)
        return original, compressed
    
    def create_metadata(self, file_path: str, original_size: int) -> Tuple[str, bytes]:
        """Create file metadata"""
        metadata = {
            'filename': os.path.basename(file_path),
            'extension': os.path.splitext(file_path)[1],
            'original_size': original_size
        }
        json_str = json.dumps(metadata, separators=(',', ':'))
        return json_str, json_str.encode('utf-8')
    
    def embed_file(self, carrier_path: str, file_path: str, output_path: str, verbose: bool = False) -> int:
        """Embed file into carrier image"""
        print_banner("DWT Steganography - File Embedding")
        
        # Validate inputs
        if not Path(carrier_path).exists():
            print_status(f"Carrier image not found: {carrier_path}", "error")
            return 1
        
        if not Path(file_path).exists():
            print_status(f"File to embed not found: {file_path}", "error") 
            return 1
        
        # Load carrier image
        print_status("Loading carrier image...")
        image, mode = self.load_image(carrier_path)
        
        # Prepare RGB array
        if image.ndim == 2:
            rgb_image = np.stack([image, image, image], axis=2)
        else:
            rgb_image = image[:, :, :3] if image.shape[2] >= 3 else image
        
        # Compress file and create metadata
        print_status("Compressing file...")
        original_data, compressed_data = self.compress_file(file_path)
        
        # Apply ECC
        print_status("Applying error correction...")
        ecc_codec = RSCodec(config.ECC_NSYM)
        protected_data = ecc_codec.encode(compressed_data)
        data_crc = zlib.crc32(compressed_data) & 0xffffffff
        
        # Create metadata
        meta_str, meta_bytes = self.create_metadata(file_path, len(original_data))
        
        # Create header
        header = Header(
            version=config.FORMAT_VERSION,
            rep_meta=config.REP_META,
            ecc_nsym=config.ECC_NSYM,
            level_data=config.LEVEL_DATA,
            qstep_data=config.QSTEP_DATA,
            meta_len_bits=len(meta_bytes) * 8,
            data_len_bits=len(protected_data) * 8,
            data_crc32=data_crc
        )
        
        # Check capacity
        pilot_capacity, _ = self.qim.calculate_capacity(rgb_image, config.LEVEL_PILOT)
        data_capacity, _ = self.qim.calculate_capacity(rgb_image, config.LEVEL_DATA)
        
        # Build bitstreams
        header_bits = BitUtils.bytes_to_bits(header.pack())
        header_repeated = RepetitionCoder.encode(header_bits, config.REP_HEADER)
        pilot_stream = np.concatenate([self.marker_bits, header_repeated])
        
        meta_bits = BitUtils.bytes_to_bits(meta_bytes)
        meta_repeated = RepetitionCoder.encode(meta_bits, config.REP_META)
        data_bits = BitUtils.bytes_to_bits(bytes(protected_data))
        
        # Build data stream
        data_stream_parts = []
        if config.HEADER_DUP_AT_L2:
            data_stream_parts.append(pilot_stream)  # Duplicate header
        data_stream_parts.extend([meta_repeated, data_bits])
        data_stream = np.concatenate(data_stream_parts)
        
        # Capacity check
        if pilot_stream.size > pilot_capacity:
            print_status(f"Pilot data too large: {pilot_stream.size} > {pilot_capacity} bits", "error")
            return 1
        
        if data_stream.size > data_capacity:
            print_status(f"Data too large: {data_stream.size:,} > {data_capacity:,} bits", "error")
            print_status("Try using a larger carrier image", "warning")
            return 1
        
        # Display statistics
        stats = {
            'original_size': len(original_data),
            'compressed_size': len(compressed_data),
            'compression_ratio': (1 - len(compressed_data) / max(1, len(original_data))) * 100,
            'protected_size': len(protected_data),
            'pilot_bits': pilot_stream.size,
            'data_bits': data_stream.size,
            'pilot_capacity': pilot_capacity,
            'data_capacity': data_capacity
        }
        print_stats(stats)
        
        # Embed data
        print_status("Embedding data...")
        stego_image = self._embed_multi_level(image, {
            config.LEVEL_PILOT: pilot_stream,
            config.LEVEL_DATA: data_stream
        }, {
            config.LEVEL_PILOT: config.QSTEP_PILOT,
            config.LEVEL_DATA: config.QSTEP_DATA
        })
        
        # Save result
        self.save_image(stego_image, output_path)
        file_size = Path(output_path).stat().st_size
        
        print_status(f"Success! Stego image saved: {output_path} ({file_size:,} bytes)", "success")
        
        # Verification if verbose
        if verbose:
            print_status("Verifying embedding...", "info")
            temp_output = output_path + ".verify.tmp"
            if self.extract_file(output_path, temp_output, verbose=False) == 0:
                Path(temp_output).unlink(missing_ok=True)
                print_status("Verification successful", "success")
        
        return 0
    
    def extract_file(self, stego_path: str, output_path: str, verbose: bool = False) -> int:
        """Extract embedded file from stego image"""
        print_banner("DWT Steganography - File Extraction")
        
        if not Path(stego_path).exists():
            print_status(f"Stego image not found: {stego_path}", "error")
            return 1
        
        # Load stego image
        print_status("Loading stego image...")
        image, mode = self.load_image(stego_path)
        
        print_status("Searching for embedded data...")
        
        # Try to find header
        max_level = max(config.LEVEL_PILOT, config.LEVEL_DATA)
        header_info = self._find_header(image, max_level)
        
        if not header_info:
            print_status("No valid header found", "error")
            return 1
        
        header, invert = header_info
        print_status(f"Header found (invert={invert})", "success")
        
        # Extract data
        print_status("Extracting payload...")
        try:
            extracted_data = self._extract_payload(image, header, invert, max_level)
            
            # Save extracted file
            with open(output_path, 'wb') as f:
                f.write(extracted_data)
            
            file_size = len(extracted_data)
            print_status(f"Success! File extracted: {output_path} ({file_size:,} bytes)", "success")
            
            return 0
            
        except Exception as e:
            print_status(f"Extraction failed: {e}", "error")
            return 1
    
    def _embed_multi_level(self, image: np.ndarray, level_streams: Dict[int, np.ndarray], 
                          level_qsteps: Dict[int, float]) -> np.ndarray:
        """Embed multiple bitstreams at different DWT levels"""
        # Prepare channels
        if image.ndim == 2:
            channels = [image.astype(float)] * 3
            alpha = None
        else:
            alpha = image[:, :, 3].copy() if image.shape[2] >= 4 else None
            channels = [image[:, :, i].astype(float) for i in range(min(3, image.shape[2]))]
            if len(channels) < 3:
                channels.extend([channels[0]] * (3 - len(channels)))
        
        max_level = max(level_streams.keys())
        bit_indices = {level: 0 for level in level_streams}
        
        stego_channels = []
        
        for ch_idx, channel in enumerate(channels):
            # Decompose
            coeffs = pywt.wavedec2(channel, config.WAVELET, level=max_level, mode=config.WT_MODE)
            
            # Embed at each level
            for level in sorted(level_streams.keys()):
                bits = level_streams[level]
                qstep = level_qsteps[level]
                
                (cH, cV, cD), coeff_idx, _ = self.qim.get_dwt_details(coeffs, level)
                
                # Embed in each detail subband
                for detail in [cH, cV, cD]:
                    bit_indices[level], _ = self.qim.embed_qim(detail, bits, bit_indices[level], qstep)
                
                coeffs[coeff_idx] = (cH, cV, cD)
            
            # Reconstruct
            reconstructed = pywt.waverec2(coeffs, config.WAVELET, mode=config.WT_MODE)
            reconstructed = reconstructed[:channel.shape[0], :channel.shape[1]]
            stego_channels.append(reconstructed)
        
        # Combine channels
        stego = np.stack(stego_channels, axis=2)
        stego = np.clip(np.round(stego), 0, 255).astype(np.uint8)
        
        if alpha is not None:
            alpha_clipped = np.clip(np.round(alpha), 0, 255).astype(np.uint8)
            stego = np.dstack([stego, alpha_clipped])
        
        return stego
    
    def _extract_bitstream(self, image: np.ndarray, level: int, qstep: float, 
                          max_level: int) -> Tuple[np.ndarray, np.ndarray]:
        """Extract bitstream from specific DWT level"""
        # Prepare channels
        if image.ndim == 2:
            channels = [image.astype(float)]
        else:
            channels = [image[:, :, i].astype(float) for i in range(min(3, image.shape[2]))]
        
        all_bits, all_scores = [], []
        
        for channel in channels[:3]:  # Use up to 3 channels
            coeffs = pywt.wavedec2(channel, config.WAVELET, level=max_level, mode=config.WT_MODE)
            (cH, cV, cD), _, _ = self.qim.get_dwt_details(coeffs, level)
            
            for detail in [cH, cV, cD]:
                bits, scores = self.qim.extract_qim(detail, qstep)
                all_bits.append(bits)
                all_scores.append(scores)
        
        combined_bits = np.concatenate(all_bits) if all_bits else np.zeros(0, dtype=np.uint8)
        combined_scores = np.concatenate(all_scores) if all_scores else np.zeros(0, dtype=float)
        
        return combined_bits, combined_scores
    
    def _find_header(self, image: np.ndarray, max_level: int) -> Optional[Tuple[Header, bool]]:
        """Find and decode header from image"""
        # Try different extraction strategies
        strategies = [
            (config.LEVEL_PILOT, config.QSTEP_PILOT, False),
            (config.LEVEL_PILOT, config.QSTEP_PILOT, True),
            (config.LEVEL_DATA, config.QSTEP_DATA, False),
            (config.LEVEL_DATA, config.QSTEP_DATA, True)
        ]
        
        for level, qstep, invert in strategies:
            try:
                header = self._try_extract_header(image, level, qstep, invert, max_level)
                if header:
                    return header, invert
            except:
                continue
        
        return None
    
    def _try_extract_header(self, image: np.ndarray, level: int, qstep: float, 
                           invert: bool, max_level: int) -> Optional[Header]:
        """Try to extract header from specific level with given parameters"""
        bits, scores = self._extract_bitstream(image, level, qstep, max_level)
        
        # Need enough bits for marker + header
        min_bits_needed = self.marker_bits.size + Header.BITS_SIZE * config.REP_HEADER
        if bits.size < min_bits_needed:
            return None
        
        # Convert scores to hard bits
        hard_bits = (scores < 0).astype(np.uint8) if not invert else (scores > 0).astype(np.uint8)
        
        # Find marker
        marker_str = ''.join(str(b) for b in hard_bits[:min(hard_bits.size, min_bits_needed + 1000)])
        marker_target = ''.join(str(b) for b in self.marker_bits)
        
        marker_pos = marker_str.find(marker_target)
        if marker_pos == -1:
            return None
        
        # Extract header
        header_start = marker_pos + self.marker_bits.size
        header_end = header_start + Header.BITS_SIZE * config.REP_HEADER
        
        if header_end > scores.size:
            return None
        
        header_scores = scores[header_start:header_end]
        header_bits = RepetitionCoder.decode_soft(header_scores, config.REP_HEADER, invert)
        header_bytes = BitUtils.bits_to_bytes(header_bits)
        
        return Header.unpack(header_bytes)
    
    def _extract_payload(self, image: np.ndarray, header: Header, invert: bool, 
                        max_level: int) -> bytes:
        """Extract and decode the embedded payload"""
        # Extract data bitstream
        data_bits, data_scores = self._extract_bitstream(
            image, header.level_data, header.qstep_data, max_level
        )
        
        # Skip header duplicate if present
        start_offset = 0
        if config.HEADER_DUP_AT_L2:
            pilot_header_bits = self.marker_bits.size + Header.BITS_SIZE * config.REP_HEADER
            start_offset = pilot_header_bits
        
        # Extract metadata
        meta_end = start_offset + header.meta_len_bits * header.rep_meta
        if meta_end > data_scores.size:
            raise ValueError("Not enough data for metadata")
        
        meta_scores = data_scores[start_offset:meta_end]
        meta_bits = RepetitionCoder.decode_soft(meta_scores, header.rep_meta, invert)
        meta_bytes = BitUtils.bits_to_bytes(meta_bits)
        metadata = json.loads(meta_bytes.decode('utf-8'))
        
        # Extract payload data
        payload_start = meta_end
        payload_end = payload_start + header.data_len_bits
        
        if payload_end > data_scores.size:
            raise ValueError("Not enough data for payload")
        
        payload_scores = data_scores[payload_start:payload_end]
        payload_bits = (payload_scores < 0).astype(np.uint8) if not invert else (payload_scores > 0).astype(np.uint8)
        payload_bytes = BitUtils.bits_to_bytes(payload_bits)
        
        # ECC decode
        ecc_codec = RSCodec(header.ecc_nsym)
        try:
            decoded = ecc_codec.decode(payload_bytes)
            compressed_data = bytes(decoded[0] if isinstance(decoded, tuple) else decoded)
        except ReedSolomonError:
            raise ValueError("ECC decode failed - too many errors")
        
        # Verify CRC
        calculated_crc = zlib.crc32(compressed_data) & 0xffffffff
        if calculated_crc != header.data_crc32:
            raise ValueError(f"CRC mismatch: {calculated_crc:08X} != {header.data_crc32:08X}")
        
        # Decompress
        original_data = self.compressor.decompress(compressed_data)
        
        # Verify size if available
        if 'original_size' in metadata:
            expected_size = metadata['original_size']
            if len(original_data) != expected_size:
                print_status(f"Size mismatch: expected {expected_size}, got {len(original_data)}", "warning")
        
        return original_data

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="DWT-based steganography tool for hiding files in PNG images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Embed a file (input can be JPG, PNG, BMP, etc.)
  python steg_tool.py --encode --png meme.jpg --file secret.exe --output stego.png
  
  # Extract a file (PNG recommended for best results)
  python steg_tool.py --decode --png stego.png --output extracted.exe
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--encode', action='store_true', help='Encode/embed a file')
    mode_group.add_argument('--decode', action='store_true', help='Decode/extract a file')
    
    # Common arguments
    parser.add_argument('--png', required=True, help='PNG image file')
    parser.add_argument('--output', required=True, help='Output file path')
    
    # Encode-specific arguments
    parser.add_argument('--file', help='File to embed (required for --encode)')
    
    # Options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.encode and not args.file:
        parser.error("--file is required when using --encode")
    
    # Create engine and process
    engine = SteganographyEngine()
    
    try:
        if args.encode:
            return engine.embed_file(args.png, args.file, args.output, args.verbose)
        else:
            return engine.extract_file(args.png, args.output, args.verbose)
    
    except KeyboardInterrupt:
        print_status("Operation cancelled by user", "error")
        return 130
    except Exception as e:
        print_status(f"Unexpected error: {e}", "error")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())