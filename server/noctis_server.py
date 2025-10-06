#!/usr/bin/env python3
"""
Noctis-MCP Server
==================

Main Flask API server for the Noctis-MCP malware development platform.
This server provides endpoints for:
- Technique querying
- Code generation
- Compilation
- OPSEC analysis
- Learning and knowledge management

Author: Noctis-MCP Community
License: MIT

Usage:
    python server/noctis_server.py

    Optional arguments:
      --host HOST     Host to bind to (default: 127.0.0.1)
      --port PORT     Port to bind to (default: 8888)
      --debug         Enable debug mode
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from flask import Flask, request, jsonify, Response
from flask import send_file
import yaml

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(log_level: str = "INFO", log_file: str = "logs/noctis.log"):
    """Configure logging for the server"""
    # Create logs directory if it doesn't exist
    Path("logs").mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file)
        ]
    )
    return logging.getLogger(__name__)


# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class Config:
    """Configuration management for Noctis-MCP Server"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from YAML file"""
        if not Path(self.config_file).exists():
            # Return default config
            return self._default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found at {self.config_file}. Using defaults.")
            return self._default_config()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML config file: {e}. Using defaults.")
            return self._default_config()
        except Exception as e:
            logger.warning(f"An unexpected error occurred while loading config: {e}. Using defaults.")
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'server': {
                'host': '127.0.0.1',
                'port': 8888,
                'debug': False
            },
            'paths': {
                'examples': 'Examples',
                'techniques': 'techniques',
                'output': 'output',
                'cache': 'cache'
            },
            'opsec': {
                'auto_fix': True
            },
            'features': {
                'code_generation': True,
                'compilation': True,
                'opsec_analysis': True
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default


# ============================================================================
# TECHNIQUE MANAGEMENT
# ============================================================================

class TechniqueManager:
    """Manages technique metadata and querying"""
    
    def __init__(self, metadata_path: str = "techniques/metadata"):
        self.metadata_path = Path(metadata_path)
        self.techniques: Dict[str, Dict] = {}
        self.load_techniques()
    
    def load_techniques(self):
        """Load all technique metadata from JSON files"""
        if not self.metadata_path.exists():
            logger.warning(f"Metadata path does not exist: {self.metadata_path}")
            logger.info("Run 'python utils/technique_indexer.py' to generate metadata")
            return
        
        json_files = list(self.metadata_path.glob('*.json'))
        if not json_files:
            logger.warning("No technique metadata files found")
            return
        
        for json_file in json_files:
            if json_file.name == 'index.json':
                continue  # Skip index file
            
            try:
                with open(json_file, 'r') as f:
                    technique_data = json.load(f)
                    technique_id = technique_data.get('technique_id', json_file.stem)
                    self.techniques[technique_id] = technique_data
            except FileNotFoundError:
                logger.error(f"Technique file not found: {json_file}")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from {json_file}: {e}")
            except Exception as e:
                logger.error(f"An unexpected error occurred loading {json_file}: {e}")
        
        logger.info(f"Loaded {len(self.techniques)} techniques")
    
    def get_all(self) -> List[Dict]:
        """Get all techniques"""
        return list(self.techniques.values())
    
    def get_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_by_category(self, category: str) -> List[Dict]:
        """Get techniques by category"""
        return [
            t for t in self.techniques.values()
            if t.get('category', '').lower() == category.lower()
        ]
    
    def search(self, query: str) -> List[Dict]:
        """Search techniques by name or description"""
        query_lower = query.lower()
        return [
            t for t in self.techniques.values()
            if query_lower in t.get('name', '').lower() or
               query_lower in t.get('description', '').lower()
        ]
    
    def get_by_mitre(self, mitre_id: str) -> List[Dict]:
        """Get techniques by MITRE ATT&CK ID"""
        return [
            t for t in self.techniques.values()
            if mitre_id in t.get('mitre_attack', [])
        ]


# ============================================================================
# FLASK APPLICATION
# ============================================================================

# Initialize logger (will be properly configured in main)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Global instances (initialized in main)
config: Config = None
technique_manager: TechniqueManager = None
agent_registry = None  # Agent registry (initialized in main)


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'techniques_loaded': len(technique_manager.techniques) if technique_manager else 0
    })


@app.route('/api/techniques', methods=['GET'])
def get_techniques():
    """
    Get all techniques or filter by parameters
    
    Query parameters:
      - category: Filter by category
      - mitre: Filter by MITRE ATT&CK ID
      - search: Search by name/description
    """
    # Get query parameters
    category = request.args.get('category')
    mitre = request.args.get('mitre')
    search = request.args.get('search')
    
    # Apply filters
    if category:
        techniques = technique_manager.get_by_category(category)
    elif mitre:
        techniques = technique_manager.get_by_mitre(mitre)
    elif search:
        techniques = technique_manager.search(search)
    else:
        techniques = technique_manager.get_all()
    
    return jsonify({
        'success': True,
        'count': len(techniques),
        'techniques': techniques
    })


@app.route('/api/techniques/<technique_id>', methods=['GET'])
def get_technique(technique_id: str):
    """Get a specific technique by ID"""
    technique = technique_manager.get_by_id(technique_id)
    
    if not technique:
        return jsonify({
            'success': False,
            'error': f'Technique {technique_id} not found'
        }), 404
    
    return jsonify({
        'success': True,
        'technique': technique
    })


@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Get all available technique categories"""
    categories = {}
    for technique in technique_manager.get_all():
        cat = technique.get('category', 'other')
        categories[cat] = categories.get(cat, 0) + 1
    
    return jsonify({
        'success': True,
        'categories': [
            {'name': cat, 'count': count}
            for cat, count in sorted(categories.items())
        ]
    })


@app.route('/api/mitre', methods=['GET'])
def get_mitre_mappings():
    """Get all MITRE ATT&CK mappings"""
    mitre_map = {}
    for technique in technique_manager.get_all():
        for mitre_id in technique.get('mitre_attack', []):
            if mitre_id not in mitre_map:
                mitre_map[mitre_id] = []
            mitre_map[mitre_id].append({
                'id': technique.get('technique_id'),
                'name': technique.get('name')
            })
    
    return jsonify({
        'success': True,
        'mappings': mitre_map
    })


@app.route('/api/generate', methods=['POST'])
def generate_code():
    """
    Generate malware code based on specifications
    
    Request body:
      - techniques: List of technique IDs to combine (required)
      - target_os: Target operating system (default: Windows)
      - payload_type: Type of payload (default: loader)
      - obfuscate_strings: Enable string encryption (default: False)
      - obfuscate_apis: Enable API hashing (default: False)
      - encryption_method: String encryption method: xor, aes, rc4 (default: xor)
      - hash_method: API hash method: djb2, rot13xor, crc32 (default: djb2)
      - flatten_control_flow: Enable control flow flattening (default: False)
      - insert_junk_code: Enable junk code insertion (default: False)
      - junk_density: Junk code density: low, medium, high (default: medium)
      - polymorphic: Enable polymorphic code generation (default: False)
      - mutation_level: Polymorphic mutation level: low, medium, high (default: medium)
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data provided'
        }), 400
    
    techniques = data.get('techniques', [])
    target_os = data.get('target_os', 'Windows')
    payload_type = data.get('payload_type', 'loader')
    obfuscate_strings = data.get('obfuscate_strings', False)
    obfuscate_apis = data.get('obfuscate_apis', False)
    encryption_method = data.get('encryption_method', 'xor')
    hash_method = data.get('hash_method', 'djb2')
    flatten_control_flow = data.get('flatten_control_flow', False)
    insert_junk_code = data.get('insert_junk_code', False)
    junk_density = data.get('junk_density', 'medium')
    polymorphic = data.get('polymorphic', False)
    mutation_level = data.get('mutation_level', 'medium')
    
    if not techniques:
        return jsonify({
            'success': False,
            'error': 'No techniques specified'
        }), 400
    
    try:
        # Import code assembler
        from server.code_assembler import CodeAssembler
        
        logger.info(f"Generating code for {len(techniques)} techniques")
        assembler = CodeAssembler()
        result = assembler.assemble(techniques)
        
        code = result.source_code
        additional_code = ""
        obfuscation_info = {}
        
        # Apply obfuscation if requested
        if obfuscate_strings:
            logger.info(f"Applying string encryption: {encryption_method}")
            from server.obfuscation import StringEncryptor
            
            encryptor = StringEncryptor(method=encryption_method)
            code, decryption_funcs = encryptor.encrypt_code(code)
            additional_code += decryption_funcs + "\n"
            
            obfuscation_info['strings_encrypted'] = len(encryptor.encrypted_strings)
            obfuscation_info['encryption_method'] = encryption_method
        
        if obfuscate_apis:
            logger.info(f"Applying API hashing: {hash_method}")
            from server.obfuscation import APIHasher
            
            hasher = APIHasher(hash_method=hash_method)
            code, resolver_code = hasher.obfuscate_code(code)
            additional_code = resolver_code + "\n" + additional_code
            
            obfuscation_info['apis_hashed'] = len(hasher.hashed_apis)
            obfuscation_info['hash_method'] = hash_method
        
        # Apply control flow flattening
        if flatten_control_flow:
            logger.info("Applying control flow flattening")
            from server.obfuscation import flatten_control_flow as apply_flatten
            
            code = apply_flatten(code)
            obfuscation_info['control_flow_flattened'] = True
        
        # Insert junk code
        if insert_junk_code:
            logger.info(f"Inserting junk code: {junk_density}")
            from server.obfuscation import insert_junk_code as apply_junk
            
            code, num_insertions = apply_junk(code, junk_density)
            obfuscation_info['junk_code_inserted'] = num_insertions
            obfuscation_info['junk_density'] = junk_density
        
        # Apply polymorphic mutations
        if polymorphic:
            logger.info(f"Applying polymorphic mutations: {mutation_level}")
            from server.polymorphic import PolymorphicEngine
            
            poly_engine = PolymorphicEngine()
            code, variant_info = poly_engine.generate_variant(code, mutation_level)
            
            obfuscation_info['polymorphic'] = True
            obfuscation_info['mutation_level'] = mutation_level
            obfuscation_info['variant_uniqueness'] = variant_info['uniqueness_percent']
            obfuscation_info['mutations_applied'] = variant_info['mutations_applied']['mutations']
        
        # Combine
        final_code = additional_code + code if additional_code else code
        
        logger.info(f"Code generation complete")
        
        return jsonify({
            'success': True,
            'code': final_code,
            'header': result.header_code,
            'techniques_used': result.technique_ids,
            'dependencies': result.dependencies,
            'conflicts': result.conflicts,
            'warnings': result.warnings,
            'opsec_notes': result.opsec_notes,
            'mitre_ttps': result.mitre_ttps,
            'obfuscation': obfuscation_info,
            'target_os': target_os,
            'payload_type': payload_type,
            'message': f'Generated code for {len(techniques)} techniques'
        })
        
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Code generation dependency error: {e}")
        return jsonify({
            'success': False,
            'error': f"A required module is missing: {e}. Please check server dependencies."
        }), 500
    except KeyError as e:
        logger.error(f"Missing key in code generation request: {e}")
        return jsonify({'success': False, 'error': f'Missing required parameter: {e}'}), 400
    except Exception as e:
        logger.error(f"Code generation error: {e}")
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/compile', methods=['POST'])
def compile_code():
    """
    Compile C/C++ code into executable
    
    Request body:
      - source_code: C/C++ source code (required)
      - architecture: x86 or x64 (default: x64)
      - optimization: O0, O1, O2, O3 (default: O2)
      - output_name: Name for executable (default: payload)
      - subsystem: Console or Windows (default: Console)
      - auto_fix: Enable automatic error fixing (default: False)
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data provided'
        }), 400
    
    source_code = data.get('source_code')
    if not source_code:
        return jsonify({
            'success': False,
            'error': 'source_code is required'
        }), 400
    
    architecture = data.get('architecture', 'x64')
    optimization = data.get('optimization', 'O2')
    output_name = data.get('output_name', 'payload')
    subsystem = data.get('subsystem', 'Console')
    auto_fix = data.get('auto_fix', False)
    
    # Validate parameters
    if architecture not in ['x86', 'x64']:
        return jsonify({
            'success': False,
            'error': 'architecture must be x86 or x64'
        }), 400
    
    if optimization not in ['O0', 'O1', 'O2', 'O3']:
        return jsonify({
            'success': False,
            'error': 'optimization must be O0, O1, O2, or O3'
        }), 400
    
    try:
        # Import unified compiler (auto-detects Windows/Linux)
        from compilation import get_compiler
        
        # Initialize compiler (Windows: MSBuild, Linux: MinGW)
        compiler = get_compiler(output_dir='compiled')
        
        # Compile code
        logger.info(f"Compiling {output_name} for {architecture} with {optimization}")
        result = compiler.compile(
            source_code=source_code,
            architecture=architecture,
            optimization=optimization,
            output_name=output_name,
            subsystem=subsystem
        )
        
        # If compilation failed and auto_fix enabled, try to fix
        if not result.success and auto_fix:
            logger.info("Compilation failed, attempting auto-fix...")
            from server.autofix_engine import AutoFixEngine
            
            autofix = AutoFixEngine(max_iterations=3)
            
            # Define compile function for iterative fixing
            def compile_func(code):
                comp_result = compiler.compile(
                    source_code=code,
                    architecture=architecture,
                    optimization=optimization,
                    output_name=output_name,
                    subsystem=subsystem
                )
                return comp_result.success, comp_result.output
            
            # Try to fix and recompile
            fix_result = autofix.fix_with_recompile(source_code, compile_func)
            
            if fix_result.success:
                # Recompile with fixed code
                result = compiler.compile(
                    source_code=fix_result.fixed_code,
                    architecture=architecture,
                    optimization=optimization,
                    output_name=output_name,
                    subsystem=subsystem
                )
                
                if result.success:
                    logger.info(f"Auto-fix successful! Compiled: {result.binary_path}")
                    return jsonify({
                        'success': True,
                        'binary_path': result.binary_path,
                        'compilation_time': result.compilation_time,
                        'warnings': result.warnings,
                        'metadata': result.metadata,
                        'auto_fix_applied': True,
                        'auto_fix_details': fix_result.to_dict(),
                        'message': f'Auto-fixed and compiled successfully to {result.binary_path}'
                    })
            
            # Auto-fix failed
            logger.warning("Auto-fix failed to resolve errors")
        
        if result.success:
            logger.info(f"Compilation successful: {result.binary_path}")
            return jsonify({
                'success': True,
                'binary_path': result.binary_path,
                'compilation_time': result.compilation_time,
                'warnings': result.warnings,
                'metadata': result.metadata,
                'message': f'Successfully compiled to {result.binary_path}'
            })
        else:
            logger.error(f"Compilation failed with {len(result.errors)} errors")
            return jsonify({
                'success': False,
                'errors': result.errors,
                'warnings': result.warnings,
                'output': result.output,
                'compilation_time': result.compilation_time,
                'suggestion': 'Try enabling auto_fix=true to automatically fix errors'
            }), 400
            
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Compiler dependency error: {e}")
        return jsonify({
            'success': False,
            'error': f"A required module is missing: {e}. Please check compiler setup."
        }), 500
    except FileNotFoundError as e:
        logger.error(f"Compiler or related file not found: {e}")
        return jsonify({
            'success': False,
            'error': f"Compiler not found. Ensure it is installed and in the system's PATH. Details: {e}"
        }), 500
    except Exception as e:
        logger.error(f"Compilation error: {e}")
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/analyze/opsec', methods=['POST'])
def analyze_opsec():
    """
    Analyze code for OPSEC issues
    
    Request body:
      - code: Source code to analyze (required)
    """
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data provided'
        }), 400
    
    code = data.get('code')
    if not code:
        return jsonify({
            'success': False,
            'error': 'code is required'
        }), 400
    
    try:
        # Import OpsecAnalyzer
        from server.opsec_analyzer import OpsecAnalyzer
        
        # Analyze code
        logger.info("Performing OPSEC analysis")
        analyzer = OpsecAnalyzer()
        report = analyzer.analyze(code)
        
        logger.info(f"OPSEC analysis complete: Score {report.overall_score}/10")
        
        return jsonify({
            'success': True,
            'opsec_report': report.to_dict(),
            'message': f'OPSEC analysis complete - Score: {report.overall_score}/10'
        })
        
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"OPSEC analyzer dependency error: {e}")
        return jsonify({
            'success': False,
            'error': f"A required module is missing: {e}. Please check server dependencies."
        }), 500
    except Exception as e:
        logger.error(f"OPSEC analysis error: {e}")
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


# ============================================================================
# C2 INTEGRATION ENDPOINTS (Phase 4)
# ============================================================================

@app.route('/api/learning/report_detection', methods=['POST'])
def report_detection():
    """Record AV/EDR detection feedback"""
    try:
        from server.learning_engine import LearningEngine, DetectionFeedback
        from datetime import datetime
        
        data = request.get_json()
        
        # Initialize learning engine
        engine = LearningEngine()
        
        # Create feedback object
        feedback = DetectionFeedback(
            timestamp=datetime.now().isoformat(),
            techniques_used=data.get('techniques_used', []),
            av_edr=data.get('av_edr'),
            detected=data.get('detected'),
            detection_type=data.get('detection_type'),
            obfuscation_level=data.get('obfuscation_level'),
            notes=data.get('notes')
        )
        
        # Record feedback
        engine.record_detection(feedback)
        
        # Get updated stats
        stats = {}
        for technique_id in feedback.techniques_used:
            tech_stats = engine.get_technique_stats(technique_id)
            if tech_stats:
                stats[technique_id] = {
                    'total_uses': tech_stats.total_uses,
                    'compilation_success_rate': round(tech_stats.compilation_success_rate, 3),
                    'detection_rate': {
                        av: round(rate, 3)
                        for av, rate in tech_stats.detection_rate.items()
                    }
                }
        
        return jsonify({
            'success': True,
            'message': 'Detection feedback recorded successfully',
            'insights': {
                'av_edr': feedback.av_edr,
                'detected': feedback.detected,
                'techniques_tested': len(feedback.techniques_used)
            },
            'stats': stats
        })
        
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Learning engine dependency error: {e}")
        return jsonify({'success': False, 'error': f"A required module is missing: {e}."}), 500
    except KeyError as e:
        logger.error(f"Missing key in detection report: {e}")
        return jsonify({'success': False, 'error': f'Missing required parameter in detection report: {e}'}), 400
    except Exception as e:
        logger.error(f"Error recording detection feedback: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/learning/recommendations', methods=['GET'])
def get_recommendations():
    """Get technique recommendations based on learned data"""
    try:
        from server.learning_engine import LearningEngine
        
        target_av = request.args.get('target_av')
        category = request.args.get('category')
        min_success_rate = float(request.args.get('min_success_rate', 0.7))
        
        # Initialize learning engine
        engine = LearningEngine()
        
        # Get recommendations
        recommendations = engine.recommend_techniques(
            target_av=target_av,
            category=category,
            min_success_rate=min_success_rate
        )
        
        # Format results
        results = []
        for technique_id, score in recommendations[:10]:  # Top 10
            tech_stats = engine.get_technique_stats(technique_id)
            if tech_stats:
                results.append({
                    'technique_id': technique_id,
                    'name': tech_stats.name,
                    'score': round(score, 3),
                    'total_uses': tech_stats.total_uses,
                    'compilation_success_rate': round(tech_stats.compilation_success_rate, 3),
                    'detection_rates': {
                        av: round(rate, 3)
                        for av, rate in tech_stats.detection_rate.items()
                    }
                })
        
        return jsonify({
            'success': True,
            'recommendations': results,
            'criteria': {
                'target_av': target_av,
                'category': category,
                'min_success_rate': min_success_rate
            }
        })
        
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Learning engine dependency error: {e}")
        return jsonify({'success': False, 'error': f"A required module is missing: {e}."}), 500
    except ValueError as e:
        logger.error(f"Invalid parameter type for recommendations: {e}")
        return jsonify({'success': False, 'error': f"Invalid parameter type provided: {e}"}), 400
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/c2/sliver/generate', methods=['POST'])
def generate_sliver_beacon():
    """
    Generate Sliver C2 beacon with Noctis obfuscation
    
    Requirements:
        - Sliver C2 must be installed and running
        - sliver-client must be in PATH
    
    Request JSON:
    {
        "listener_host": "c2.example.com",
        "listener_port": 443,
        "protocol": "https",  # https, http, dns, tcp, mtls
        "architecture": "x64",  # x64, x86
        "techniques": ["NOCTIS-T124", "NOCTIS-T118"],  # Optional
        "obfuscate": true,
        "beacon_name": "custom_name"  # Optional
    }
    
    Returns:
        JSON with generation results
    """
    try:
        data = request.get_json()
        
        # Required parameters
        listener_host = data.get('listener_host')
        listener_port = data.get('listener_port')
        
        if not listener_host or not listener_port:
            return jsonify({
                'success': False,
                'error': 'listener_host and listener_port are required'
            }), 400
        
        # Optional parameters
        protocol = data.get('protocol', 'https')
        architecture = data.get('architecture', 'x64')
        techniques = data.get('techniques', [])
        obfuscate = data.get('obfuscate', True)
        beacon_name = data.get('beacon_name')
        
        # Import Sliver adapter
        from c2_adapters.sliver_adapter import generate_sliver_beacon
        
        # Generate beacon
        logger.info(f"Generating Sliver beacon: {protocol}://{listener_host}:{listener_port}")
        
        result = generate_sliver_beacon(
            listener_host=listener_host,
            listener_port=listener_port,
            protocol=protocol,
            architecture=architecture,
            techniques=techniques,
            obfuscate=obfuscate,
            verbose=True
        )
        
        # Return result
        if result.success:
            logger.info(f"Sliver beacon generated successfully")
            return jsonify({
                'success': True,
                'beacon_path': result.beacon_path,
                'shellcode_path': result.shellcode_path,
                'beacon_size': result.beacon_size,
                'techniques_applied': result.techniques_applied,
                'obfuscation_summary': result.obfuscation_summary,
                'opsec_score': result.opsec_score,
                'compilation_time': result.compilation_time,
                'metadata': result.metadata,
                'timestamp': result.timestamp.isoformat()
            })
        else:
            logger.error(f"Sliver beacon generation failed: {result.error_message}")
            return jsonify({
                'success': False,
                'error': result.error_message
            }), 500
            
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Sliver adapter dependency error: {e}")
        return jsonify({'success': False, 'error': f"A required module is missing: {e}. Please check C2 adapter setup."}), 500
    except KeyError as e:
        logger.error(f"Missing key in Sliver beacon request: {e}")
        return jsonify({'success': False, 'error': f'Missing required parameter: {e}'}), 400
    except Exception as e:
        logger.error(f"Error generating Sliver beacon: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/c2/mythic/generate', methods=['POST'])
def generate_mythic_agent_endpoint():
    """
    Generate Mythic C2 agent with Noctis obfuscation
    
    Requirements:
        - Mythic C2 must be installed and running
        - API token must be provided
    
    Request JSON:
    {
        "listener_host": "c2.example.com",
        "listener_port": 80,
        "agent_type": "apollo",  # apollo, apfell, poseidon, merlin, atlas
        "c2_profile": "http",  # http, https, dns, smb, websocket
        "architecture": "x64",  # x64, x86, arm64
        "api_token": "your_mythic_api_token",
        "techniques": ["NOCTIS-T124"],  # Optional
        "obfuscate": true
    }
    
    Returns:
        JSON with generation results
    """
    try:
        data = request.get_json()
        
        # Required parameters
        listener_host = data.get('listener_host')
        listener_port = data.get('listener_port')
        api_token = data.get('api_token')
        
        if not listener_host or not listener_port:
            return jsonify({
                'success': False,
                'error': 'listener_host and listener_port are required'
            }), 400
        
        if not api_token:
            return jsonify({
                'success': False,
                'error': 'api_token is required for Mythic integration'
            }), 400
        
        # Optional parameters
        agent_type = data.get('agent_type', 'apollo')
        c2_profile = data.get('c2_profile', 'http')
        architecture = data.get('architecture', 'x64')
        techniques = data.get('techniques', [])
        obfuscate = data.get('obfuscate', True)
        
        # Import Mythic adapter
        from c2_adapters.mythic_adapter import generate_mythic_agent
        
        # Generate agent
        logger.info(f"Generating Mythic agent: {agent_type} with {c2_profile}")
        
        result = generate_mythic_agent(
            listener_host=listener_host,
            listener_port=listener_port,
            agent_type=agent_type,
            c2_profile=c2_profile,
            architecture=architecture,
            api_token=api_token,
            techniques=techniques,
            obfuscate=obfuscate
        )
        
        # Return result
        if result.success:
            logger.info(f"Mythic agent generated successfully")
            return jsonify({
                'success': True,
                'beacon_path': result.beacon_path,
                'shellcode_path': result.shellcode_path,
                'beacon_size': result.beacon_size,
                'techniques_applied': result.techniques_applied,
                'obfuscation_summary': result.obfuscation_summary,
                'opsec_score': result.opsec_score,
                'compilation_time': result.compilation_time,
                'metadata': result.metadata,
                'timestamp': result.timestamp.isoformat()
            })
        else:
            logger.error(f"Mythic agent generation failed: {result.error_message}")
            return jsonify({
                'success': False,
                'error': result.error_message
            }), 500
            
    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Mythic adapter dependency error: {e}")
        return jsonify({'success': False, 'error': f"A required module is missing: {e}. Please check C2 adapter setup."}), 500
    except KeyError as e:
        logger.error(f"Missing key in Mythic agent request: {e}")
        return jsonify({'success': False, 'error': f'Missing required parameter: {e}'}), 400
    except Exception as e:
        logger.error(f"Error generating Mythic agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/c2/frameworks', methods=['GET'])
def get_c2_frameworks():
    """
    Get list of supported C2 frameworks
    
    Returns:
        JSON with supported frameworks and their capabilities
    """
    return jsonify({
        'success': True,
        'frameworks': [
            {
                'name': 'Sliver',
                'status': 'implemented',
                'protocols': ['https', 'http', 'dns', 'tcp', 'mtls'],
                'architectures': ['x64', 'x86'],
                'formats': ['shellcode', 'exe', 'dll'],
                'features': [
                    'Multiple C2 protocols',
                    'Beacon/Session modes',
                    'Advanced evasion',
                    'Noctis obfuscation integration'
                ]
            },
            {
                'name': 'Havoc',
                'status': 'manual_only',
                'protocols': ['http', 'https', 'smb'],
                'architectures': ['x64', 'x86'],
                'formats': ['shellcode', 'exe', 'dll'],
                'features': [
                    'Sleep obfuscation (Ekko, Foliage)',
                    'Indirect syscalls',
                    'Stack duplication',
                    'Manual demon generation via GUI'
                ],
                'api_status': 'Coming Soon',
                'api_docs': 'https://havocframework.com/docs/service_api',
                'notes': 'Service API not yet available. Use Havoc GUI client to generate demons manually, then apply Noctis obfuscation.'
            },
            {
                'name': 'Mythic',
                'status': 'implemented',
                'protocols': ['http', 'https', 'websocket', 'dns', 'smb'],
                'architectures': ['x64', 'x86', 'arm64'],
                'formats': ['exe', 'dll', 'shellcode', 'service_exe'],
                'features': [
                    'Multiple agent types (Apollo, Poseidon, Merlin)',
                    'Modular C2 profiles',
                    'REST API integration',
                    'Noctis obfuscation integration'
                ]
            }
        ]
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics about the technique database"""
    techniques = technique_manager.get_all()
    
    # Count by category
    by_category = {}
    for t in techniques:
        cat = t.get('category', 'other')
        by_category[cat] = by_category.get(cat, 0) + 1
    
    # Count by author
    by_author = {}
    for t in techniques:
        author = t.get('author', 'Unknown')
        by_author[author] = by_author.get(author, 0) + 1
    
    # Count MITRE coverage
    mitre_ids = set()
    for t in techniques:
        mitre_ids.update(t.get('mitre_attack', []))
    
    return jsonify({
        'success': True,
        'statistics': {
            'total_techniques': len(techniques),
            'categories': by_category,
            'authors': by_author,
            'mitre_coverage': {
                'total_ttps': len(mitre_ids),
                'ttps': sorted(list(mitre_ids))
            }
        }
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


# ============================================================================
# MAIN
# ============================================================================

def print_banner():
    """Print server startup banner"""
    banner = """
====================================================================
                   NOCTIS-MCP SERVER                            
     AI-Driven Malware Development Platform v2.0          
                                                                   
  [*] Dynamic AI Partnership for Red Team Operations                
  [*] Open Source Community Project                                
====================================================================
"""
    print(banner)


def main():
    """Main entry point for the server"""
    global config, technique_manager, logger, agent_registry
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Noctis-MCP Server')
    parser.add_argument('--host', default=None, help='Host to bind to')
    parser.add_argument('--port', type=int, default=None, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()
    
    # Load configuration
    config = Config(config_file=args.config)
    
    # Setup logging
    log_level = "DEBUG" if args.debug else config.get('logging.level', 'INFO')
    log_file = config.get('logging.file', 'logs/noctis.log')
    logger = setup_logging(log_level, log_file)
    
    # Print banner
    print_banner()
    
    # Initialize technique manager
    metadata_path = config.get('paths.techniques', 'techniques') + '/metadata'
    technique_manager = TechniqueManager(metadata_path)

    # Initialize agent registry
    logger.info("Initializing agent registry...")
    from server.agents import AgentRegistry
    agent_config = {
        'db_path': config.get('paths.database', 'data/knowledge_base.db'),
        'metadata_path': metadata_path,
        'output_dir': config.get('paths.output', 'output'),
        'rag_db_path': config.get('paths.rag_db', 'data/rag_db')
    }
    agent_registry = AgentRegistry

    # Initialize RAG engine for agentic intelligence
    logger.info("Initializing RAG engine...")
    try:
        from server.rag import RAGEngine
        rag_engine = RAGEngine(persist_dir=agent_config['rag_db_path'])
        logger.info(f"RAG engine initialized: {rag_engine.get_stats()}")

        # Auto-index knowledge base on startup if empty
        stats = rag_engine.get_stats()
        if stats.get('knowledge_base', 0) == 0:
            logger.info("RAG database empty - indexing knowledge base...")
            indexed = rag_engine.index_knowledge_base('techniques/knowledge')
            logger.info(f"Indexed {indexed} knowledge chunks")

    except Exception as e:
        logger.warning(f"RAG engine initialization failed: {e}")
        logger.warning("Agentic features will be disabled")
        rag_engine = None

    # Initialize code assembler with RAG
    from server.code_assembler import CodeAssembler
    code_assembler = CodeAssembler(rag_engine=rag_engine)
    logger.info("Code assembler initialized with RAG support")

    # Initialize agent registry first (without learning engine to break circular dependency)
    agent_config['learning_engine'] = None
    AgentRegistry.initialize(agent_config)
    logger.info("Agent registry initialized")

    # Initialize learning engine after registry
    from server.learning_engine import AgenticLearningEngine
    learning_engine = AgenticLearningEngine(
        db_path=agent_config['db_path'],
        agent_registry=AgentRegistry
    )
    logger.info("Learning engine initialized")

    # Inject learning engine back into registry
    AgentRegistry.set_learning_engine(learning_engine)
    logger.info("Learning engine injected into agent registry")

    # Register agentic API endpoints
    if rag_engine and rag_engine.enabled:
        logger.info("Registering agentic API endpoints...")
        from server.agentic_api import init_agentic_api
        init_agentic_api(app, rag_engine, technique_manager, code_assembler, learning_engine)
        logger.info("Agentic API endpoints registered")
    else:
        logger.warning("Agentic API endpoints NOT registered (RAG disabled)")

    # Register education API endpoints
    logger.info("Registering education API endpoints...")
    from server.education_api import education_bp, init_education_api
    education_config = {
        'lessons_path': config.get('paths.lessons', 'data/lessons.json'),
        'quizzes_path': config.get('paths.quizzes', 'data/quizzes.json'),
        'education_db': config.get('paths.education_db', 'data/education_progress.db')
    }
    init_education_api(education_config)
    app.register_blueprint(education_bp)
    logger.info("Education API endpoints registered")

    # Determine host and port with proper type handling
    host = args.host if args.host is not None else config.get('server.host', '127.0.0.1')
    port = args.port if args.port is not None else config.get('server.port', 8888)
    debug = args.debug if args.debug else config.get('server.debug', False)
    
    # Log startup info
    logger.info(f"Starting Noctis-MCP Server")
    logger.info(f"Host: {host}")
    logger.info(f"Port: {port}")
    logger.info(f"Debug: {debug}")
    logger.info(f"Techniques loaded: {len(technique_manager.techniques)}")
    
    # Print access URL
    print(f"\n[*] Server starting on http://{host}:{port}")
    print(f"[*] Techniques loaded: {len(technique_manager.techniques)}")
    print(f"\n[*] API Endpoints:")
    print(f"   - GET  /health                      - Health check")
    print(f"   - GET  /api/techniques              - List all techniques")
    print(f"   - GET  /api/techniques/<id>         - Get technique by ID")
    print(f"   - GET  /api/categories              - List categories")
    print(f"   - GET  /api/stats                   - Database statistics")
    print(f"   - POST /api/generate                - Generate code")
    print(f"   - POST /api/compile                 - Compile code")
    print(f"   - POST /api/analyze/opsec           - OPSEC analysis")
    print(f"   - GET  /api/c2/frameworks           - List C2 frameworks")
    print(f"   - POST /api/c2/sliver/generate      - Generate Sliver beacon")
    print(f"\n[*] Agent API Endpoints (V2):")
    print(f"   - POST /api/v2/agents/technique-selection   - AI technique selection")
    print(f"   - POST /api/v2/agents/malware-development   - Autonomous malware dev")
    print(f"   - POST /api/v2/agents/opsec-optimization    - OPSEC optimization")
    print(f"   - POST /api/v2/agents/learning              - Learning feedback")
    print(f"   - GET  /api/v2/agents/status                - Agent status")

    if rag_engine and rag_engine.enabled:
        print(f"\n[*] Agentic Intelligence API (RAG-Powered):")
        print(f"   - POST /api/v2/intelligence/search          - Search RAG for intelligence")
        print(f"   - POST /api/v2/intelligence/analyze         - Deep technique analysis")
        print(f"   - POST /api/v2/intelligence/fetch-latest    - Fetch live intelligence")
        print(f"   - POST /api/v2/code/generate                - RAG-informed code generation")
        print(f"   - POST /api/v2/code/validate                - Validate code quality")
        print(f"   - POST /api/v2/techniques/select            - Intelligent technique selection")
        print(f"   - GET  /api/v2/rag/stats                    - RAG system statistics")
        print(f"\n[+] RAG System: ENABLED ({rag_engine.get_stats().get('knowledge_base', 0)} knowledge chunks indexed)")
    else:
        print(f"\n[!] RAG System: DISABLED (install dependencies: pip install chromadb sentence-transformers)")

    # Security warning for debug mode
    if debug:
        print(f"\n" + "="*70)
        print(f"⚠️  WARNING: Flask debug mode is ENABLED")
        print(f"="*70)
        print(f"  This is a LOCAL DEVELOPMENT TOOL - debug mode is acceptable.")
        print(f"  However, if exposing to network:")
        print(f"    - Do NOT bind to 0.0.0.0 or public IP")
        print(f"    - Debug mode exposes code and enables remote debugger")
        print(f"    - Use production WSGI server (gunicorn) for networked deployment")
        print(f"="*70 + "\n")

    print(f"\n[!] Press Ctrl+C to stop the server\n")

    # Run server
    try:
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down Noctis-MCP Server...")
        logger.info("Server shutdown by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


# ============================================================================
# AGENT-BASED API ENDPOINTS (V2)
# ============================================================================

@app.route('/api/v2/agents/technique-selection', methods=['POST'])
def api_v2_technique_selection():
    """
    AI-powered technique selection using TechniqueSelectionAgent

    Request body:
        {
            "target_av": "Windows Defender",
            "objective": "evasion",
            "complexity": "medium",
            "constraints": {
                "max_techniques": 5,
                "min_effectiveness_score": 0.8
            }
        }
    """
    try:
        if not agent_registry:
            return jsonify({'success': False, 'error': 'Agent registry not initialized'}), 500

        params = request.json or {}

        # Get agent and run
        agent = agent_registry.get_agent('technique_selection')
        result = agent.run(**params)

        # Return result
        return jsonify(result.to_dict())

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Agent dependency error: {e}")
        return jsonify({'success': False, 'error': f"An agent-related module is missing: {e}."}), 500
    except KeyError as e:
        logger.error(f"Agent not found or misconfigured: {e}")
        return jsonify({'success': False, 'error': f"Agent access error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error in technique selection agent: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v2/agents/malware-development', methods=['POST'])
def api_v2_malware_development():
    """
    Autonomous malware development using MalwareDevelopmentAgent

    Request body:
        {
            "goal": "Create stealthy loader",
            "target_av": "Windows Defender",
            "target_os": "Windows",
            "architecture": "x64",
            "auto_compile": true,
            "target_opsec_score": 8.0,
            "max_techniques": 5
        }
    """
    try:
        if not agent_registry:
            return jsonify({'success': False, 'error': 'Agent registry not initialized'}), 500

        params = request.json or {}

        # Get agent and run
        agent = agent_registry.get_agent('malware_development')
        result = agent.run(**params)

        # Return result
        return jsonify(result.to_dict())

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Agent dependency error: {e}")
        return jsonify({'success': False, 'error': f"An agent-related module is missing: {e}."}), 500
    except KeyError as e:
        logger.error(f"Agent not found or misconfigured: {e}")
        return jsonify({'success': False, 'error': f"Agent access error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error in malware development agent: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v2/agents/opsec-optimization', methods=['POST'])
def api_v2_opsec_optimization():
    """
    OPSEC optimization using OpsecOptimizationAgent

    Request body:
        {
            "code": "source code here",
            "target_score": 8.0,
            "max_iterations": 3
        }
    """
    try:
        if not agent_registry:
            return jsonify({'success': False, 'error': 'Agent registry not initialized'}), 500

        params = request.json or {}

        # Get agent and run
        agent = agent_registry.get_agent('opsec_optimization')
        result = agent.run(**params)

        # Return result
        return jsonify(result.to_dict())

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Agent dependency error: {e}")
        return jsonify({'success': False, 'error': f"An agent-related module is missing: {e}."}), 500
    except KeyError as e:
        logger.error(f"Agent not found or misconfigured: {e}")
        return jsonify({'success': False, 'error': f"Agent access error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error in OPSEC optimization agent: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v2/agents/learning', methods=['POST'])
def api_v2_learning():
    """
    Learning agent for feedback collection

    Request body:
        {
            "action": "record_detection",
            "techniques": ["NOCTIS-T001"],
            "av_edr": "Windows Defender",
            "detected": false,
            ...
        }
    """
    try:
        if not agent_registry:
            return jsonify({'success': False, 'error': 'Agent registry not initialized'}), 500

        params = request.json or {}

        # Get agent and run
        agent = agent_registry.get_agent('learning')
        result = agent.run(**params)

        # Return result
        return jsonify(result.to_dict())

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Agent dependency error: {e}")
        return jsonify({'success': False, 'error': f"An agent-related module is missing: {e}."}), 500
    except KeyError as e:
        logger.error(f"Agent not found or misconfigured: {e}")
        return jsonify({'success': False, 'error': f"Agent access error: {e}"}), 500
    except Exception as e:
        logger.error(f"Error in learning agent: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/v2/agents/status', methods=['GET'])
def api_v2_agents_status():
    """Get status of all registered agents"""
    try:
        if not agent_registry:
            return jsonify({'success': False, 'error': 'Agent registry not initialized'}), 500

        status = agent_registry.list_agents()

        return jsonify({
            'success': True,
            'agents': status,
            'total_agents': len(status)
        })

    except (ImportError, ModuleNotFoundError) as e:
        logger.error(f"Agent dependency error: {e}")
        return jsonify({'success': False, 'error': f"An agent-related module is missing: {e}."}), 500
    except Exception as e:
        logger.error(f"Error getting agent status: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    main()

