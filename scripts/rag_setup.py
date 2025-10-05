#!/usr/bin/env python3
"""
RAG System Setup Script
========================

One-command initialization of the RAG (Retrieval Augmented Generation) system.

This script:
1. Installs required dependencies
2. Initializes ChromaDB vector database
3. Downloads and indexes embedding model
4. Indexes knowledge base markdown files
5. Performs initial intelligence gathering from GitHub/arXiv/blogs

Usage:
    python scripts/rag_setup.py

Options:
    --skip-intelligence: Skip initial intelligence gathering (faster setup)
    --knowledge-only: Only index knowledge base, skip intelligence gathering
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
from typing import Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def check_dependencies() -> bool:
    """Check if required dependencies are installed"""
    logger.info("Checking dependencies...")

    # Map package names to import names
    required_packages = {
        'chromadb': 'chromadb',
        'sentence_transformers': 'sentence_transformers',
        'feedparser': 'feedparser',
        'arxiv': 'arxiv',
        'beautifulsoup4': 'bs4',
        'lxml': 'lxml'
    }

    missing = []
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            logger.info(f"  ✓ {package_name}")
        except ImportError:
            logger.error(f"  ✗ {package_name}")
            missing.append(package_name)

    if missing:
        logger.error(f"\nMissing packages: {', '.join(missing)}")
        logger.error("Install with: pip install -r requirements.txt")
        return False

    logger.info("All dependencies installed ✓\n")
    return True


def download_embedding_model():
    """Download sentence-transformers embedding model"""
    logger.info("Downloading embedding model (all-MiniLM-L6-v2)...")
    logger.info("This may take a few minutes on first run...")

    try:
        from sentence_transformers import SentenceTransformer

        # This will download the model if not already cached
        model = SentenceTransformer('all-MiniLM-L6-v2')
        logger.info("Embedding model ready ✓\n")
        return True

    except Exception as e:
        logger.error(f"Failed to download embedding model: {e}")
        return False


def initialize_rag_database() -> Optional[object]:
    """Initialize ChromaDB and RAG engine"""
    logger.info("Initializing RAG database...")

    try:
        from server.rag import RAGEngine

        # Create data directory if needed
        data_dir = Path("data/rag_db")
        data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize RAG engine
        rag = RAGEngine(persist_dir=str(data_dir))

        logger.info(f"RAG database initialized at: {data_dir}")
        logger.info(f"Collections created: {len(rag.client.list_collections())}")
        logger.info("  - malware_knowledge (conceptual understanding)")
        logger.info("  - github_techniques (real-world implementations)")
        logger.info("  - research_papers (academic research)")
        logger.info("  - security_blogs (industry intelligence)")
        logger.info("  - av_detections (detection feedback)\n")

        return rag

    except Exception as e:
        logger.error(f"Failed to initialize RAG database: {e}")
        import traceback
        traceback.print_exc()
        return None


def index_knowledge_base(rag_engine) -> int:
    """Index knowledge base markdown files"""
    logger.info("Indexing knowledge base...")

    knowledge_path = Path("techniques/knowledge")
    if not knowledge_path.exists():
        logger.warning(f"Knowledge base path not found: {knowledge_path}")
        return 0

    indexed = 0
    for md_file in knowledge_path.glob("*.md"):
        try:
            logger.info(f"  Indexing: {md_file.name}")

            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract technique ID from filename
            tech_id = md_file.stem

            # Add to RAG
            rag_engine.add_markdown_knowledge(
                title=f"Knowledge: {tech_id.title()}",
                content=content,
                technique_id=f"NOCTIS-{tech_id.upper()}",
                metadata={
                    'source': 'knowledge_base',
                    'file': str(md_file)
                }
            )

            indexed += 1

        except Exception as e:
            logger.error(f"  Failed to index {md_file.name}: {e}")

    logger.info(f"Knowledge base indexed: {indexed} files ✓\n")
    return indexed


def gather_intelligence(rag_engine) -> dict:
    """Perform initial intelligence gathering"""
    logger.info("Gathering live intelligence from GitHub, arXiv, and security blogs...")
    logger.info("This may take 5-10 minutes...")

    try:
        from server.intelligence import LiveIntelligence

        intel = LiveIntelligence(rag_engine=rag_engine)

        # Run full intelligence refresh
        stats = intel.full_intelligence_refresh()

        logger.info("\n=== Intelligence Gathering Complete ===")
        logger.info(f"  GitHub Repos: {stats['github_repos']}")
        logger.info(f"  arXiv Papers: {stats['arxiv_papers']}")
        logger.info(f"  Blog Posts: {stats['blog_posts']}")
        logger.info(f"  Total Indexed: {stats['indexed']}")
        logger.info(f"  Errors: {stats['errors']}")
        logger.info("✓\n")

        return stats

    except Exception as e:
        logger.error(f"Intelligence gathering failed: {e}")
        import traceback
        traceback.print_exc()
        return {}


def verify_setup(rag_engine) -> bool:
    """Verify RAG system is working correctly"""
    logger.info("Verifying RAG setup...")

    try:
        # Test query
        query = "process injection evasion techniques"
        results = rag_engine.search_knowledge(query, n_results=3)

        if results:
            logger.info(f"Test query successful: found {len(results)} results")
            logger.info("  Sample result:")
            logger.info(f"    Source: {results[0].get('source', 'unknown')}")
            logger.info(f"    Content preview: {results[0].get('content', '')[:100]}...")
            logger.info("RAG system verified ✓\n")
            return True
        else:
            logger.warning("Test query returned no results")
            logger.warning("This may indicate indexing issues\n")
            return False

    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False


def main():
    """Main setup workflow"""
    parser = argparse.ArgumentParser(description="Setup RAG system for Noctis-MCP")
    parser.add_argument('--skip-intelligence', action='store_true',
                        help='Skip initial intelligence gathering (faster)')
    parser.add_argument('--knowledge-only', action='store_true',
                        help='Only index knowledge base')
    args = parser.parse_args()

    print("="*70)
    print("  Noctis-MCP RAG System Setup")
    print("="*70 + "\n")

    # Step 1: Check dependencies
    if not check_dependencies():
        logger.error("Setup failed: missing dependencies")
        return 1

    # Step 2: Download embedding model
    if not download_embedding_model():
        logger.error("Setup failed: could not download embedding model")
        return 1

    # Step 3: Initialize RAG database
    rag_engine = initialize_rag_database()
    if not rag_engine:
        logger.error("Setup failed: could not initialize RAG database")
        return 1

    # Step 4: Index knowledge base
    indexed = index_knowledge_base(rag_engine)
    if indexed == 0:
        logger.warning("No knowledge base files indexed")

    # Step 5: Gather intelligence (optional)
    if not args.knowledge_only and not args.skip_intelligence:
        stats = gather_intelligence(rag_engine)
        if stats.get('indexed', 0) == 0:
            logger.warning("No intelligence data indexed")
    elif args.skip_intelligence:
        logger.info("Skipping intelligence gathering (--skip-intelligence)\n")
    elif args.knowledge_only:
        logger.info("Skipping intelligence gathering (--knowledge-only)\n")

    # Step 6: Verify setup
    if verify_setup(rag_engine):
        print("="*70)
        print("  ✓ RAG System Setup Complete!")
        print("="*70)
        print("\nNext steps:")
        print("  1. Start the server: python server/noctis_server.py --port 8888")
        print("  2. Use MCP tools in Cursor/VSCode to interact with Noctis")
        print("  3. Run weekly intelligence updates: python scripts/update_intelligence.py")
        print()
        return 0
    else:
        logger.error("Setup completed with warnings - verification failed")
        return 1


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.warning("\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\nSetup failed with unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
