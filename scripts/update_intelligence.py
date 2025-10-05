#!/usr/bin/env python3
"""
Intelligence Update Script
==========================

Refreshes live intelligence from GitHub, arXiv, and security blogs.

This script should be run weekly (or on-demand) to keep the RAG system
updated with the latest evasion techniques, research, and threat intelligence.

Usage:
    python scripts/update_intelligence.py

Options:
    --github-only: Only update GitHub repositories
    --arxiv-only: Only update arXiv research papers
    --blogs-only: Only update security blog posts
    --full: Full refresh (same as no options)
    --custom-queries: Use custom search queries from JSON file
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse
import logging
import json
from datetime import datetime
from typing import List, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def load_custom_queries(query_file: str) -> dict:
    """Load custom search queries from JSON file"""
    try:
        with open(query_file, 'r') as f:
            queries = json.load(f)
        logger.info(f"Loaded custom queries from {query_file}")
        return queries
    except Exception as e:
        logger.error(f"Failed to load custom queries: {e}")
        return {}


def update_github_intelligence(intel_engine, custom_queries: Optional[List[str]] = None) -> dict:
    """Update GitHub intelligence"""
    logger.info("="*70)
    logger.info("Updating GitHub Intelligence")
    logger.info("="*70)

    # Default queries optimized for malware development techniques
    default_queries = [
        "process injection EDR evasion",
        "syscalls direct NTDLL unhooking",
        "API hashing malware obfuscation",
        "AMSI bypass powershell",
        "ETW patching kernel callbacks",
        "shellcode encryption AES",
        "memory evasion sleep obfuscation",
        "ppid spoofing parent process",
        "reflective DLL injection",
        "indirect syscalls hell's gate"
    ]

    queries = custom_queries or default_queries
    total_repos = 0
    indexed = 0

    for query in queries:
        logger.info(f"\nSearching GitHub: {query}")
        repos = intel_engine.search_github_repos(query, max_results=5, min_stars=10)
        total_repos += len(repos)

        for repo in repos:
            readme = intel_engine.fetch_github_readme(repo["name"])
            if readme and intel_engine.index_github_repo(repo, readme):
                indexed += 1

    logger.info(f"\nGitHub Update Complete:")
    logger.info(f"  Repos found: {total_repos}")
    logger.info(f"  Repos indexed: {indexed}")

    return {"repos_found": total_repos, "repos_indexed": indexed}


def update_arxiv_intelligence(intel_engine, custom_queries: Optional[List[str]] = None) -> dict:
    """Update arXiv research intelligence"""
    logger.info("\n" + "="*70)
    logger.info("Updating arXiv Research Intelligence")
    logger.info("="*70)

    # Default queries for relevant research
    default_queries = [
        "malware detection evasion",
        "adversarial machine learning security",
        "EDR bypass techniques",
        "endpoint security evasion",
        "behavioral analysis evasion",
        "code obfuscation polymorphism"
    ]

    queries = custom_queries or default_queries
    total_papers = 0
    indexed = 0

    for query in queries:
        logger.info(f"\nSearching arXiv: {query}")
        papers = intel_engine.search_arxiv_papers(query, max_results=10, days_back=180)
        total_papers += len(papers)

        for paper in papers:
            if intel_engine.index_research_paper(paper):
                indexed += 1

    logger.info(f"\narXiv Update Complete:")
    logger.info(f"  Papers found: {total_papers}")
    logger.info(f"  Papers indexed: {indexed}")

    return {"papers_found": total_papers, "papers_indexed": indexed}


def update_blog_intelligence(intel_engine) -> dict:
    """Update security blog intelligence"""
    logger.info("\n" + "="*70)
    logger.info("Updating Security Blog Intelligence")
    logger.info("="*70)

    logger.info("\nFetching from security blogs:")
    logger.info("  - MDSec")
    logger.info("  - Outflank")
    logger.info("  - XPN InfoSec")
    logger.info("  - TrustedSec")
    logger.info("  - SpecterOps")

    posts = intel_engine.fetch_security_blogs(max_posts_per_blog=5, days_back=30)
    indexed = 0

    for post in posts:
        if intel_engine.index_blog_post(post):
            indexed += 1

    logger.info(f"\nBlog Update Complete:")
    logger.info(f"  Posts found: {len(posts)}")
    logger.info(f"  Posts indexed: {indexed}")

    return {"posts_found": len(posts), "posts_indexed": indexed}


def generate_report(stats: dict, output_file: Optional[str] = None):
    """Generate intelligence update report"""
    report_lines = []

    report_lines.append("="*70)
    report_lines.append("  Noctis-MCP Intelligence Update Report")
    report_lines.append("="*70)
    report_lines.append(f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("\n--- GitHub Intelligence ---")
    report_lines.append(f"  Repositories Found: {stats['github']['repos_found']}")
    report_lines.append(f"  Repositories Indexed: {stats['github']['repos_indexed']}")

    report_lines.append("\n--- arXiv Research ---")
    report_lines.append(f"  Papers Found: {stats['arxiv']['papers_found']}")
    report_lines.append(f"  Papers Indexed: {stats['arxiv']['papers_indexed']}")

    report_lines.append("\n--- Security Blogs ---")
    report_lines.append(f"  Posts Found: {stats['blogs']['posts_found']}")
    report_lines.append(f"  Posts Indexed: {stats['blogs']['posts_indexed']}")

    total_indexed = (
        stats['github']['repos_indexed'] +
        stats['arxiv']['papers_indexed'] +
        stats['blogs']['posts_indexed']
    )

    report_lines.append("\n--- Summary ---")
    report_lines.append(f"  Total Intelligence Sources Indexed: {total_indexed}")
    report_lines.append("="*70)

    report = "\n".join(report_lines)

    # Print to console
    print("\n" + report)

    # Save to file if specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"\nReport saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


def main():
    """Main update workflow"""
    parser = argparse.ArgumentParser(description="Update Noctis-MCP intelligence")
    parser.add_argument('--github-only', action='store_true',
                        help='Only update GitHub repositories')
    parser.add_argument('--arxiv-only', action='store_true',
                        help='Only update arXiv research papers')
    parser.add_argument('--blogs-only', action='store_true',
                        help='Only update security blogs')
    parser.add_argument('--full', action='store_true',
                        help='Full refresh (default behavior)')
    parser.add_argument('--custom-queries', type=str,
                        help='Path to JSON file with custom search queries')
    parser.add_argument('--report', type=str,
                        help='Save report to file')
    args = parser.parse_args()

    print("="*70)
    print("  Noctis-MCP Intelligence Update")
    print("="*70 + "\n")

    # Initialize RAG engine
    try:
        from server.rag import RAGEngine
        from server.intelligence import LiveIntelligence

        logger.info("Initializing RAG engine...")
        rag_engine = RAGEngine(persist_dir="data/rag_db")

        logger.info("Initializing intelligence engine...")
        intel_engine = LiveIntelligence(rag_engine=rag_engine)

    except Exception as e:
        logger.error(f"Failed to initialize engines: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Load custom queries if specified
    custom_queries_data = {}
    if args.custom_queries:
        custom_queries_data = load_custom_queries(args.custom_queries)

    # Determine what to update
    update_all = args.full or not (args.github_only or args.arxiv_only or args.blogs_only)

    stats = {
        'github': {'repos_found': 0, 'repos_indexed': 0},
        'arxiv': {'papers_found': 0, 'papers_indexed': 0},
        'blogs': {'posts_found': 0, 'posts_indexed': 0}
    }

    try:
        # Update GitHub
        if update_all or args.github_only:
            github_queries = custom_queries_data.get('github')
            stats['github'] = update_github_intelligence(intel_engine, github_queries)

        # Update arXiv
        if update_all or args.arxiv_only:
            arxiv_queries = custom_queries_data.get('arxiv')
            stats['arxiv'] = update_arxiv_intelligence(intel_engine, arxiv_queries)

        # Update Blogs
        if update_all or args.blogs_only:
            stats['blogs'] = update_blog_intelligence(intel_engine)

        # Generate report
        generate_report(stats, output_file=args.report)

        logger.info("\n✓ Intelligence update complete!")
        return 0

    except KeyboardInterrupt:
        logger.warning("\nUpdate interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"\nUpdate failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
