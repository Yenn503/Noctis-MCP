#!/usr/bin/env python3
"""
Noctis-MCP Intelligence Auto-Updater
=====================================

Automated intelligence gathering from multiple sources.
Runs on schedule to keep RAG database fresh with latest techniques.

Features:
- GitHub trending malware repos
- Security blog RSS feeds (25+ sources)
- arXiv research papers
- Malware analysis feeds
- Smart deduplication
- Comprehensive logging

Usage:
    python scripts/intelligence_updater.py --mode [daily|weekly|manual]

Cron Examples:
    # Daily update (light): GitHub trending + blogs
    0 2 * * * /path/to/venv/bin/python /path/to/scripts/intelligence_updater.py --mode daily

    # Weekly update (heavy): Full refresh including arXiv
    0 3 * * 0 /path/to/venv/bin/python /path/to/scripts/intelligence_updater.py --mode weekly
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from server.rag import RAGEngine
from server.intelligence import LiveIntelligence

# Setup logging
LOG_DIR = Path("logs/intelligence")
LOG_DIR.mkdir(parents=True, exist_ok=True)

log_file = LOG_DIR / f"update_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
)
logger = logging.getLogger(__name__)


class IntelligenceUpdater:
    """Manages automated intelligence updates"""

    def __init__(self, rag_engine: RAGEngine):
        self.rag = rag_engine
        self.intel = LiveIntelligence(rag_engine=rag_engine)
        self.stats_file = Path("data/intelligence_stats.json")

    def load_stats(self) -> Dict:
        """Load historical stats"""
        if self.stats_file.exists():
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        return {"total_runs": 0, "total_indexed": 0, "last_run": None, "runs": []}

    def save_stats(self, stats: Dict):
        """Save stats to disk"""
        with open(self.stats_file, 'w') as f:
            json.dump(stats, f, indent=2)

    def daily_update(self) -> Dict:
        """
        Daily light update - trending repos + recent blogs
        Fast, low resource usage
        """
        logger.info("🔄 Starting DAILY intelligence update...")

        github_queries = [
            # Focus on trending/recent techniques
            "EDR bypass 2025",
            "syscalls evasion",
            "AMSI bypass",
            "process injection",
            "Cobalt Strike"
        ]

        stats = {
            "mode": "daily",
            "timestamp": datetime.now().isoformat(),
            "github_repos": 0,
            "blog_posts": 0,
            "arxiv_papers": 0,
            "indexed": 0,
            "errors": 0
        }

        # GitHub trending (smaller set)
        for query in github_queries:
            logger.info(f"📂 GitHub: {query}")
            repos = self.intel.search_github_repos(query, max_results=3, min_stars=10)
            stats["github_repos"] += len(repos)

            for repo in repos:
                readme = self.intel.fetch_github_readme(repo["name"])
                if readme and self.intel.index_github_repo(repo, readme):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        # Security blogs (recent posts only)
        logger.info("📰 Fetching security blogs...")
        posts = self.intel.fetch_security_blogs(max_posts_per_blog=2, days_back=7)
        stats["blog_posts"] = len(posts)

        for post in posts:
            if self.intel.index_blog_post(post):
                stats["indexed"] += 1
            else:
                stats["errors"] += 1

        logger.info(f"✅ Daily update complete: {stats['indexed']} items indexed")
        return stats

    def weekly_update(self) -> Dict:
        """
        Weekly heavy update - comprehensive refresh
        Includes arXiv papers and deeper GitHub search
        """
        logger.info("🔄 Starting WEEKLY intelligence update...")

        github_queries = [
            # Comprehensive malware queries
            "process injection EDR evasion",
            "syscalls direct NTDLL",
            "Hell's Gate Halo's Gate",
            "AMSI bypass ETW patching",
            "shellcode encryption loader",
            "reflective DLL injection",
            "Cobalt Strike beacon",
            "Sliver implant malware",
            "unhooking NTDLL",
            "stack spoofing",
            "API hashing malware",
            "process hollowing doppelganging"
        ]

        arxiv_queries = [
            "malware detection evasion",
            "adversarial machine learning security",
            "EDR bypass",
            "polymorphic malware",
            "syscall hooking"
        ]

        stats = {
            "mode": "weekly",
            "timestamp": datetime.now().isoformat(),
            "github_repos": 0,
            "blog_posts": 0,
            "arxiv_papers": 0,
            "indexed": 0,
            "errors": 0
        }

        # GitHub (comprehensive)
        for query in github_queries:
            logger.info(f"📂 GitHub: {query}")
            repos = self.intel.search_github_repos(query, max_results=5, min_stars=5)
            stats["github_repos"] += len(repos)

            for repo in repos:
                readme = self.intel.fetch_github_readme(repo["name"])
                if readme and self.intel.index_github_repo(repo, readme):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        # arXiv papers (weekly only)
        for query in arxiv_queries:
            logger.info(f"📄 arXiv: {query}")
            papers = self.intel.search_arxiv_papers(query, max_results=10, days_back=30)
            stats["arxiv_papers"] += len(papers)

            for paper in papers:
                if self.intel.index_research_paper(paper):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        # Security blogs (comprehensive)
        logger.info("📰 Fetching security blogs...")
        posts = self.intel.fetch_security_blogs(max_posts_per_blog=5, days_back=30)
        stats["blog_posts"] = len(posts)

        for post in posts:
            if self.intel.index_blog_post(post):
                stats["indexed"] += 1
            else:
                stats["errors"] += 1

        logger.info(f"✅ Weekly update complete: {stats['indexed']} items indexed")
        return stats

    def manual_update(self, custom_queries: List[str] = None) -> Dict:
        """
        Manual update with custom queries
        For testing or specific intelligence gathering
        """
        logger.info("🔄 Starting MANUAL intelligence update...")

        if not custom_queries:
            custom_queries = [
                "malware development",
                "red team tools",
                "offensive security"
            ]

        return self.intel.full_intelligence_refresh(
            github_queries=custom_queries,
            arxiv_queries=custom_queries[:2],
            fetch_blogs=True
        )

    def run(self, mode: str = "daily") -> Dict:
        """
        Run intelligence update

        Args:
            mode: daily, weekly, or manual

        Returns:
            Statistics dictionary
        """
        logger.info(f"=" * 70)
        logger.info(f"  Noctis-MCP Intelligence Updater - {mode.upper()} Mode")
        logger.info(f"=" * 70)

        # Check RAG status
        rag_stats = self.rag.get_stats()
        logger.info(f"📊 Current RAG Status:")
        logger.info(f"   Knowledge: {rag_stats.get('knowledge_base', 0)} chunks")
        logger.info(f"   GitHub: {rag_stats.get('github_repos', 0)} repos")
        logger.info(f"   Papers: {rag_stats.get('research_papers', 0)} papers")
        logger.info(f"   Blogs: {rag_stats.get('blog_posts', 0)} posts")
        logger.info(f"")

        # Run update
        if mode == "daily":
            stats = self.daily_update()
        elif mode == "weekly":
            stats = self.weekly_update()
        elif mode == "manual":
            stats = self.manual_update()
        else:
            raise ValueError(f"Unknown mode: {mode}")

        # Update historical stats
        historical = self.load_stats()
        historical["total_runs"] += 1
        historical["total_indexed"] += stats["indexed"]
        historical["last_run"] = stats["timestamp"]
        historical["runs"].append(stats)

        # Keep only last 30 runs
        historical["runs"] = historical["runs"][-30:]
        self.save_stats(historical)

        # Final RAG stats
        final_rag_stats = self.rag.get_stats()
        logger.info(f"")
        logger.info(f"📊 Final RAG Status:")
        logger.info(f"   Knowledge: {final_rag_stats.get('knowledge_base', 0)} chunks")
        logger.info(f"   GitHub: {final_rag_stats.get('github_repos', 0)} repos")
        logger.info(f"   Papers: {final_rag_stats.get('research_papers', 0)} papers")
        logger.info(f"   Blogs: {final_rag_stats.get('blog_posts', 0)} posts")

        logger.info(f"")
        logger.info(f"=" * 70)
        logger.info(f"✅ Update complete!")
        logger.info(f"   Mode: {stats['mode']}")
        logger.info(f"   Items indexed: {stats['indexed']}")
        logger.info(f"   Errors: {stats['errors']}")
        logger.info(f"   Total runs: {historical['total_runs']}")
        logger.info(f"   Total indexed: {historical['total_indexed']}")
        logger.info(f"   Log file: {log_file}")
        logger.info(f"=" * 70)

        return stats


def main():
    parser = argparse.ArgumentParser(description="Noctis-MCP Intelligence Auto-Updater")
    parser.add_argument(
        '--mode',
        choices=['daily', 'weekly', 'manual'],
        default='daily',
        help='Update mode: daily (light), weekly (heavy), manual (custom)'
    )
    parser.add_argument(
        '--queries',
        nargs='+',
        help='Custom queries for manual mode'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be updated without actually indexing'
    )

    args = parser.parse_args()

    try:
        # Initialize RAG
        logger.info("🚀 Initializing RAG engine...")
        rag = RAGEngine(persist_dir="data/rag_db")

        if not rag.enabled:
            logger.error("❌ RAG engine not enabled. Install dependencies:")
            logger.error("   pip install chromadb sentence-transformers")
            sys.exit(1)

        # Run updater
        updater = IntelligenceUpdater(rag)

        if args.mode == "manual" and args.queries:
            stats = updater.manual_update(args.queries)
        else:
            stats = updater.run(args.mode)

        # Print summary
        print("\n" + "=" * 70)
        print("📊 UPDATE SUMMARY")
        print("=" * 70)
        print(f"Mode:          {stats['mode']}")
        print(f"GitHub Repos:  {stats['github_repos']}")
        print(f"Blog Posts:    {stats['blog_posts']}")
        print(f"Papers:        {stats.get('arxiv_papers', 0)}")
        print(f"Indexed:       {stats['indexed']}")
        print(f"Errors:        {stats['errors']}")
        print(f"Timestamp:     {stats['timestamp']}")
        print("=" * 70)

        sys.exit(0)

    except KeyboardInterrupt:
        logger.info("\n⚠️  Update interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"❌ Update failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
