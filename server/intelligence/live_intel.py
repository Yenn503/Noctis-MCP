#!/usr/bin/env python3
"""
Live Intelligence Gathering System
===================================

Fetches real-time intelligence from:
- GitHub repositories (evasion techniques, tools)
- arXiv research papers (security research)
- Security blogs (MDSec, Outflank, XPN, TrustedSec, SpecterOps)

Auto-indexes into RAG system for intelligent retrieval.
"""

import requests
import feedparser
import arxiv
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import time
import logging
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)


class LiveIntelligence:
    """Gathers live intelligence from GitHub, arXiv, and security blogs"""

    def __init__(self, rag_engine=None):
        """
        Initialize intelligence gathering system

        Args:
            rag_engine: Optional RAG engine for auto-indexing
        """
        self.rag_engine = rag_engine

        # GitHub API configuration
        self.github_api = "https://api.github.com"
        self.github_token = os.getenv("GITHUB_TOKEN")  # Optional: for higher rate limits

        # Malware & Red Team Specific Feeds (High Value for Offensive Security)
        self.security_blogs = {
            # Elite Red Team Blogs
            "MDSec": "https://www.mdsec.co.uk/feed/",
            "Outflank": "https://outflank.nl/blog/feed/",
            "XPN InfoSec": "https://blog.xpnsec.com/rss.xml",
            "TrustedSec": "https://www.trustedsec.com/feed/",
            "SpecterOps": "https://posts.specterops.io/feed",

            # Malware Analysis & Techniques
            "Malware-Traffic-Analysis": "https://www.malware-traffic-analysis.net/blog-entries.rss",
            "Malwarebytes Labs": "https://www.malwarebytes.com/blog/feed/index.xml",
            "Hybrid Analysis Blog": "https://www.hybrid-analysis.com/feed",
            "VX Underground": "https://www.vx-underground.org/feed.xml",  # Premier malware research

            # Exploit Development & Research
            "Exploit-DB": "https://www.exploit-db.com/rss.xml",
            "Project Zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
            "ZDI (Zero Day Initiative)": "https://www.zerodayinitiative.com/blog?format=rss",

            # Windows Internals & Evasion
            "Red Team Notes (ired.team)": "https://www.ired.team/feed",
            "Pentester Academy": "https://blog.pentesteracademy.com/feed",
            "0x00sec": "https://0x00sec.org/posts.rss",
            "Hexacorn": "https://www.hexacorn.com/blog/feed/",  # EDR bypass guru

            # APT & Advanced Techniques
            "Unit42 Palo Alto": "https://unit42.paloaltonetworks.com/feed/",
            "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
            "CrowdStrike Blog": "https://www.crowdstrike.com/blog/feed/",

            # General Security News (filtered for malware content)
            "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "Dark Reading": "https://www.darkreading.com/rss.xml",
            "Krebs on Security": "https://krebsonsecurity.com/feed/"
        }

        # Rate limiting
        self.last_github_request = 0
        self.github_rate_limit = 1.0  # seconds between requests

    def _rate_limit_github(self):
        """Enforce GitHub API rate limiting"""
        elapsed = time.time() - self.last_github_request
        if elapsed < self.github_rate_limit:
            time.sleep(self.github_rate_limit - elapsed)
        self.last_github_request = time.time()

    def _get_github_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Noctis-MCP-Intelligence"
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    def search_github_repos(
        self,
        query: str,
        max_results: int = 10,
        min_stars: int = 5
    ) -> List[Dict]:
        """
        Search GitHub for relevant repositories

        Args:
            query: Search query (e.g., "process injection EDR evasion")
            max_results: Maximum number of repos to return
            min_stars: Minimum star count filter

        Returns:
            List of repository data dictionaries
        """
        self._rate_limit_github()

        try:
            # Build search query with filters
            search_query = f"{query} stars:>={min_stars}"

            url = f"{self.github_api}/search/repositories"
            params = {
                "q": search_query,
                "sort": "stars",
                "order": "desc",
                "per_page": max_results
            }

            response = requests.get(
                url,
                headers=self._get_github_headers(),
                params=params,
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            repos = []

            for item in data.get("items", []):
                repo_data = {
                    "name": item["full_name"],
                    "description": item.get("description", ""),
                    "url": item["html_url"],
                    "stars": item["stargazers_count"],
                    "language": item.get("language", "Unknown"),
                    "updated_at": item["updated_at"],
                    "topics": item.get("topics", [])
                }
                repos.append(repo_data)

                logger.info(f"Found repo: {repo_data['name']} ({repo_data['stars']} stars)")

            return repos

        except requests.RequestException as e:
            logger.error(f"GitHub search failed: {e}")
            return []

    def fetch_github_readme(self, repo_full_name: str) -> Optional[str]:
        """
        Fetch README content from a GitHub repository

        Args:
            repo_full_name: Full repo name (e.g., "user/repo")

        Returns:
            README content as markdown string, or None if not found
        """
        self._rate_limit_github()

        try:
            url = f"{self.github_api}/repos/{repo_full_name}/readme"

            response = requests.get(
                url,
                headers={
                    **self._get_github_headers(),
                    "Accept": "application/vnd.github.v3.raw"
                },
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Fetched README for {repo_full_name}")
                return response.text
            else:
                logger.warning(f"No README found for {repo_full_name}")
                return None

        except requests.RequestException as e:
            logger.error(f"Failed to fetch README for {repo_full_name}: {e}")
            return None

    def search_arxiv_papers(
        self,
        query: str,
        max_results: int = 10,
        days_back: int = 365
    ) -> List[Dict]:
        """
        Search arXiv for security research papers

        Args:
            query: Search query (e.g., "malware detection evasion")
            max_results: Maximum number of papers
            days_back: Only include papers from last N days

        Returns:
            List of paper data dictionaries
        """
        try:
            # Build arXiv query
            search = arxiv.Search(
                query=query,
                max_results=max_results,
                sort_by=arxiv.SortCriterion.SubmittedDate,
                sort_order=arxiv.SortOrder.Descending
            )

            papers = []
            cutoff_date = datetime.now() - timedelta(days=days_back)

            for result in search.results():
                # Filter by date
                if result.published.replace(tzinfo=None) < cutoff_date:
                    continue

                paper_data = {
                    "title": result.title,
                    "authors": [author.name for author in result.authors],
                    "summary": result.summary,
                    "published": result.published.isoformat(),
                    "url": result.entry_id,
                    "pdf_url": result.pdf_url,
                    "categories": result.categories
                }
                papers.append(paper_data)

                logger.info(f"Found paper: {paper_data['title']}")

            return papers

        except Exception as e:
            logger.error(f"arXiv search failed: {e}")
            return []

    def fetch_security_blogs(
        self,
        max_posts_per_blog: int = 5,
        days_back: int = 90
    ) -> List[Dict]:
        """
        Fetch latest posts from security blogs

        Args:
            max_posts_per_blog: Max posts to fetch per blog
            days_back: Only include posts from last N days

        Returns:
            List of blog post data dictionaries
        """
        all_posts = []
        cutoff_date = datetime.now() - timedelta(days=days_back)

        for blog_name, feed_url in self.security_blogs.items():
            try:
                logger.info(f"Fetching {blog_name} blog posts...")

                feed = feedparser.parse(feed_url)
                posts_found = 0

                for entry in feed.entries[:max_posts_per_blog * 2]:  # Fetch extra in case some are old
                    # Parse publish date
                    published = None
                    if hasattr(entry, 'published_parsed'):
                        published = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed'):
                        published = datetime(*entry.updated_parsed[:6])

                    # Filter by date
                    if published and published < cutoff_date:
                        continue

                    # Extract content
                    content = ""
                    if hasattr(entry, 'content'):
                        content = entry.content[0].value
                    elif hasattr(entry, 'summary'):
                        content = entry.summary

                    # Clean HTML
                    soup = BeautifulSoup(content, 'lxml')
                    clean_content = soup.get_text(separator='\n', strip=True)

                    post_data = {
                        "blog": blog_name,
                        "title": entry.title,
                        "url": entry.link,
                        "published": published.isoformat() if published else None,
                        "content": clean_content[:2000],  # Limit content size
                        "summary": entry.get('summary', '')[:500]
                    }
                    all_posts.append(post_data)
                    posts_found += 1

                    logger.info(f"  - {post_data['title']}")

                    if posts_found >= max_posts_per_blog:
                        break

            except Exception as e:
                logger.error(f"Failed to fetch {blog_name}: {e}")
                continue

        return all_posts

    def index_github_repo(self, repo_data: Dict, readme: str) -> bool:
        """
        Index a GitHub repository into RAG system

        Args:
            repo_data: Repository metadata
            readme: README content

        Returns:
            True if indexed successfully
        """
        if not self.rag_engine:
            logger.warning("No RAG engine configured")
            return False

        try:
            self.rag_engine.add_github_repo(
                repo_name=repo_data["name"],
                description=repo_data["description"],
                readme=readme,
                url=repo_data["url"]
            )
            logger.info(f"Indexed GitHub repo: {repo_data['name']} ({repo_data['stars']} stars)")
            return True

        except Exception as e:
            logger.error(f"Failed to index repo {repo_data['name']}: {e}")
            return False

    def index_research_paper(self, paper_data: Dict) -> bool:
        """
        Index a research paper into RAG system

        Args:
            paper_data: Paper metadata and content

        Returns:
            True if indexed successfully
        """
        if not self.rag_engine:
            logger.warning("No RAG engine configured")
            return False

        try:
            self.rag_engine.add_research_paper(
                title=paper_data["title"],
                abstract=paper_data["summary"],
                url=paper_data["url"],
                published=paper_data.get("published", "unknown")
            )
            logger.info(f"Indexed research paper: {paper_data['title']}")
            return True

        except Exception as e:
            logger.error(f"Failed to index paper {paper_data['title']}: {e}")
            return False

    def index_blog_post(self, post_data: Dict) -> bool:
        """
        Index a blog post into RAG system

        Args:
            post_data: Blog post metadata and content

        Returns:
            True if indexed successfully
        """
        if not self.rag_engine:
            logger.warning("No RAG engine configured")
            return False

        try:
            self.rag_engine.add_blog_post(
                title=post_data["title"],
                summary=post_data["content"],
                url=post_data["url"],
                published=post_data.get("published", "unknown")
            )
            logger.info(f"Indexed blog post: {post_data['title']}")
            return True

        except Exception as e:
            logger.error(f"Failed to index blog post {post_data['title']}: {e}")
            return False

    def full_intelligence_refresh(
        self,
        github_queries: List[str] = None,
        arxiv_queries: List[str] = None,
        fetch_blogs: bool = True
    ) -> Dict:
        """
        Perform a full intelligence refresh from all sources

        Args:
            github_queries: List of GitHub search queries
            arxiv_queries: List of arXiv search queries
            fetch_blogs: Whether to fetch security blog posts

        Returns:
            Summary statistics
        """
        stats = {
            "github_repos": 0,
            "arxiv_papers": 0,
            "blog_posts": 0,
            "indexed": 0,
            "errors": 0
        }

        # Default queries if none provided - MALWARE FOCUSED
        if github_queries is None:
            github_queries = [
                # Process Injection & Evasion
                "process injection EDR evasion",
                "process hollowing doppelganging",
                "thread hijacking APC injection",

                # Syscalls & API Techniques
                "syscalls direct NTDLL",
                "Hell's Gate Halo's Gate",
                "SysWhispers indirect syscalls",

                # Obfuscation & Evasion
                "API hashing malware",
                "string encryption obfuscation",
                "control flow flattening",

                # EDR/AV Bypass
                "AMSI bypass",
                "ETW patching disable",
                "NTDLL unhooking",
                "PPL protected process",

                # Shellcode & Loaders
                "shellcode encryption loader",
                "reflective DLL injection",
                "beacon object files BOF",

                # C2 & Persistence
                "command control evasion",
                "persistence techniques Windows",
                "fileless malware memory",

                # Modern Techniques
                "Cobalt Strike beacon",
                "Sliver implant",
                "stack spoofing call stack",
                "Heaven's Gate WoW64"
            ]

        if arxiv_queries is None:
            arxiv_queries = [
                # Core Malware Research
                "malware detection evasion",
                "adversarial machine learning security",
                "EDR bypass techniques",

                # Advanced Topics
                "polymorphic metamorphic malware",
                "syscall hooking detection",
                "memory forensics evasion",
                "steganography malware",

                # AI/ML Security
                "adversarial examples malware",
                "machine learning evasion attacks"
            ]

        logger.info("=== Starting Full Intelligence Refresh ===")

        # GitHub repositories
        for query in github_queries:
            logger.info(f"Searching GitHub: {query}")
            repos = self.search_github_repos(query, max_results=5)
            stats["github_repos"] += len(repos)

            for repo in repos:
                readme = self.fetch_github_readme(repo["name"])
                if readme and self.index_github_repo(repo, readme):
                    stats["indexed"] += 1
                elif readme is None:
                    stats["errors"] += 1

        # arXiv papers
        for query in arxiv_queries:
            logger.info(f"Searching arXiv: {query}")
            papers = self.search_arxiv_papers(query, max_results=10)
            stats["arxiv_papers"] += len(papers)

            for paper in papers:
                if self.index_research_paper(paper):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        # Security blogs
        if fetch_blogs:
            logger.info("Fetching security blog posts...")
            posts = self.fetch_security_blogs(max_posts_per_blog=5)
            stats["blog_posts"] += len(posts)

            for post in posts:
                if self.index_blog_post(post):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        logger.info("=== Intelligence Refresh Complete ===")
        logger.info(f"Stats: {stats}")

        return stats


# Standalone usage
if __name__ == "__main__":
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

    from rag.rag_engine import RAGEngine

    # Initialize
    rag = RAGEngine()
    intel = LiveIntelligence(rag_engine=rag)

    # Run full refresh
    stats = intel.full_intelligence_refresh()

    print("\n=== Intelligence Refresh Summary ===")
    print(f"GitHub Repos Found: {stats['github_repos']}")
    print(f"arXiv Papers Found: {stats['arxiv_papers']}")
    print(f"Blog Posts Found: {stats['blog_posts']}")
    print(f"Total Indexed: {stats['indexed']}")
    print(f"Errors: {stats['errors']}")
