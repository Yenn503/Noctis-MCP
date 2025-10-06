"""
RAG (Retrieval Augmented Generation) Engine for Noctis-MCP
Real vector embeddings with ChromaDB + sentence-transformers
NO MOCK DATA - production-ready implementation
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional
import time

logger = logging.getLogger(__name__)

# Lazy imports - only load when needed
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.warning("ChromaDB not installed - RAG features disabled")

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not installed - RAG features disabled")


class RAGEngine:
    """
    Production RAG system using ChromaDB for vector storage
    """

    def __init__(self, persist_dir: str = "data/rag_db"):
        if not CHROMADB_AVAILABLE or not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.error("RAG dependencies not installed. Run: pip install chromadb sentence-transformers")
            self.enabled = False
            return

        self.enabled = True
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)

        # Initialize embedding model (local, no API calls)
        logger.info("[RAG] Loading embedding model (all-MiniLM-L6-v2)...")
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        logger.info("[RAG] Embedding model loaded")

        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=persist_dir,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

        # Create collections
        self.knowledge = self._get_or_create_collection("malware_knowledge")
        self.github_repos = self._get_or_create_collection("github_techniques")
        self.research_papers = self._get_or_create_collection("research_papers")
        self.blog_posts = self._get_or_create_collection("security_blogs")
        self.detection_intel = self._get_or_create_collection("av_detections")

        logger.info("[RAG] ChromaDB initialized successfully")

    def _get_or_create_collection(self, name: str):
        """Get or create collection"""
        try:
            return self.client.get_collection(name)
        except Exception as e:
            # Collection doesn't exist, create it
            logger.debug(f"Collection '{name}' not found, creating new collection: {e}")
            return self.client.create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )

    def index_knowledge_base(self, knowledge_dir: str = "techniques/knowledge"):
        """Index markdown knowledge files into RAG"""
        if not self.enabled:
            return 0

        knowledge_path = Path(knowledge_dir)
        if not knowledge_path.exists():
            logger.warning(f"[RAG] Knowledge directory not found: {knowledge_dir}")
            return 0

        indexed_count = 0

        for md_file in knowledge_path.rglob("*.md"):
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Split into semantic chunks
                chunks = self._chunk_markdown(content)

                for i, chunk in enumerate(chunks):
                    # Generate embedding
                    embedding = self.embedder.encode(chunk['text']).tolist()

                    # Store in ChromaDB
                    self.knowledge.upsert(
                        ids=[f"{md_file.stem}_{i}"],
                        embeddings=[embedding],
                        documents=[chunk['text']],
                        metadatas=[{
                            'source': str(md_file),
                            'technique': md_file.stem,
                            'section': chunk['heading'],
                            'type': 'knowledge_base'
                        }]
                    )
                    indexed_count += 1

            except Exception as e:
                logger.error(f"[RAG] Failed to index {md_file}: {e}")

        logger.info(f"[RAG] Indexed {indexed_count} knowledge chunks")
        return indexed_count

    def search_knowledge(
        self,
        query: str,
        target_av: str = None,
        n_results: int = 5
    ) -> List[Dict]:
        """
        Search all collections for relevant knowledge
        Returns ranked results from all sources
        """
        if not self.enabled:
            return []

        # Build enhanced query
        search_query = query
        if target_av:
            search_query = f"{query} {target_av} evasion detection"

        # Generate embedding
        query_embedding = self.embedder.encode(search_query).tolist()

        all_results = []

        # Search each collection
        collections = [
            (self.knowledge, 'knowledge_base', n_results),
            (self.github_repos, 'github', 3),
            (self.research_papers, 'research', 3),
            (self.blog_posts, 'blog', 2)
        ]

        for collection, source_type, limit in collections:
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=limit
                )
                all_results.extend(self._format_results(results, source_type))
            except Exception as e:
                logger.error(f"[RAG] Search failed for {source_type}: {e}")

        # Search detection intel if AV specified
        if target_av:
            try:
                av_query = f"{target_av} detection patterns IOCs"
                av_embedding = self.embedder.encode(av_query).tolist()
                detection_results = self.detection_intel.query(
                    query_embeddings=[av_embedding],
                    n_results=3
                )
                all_results.extend(self._format_results(detection_results, 'detection'))
            except Exception as e:
                logger.error(f"[RAG] Detection search failed: {e}")

        # Sort by relevance (distance - lower is better)
        all_results.sort(key=lambda x: x.get('distance', 1.0))

        return all_results[:n_results * 2]

    def add_github_repo(self, repo_name: str, description: str, readme: str, url: str):
        """Add GitHub repository to RAG"""
        if not self.enabled:
            return

        text = f"{repo_name}\n\n{description}\n\n{readme[:2000]}"
        embedding = self.embedder.encode(text).tolist()

        self.github_repos.upsert(
            ids=[url],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                'name': repo_name,
                'url': url,
                'type': 'github_repo',
                'indexed_at': time.strftime('%Y-%m-%d')
            }]
        )

    def add_research_paper(self, title: str, abstract: str, url: str, published: str = None):
        """Add research paper to RAG"""
        if not self.enabled:
            return

        text = f"{title}\n\n{abstract}"
        embedding = self.embedder.encode(text).tolist()

        self.research_papers.upsert(
            ids=[url],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                'title': title,
                'url': url,
                'published': published or 'unknown',
                'type': 'research_paper'
            }]
        )

    def add_blog_post(self, title: str, summary: str, url: str, published: str = None):
        """Add security blog post to RAG"""
        if not self.enabled:
            return

        text = f"{title}\n\n{summary}"
        embedding = self.embedder.encode(text).tolist()

        self.blog_posts.upsert(
            ids=[url],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                'title': title,
                'url': url,
                'published': published or 'unknown',
                'type': 'blog_post'
            }]
        )

    def add_markdown_knowledge(self, title: str, content: str, technique_id: str, metadata: dict = None):
        """Add markdown knowledge file to RAG"""
        if not self.enabled:
            return

        # Split into semantic chunks
        chunks = self._chunk_markdown(content)

        for i, chunk in enumerate(chunks):
            # Generate embedding
            embedding = self.embedder.encode(chunk['text']).tolist()

            # Prepare metadata
            chunk_metadata = {
                'title': title,
                'technique_id': technique_id,
                'section': chunk['heading'],
                'type': 'knowledge_base',
                'indexed_at': time.strftime('%Y-%m-%d')
            }
            if metadata:
                chunk_metadata.update(metadata)

            # Store in ChromaDB
            doc_id = f"{technique_id}_{i}"
            self.knowledge.upsert(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[chunk['text']],
                metadatas=[chunk_metadata]
            )

    def add_detection_pattern(
        self,
        av_name: str,
        technique: str,
        ioc_description: str,
        detected: bool,
        date: str
    ):
        """Record AV detection pattern from user feedback"""
        if not self.enabled:
            return

        text = f"{av_name} detection for {technique}: {ioc_description}"
        embedding = self.embedder.encode(text).tolist()

        doc_id = f"{av_name}_{technique}_{int(time.time())}"

        self.detection_intel.add(
            ids=[doc_id],
            embeddings=[embedding],
            documents=[text],
            metadatas=[{
                'av': av_name,
                'technique': technique,
                'detected': detected,
                'date': date,
                'type': 'detection_pattern'
            }]
        )

    def get_stats(self) -> Dict:
        """Get RAG system statistics"""
        if not self.enabled:
            return {'enabled': False}

        return {
            'enabled': True,
            'knowledge_base': self.knowledge.count(),
            'github_repos': self.github_repos.count(),
            'research_papers': self.research_papers.count(),
            'blog_posts': self.blog_posts.count(),
            'detection_intel': self.detection_intel.count(),
            'embedding_model': 'all-MiniLM-L6-v2',
            'vector_db': 'ChromaDB'
        }

    def _chunk_markdown(self, content: str) -> List[Dict]:
        """Split markdown by headings for semantic chunking"""
        chunks = []
        current_heading = "Introduction"
        current_lines = []

        for line in content.split('\n'):
            if line.startswith('#'):
                # Save previous chunk
                if current_lines:
                    text = '\n'.join(current_lines).strip()
                    if len(text) > 50:  # Filter tiny chunks
                        chunks.append({
                            'heading': current_heading,
                            'text': text
                        })
                # Start new chunk
                current_heading = line.strip('#').strip()
                current_lines = [line]
            else:
                current_lines.append(line)

        # Add final chunk
        if current_lines:
            text = '\n'.join(current_lines).strip()
            if len(text) > 50:
                chunks.append({
                    'heading': current_heading,
                    'text': text
                })

        return chunks

    def _format_results(self, results: Dict, source_type: str) -> List[Dict]:
        """Format ChromaDB results"""
        formatted = []

        if not results or not results.get('documents'):
            return formatted

        # Handle case where documents is a list of lists
        documents = results['documents'][0] if isinstance(results['documents'][0], list) else results['documents']
        
        for i, doc in enumerate(documents):
            formatted.append({
                'content': doc,  # Use 'content' as primary key for consistency
                'text': doc,     # Keep 'text' for backward compatibility
                'metadata': results['metadatas'][0][i] if results.get('metadatas') and len(results['metadatas']) > 0 else {},
                'distance': results['distances'][0][i] if results.get('distances') and len(results['distances']) > 0 else 1.0,
                'source': source_type  # Use 'source' for consistency with other parts of codebase
            })

        return formatted
