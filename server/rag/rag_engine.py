"""
Simple RAG Engine - Search techniques for code snippets
"""
from pathlib import Path
import re

class RAGEngine:
    """Simple file-based RAG (no ChromaDB needed for v3.0)"""

    def __init__(self):
        self.techniques_dir = Path("techniques")
        self.enabled = self.techniques_dir.exists()

    def search(self, query, n_results=5):
        """Search for technique implementations"""
        if not self.enabled:
            return []

        results = []
        query_lower = query.lower()

        # Search all .c and .h files
        for file_path in self.techniques_dir.rglob("*.c"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Simple relevance: count query word occurrences
                    relevance = sum(1 for word in query_lower.split() if word in content.lower())

                    if relevance > 0:
                        # Extract first function or comment block
                        lines = content.split('\n')
                        snippet = '\n'.join(lines[:50])  # First 50 lines

                        results.append({
                            'file': str(file_path),
                            'content': snippet,
                            'document': snippet,
                            'relevance': relevance
                        })
            except:
                continue

        # Sort by relevance
        results.sort(key=lambda x: x['relevance'], reverse=True)
        return results[:n_results]
