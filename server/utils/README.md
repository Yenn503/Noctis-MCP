# Server Utilities

## Caching Strategy

### Intelligence Cache (`IntelligenceCache`)
**Purpose**: Speed up repeat intelligence searches
**TTL**: 24 hours
**What it caches**: RAG search results ONLY
**Why 24hr**: Security intelligence changes frequently, fresh data is important

**Does NOT cache**:
- User education progress (stored in SQLite permanently)
- Quiz scores (stored in SQLite permanently)
- Achievements (stored in SQLite permanently)
- Lesson completions (stored in SQLite permanently)

### Embedding Cache (`EmbeddingCache`)
**Purpose**: Avoid redundant embedding generation
**TTL**: No expiration (embeddings don't change)
**What it caches**: Text embeddings for common queries
**Size**: 500 entries (LRU eviction)

### Metrics Collector (`MetricsCollector`)
**Purpose**: Track API performance
**Tracks**: Request counts, response times, errors
**Storage**: In-memory only (resets on server restart)

---

## Data Persistence

| Data Type | Storage | Duration | Location |
|-----------|---------|----------|----------|
| **Education Progress** | SQLite | Permanent | `data/education_progress.db` |
| **Quiz Scores** | SQLite | Permanent | `data/education_progress.db` |
| **Achievements** | SQLite | Permanent | `data/education_progress.db` |
| **RAG Documents** | ChromaDB | Permanent | `data/rag_db/` |
| **Intelligence Search Results** | Memory Cache | 24 hours | RAM (temporary) |
| **Embeddings** | Memory Cache | Until evicted | RAM (temporary) |
| **Metrics** | Memory | Until restart | RAM (temporary) |

**Key Point**: User data is NEVER cached temporarily. Only search results are cached for performance.
