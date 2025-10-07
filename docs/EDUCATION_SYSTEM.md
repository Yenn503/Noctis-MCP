# Education System Architecture

## Overview

The Noctis-MCP Education System provides an interactive, AI-powered learning experience for malware development techniques. The system uses **curated, consistent lessons** (not RAG-generated) to ensure every learner receives the same high-quality content.

## Design Principles

1. **Consistency First**: All lessons are curated and fixed in `data/lessons.json`, ensuring every user gets identical, high-quality content
2. **No RAG for Lessons**: Unlike the intelligence gathering system, lessons are NOT dynamically generated to avoid inconsistency
3. **AI as Teacher**: The IDE's AI (Claude/GPT-4) acts as an interactive tutor using MCP tools to deliver structured content
4. **Progress Tracking**: SQLite database tracks user progress, quiz scores, and achievements
5. **Gamification**: Achievements and progress tracking encourage continued learning

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      USER IN IDE                             │
│  (Asks AI: "I want to learn process injection")             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   AI AGENT (Claude/GPT-4)                    │
│  - Decides which MCP tool to call                            │
│  - Teaches content interactively                             │
│  - Adapts to user questions                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              MCP EDUCATION TOOLS (9 Tools)                   │
│  list_learning_topics() ────────┐                            │
│  start_lesson()                 │                            │
│  get_lesson_module()            │                            │
│  complete_module()              ├─► noctis_mcp_client/       │
│  check_understanding()          │   noctis_mcp.py            │
│  submit_quiz()                  │                            │
│  get_learning_progress()        │                            │
│  get_recommended_lesson()       │                            │
│  search_lessons() ──────────────┘                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼ HTTP Requests
┌─────────────────────────────────────────────────────────────┐
│           EDUCATION API (Flask Blueprint)                    │
│  /api/v2/education/topics                                    │
│  /api/v2/education/topic/<id>                                │
│  /api/v2/education/lesson/<id>/module/<n>                    │
│  /api/v2/education/progress                                  │
│  /api/v2/education/quiz/<id>                  ──────────────┐│
│  /api/v2/education/quiz/<id>/submit                         ││
│  /api/v2/education/recommend                                ││
└────────────────────────┬───────────────────────────────────┬┘│
                         │                                   │ │
                         ▼                                   ▼ │
           ┌─────────────────────────┐      ┌──────────────────┴───┐
           │   LESSON MANAGER        │      │  PROGRESS TRACKER    │
           │  lesson_manager.py      │      │  learning_engine.py  │
           │                         │      │                      │
           │ - Loads lessons.json    │      │ - SQLite database    │
           │ - Returns curated       │      │ - Track progress     │
           │   content               │      │ - Quiz scores        │
           │ - No dynamic generation │      │ - Achievements       │
           └────────┬────────────────┘      └──────────┬───────────┘
                    │                                  │
                    ▼                                  ▼
         ┌──────────────────┐                ┌────────────────────┐
         │  data/           │                │  data/             │
         │  lessons.json    │                │  quizzes.json      │
         │                  │                │                    │
         │  10 curated      │                │  10 quiz           │
         │  techniques      │                │  question banks    │
         └──────────────────┘                └────────────────────┘
```

## Data Flow

### Learning Flow Example

```
1. User: "I want to learn malware development"

2. AI calls: list_learning_topics()
   → API: GET /api/v2/education/topics
   → LessonManager loads data/lessons.json
   → Returns: 10 techniques sorted by difficulty

3. AI shows user the curriculum organized by difficulty:
   BEGINNER: Process Injection, Persistence...
   INTERMEDIATE: Shellcode Injection, PE Manipulation...
   ADVANCED: Direct Syscalls, Process Hollowing...

4. User: "Teach me process injection"

5. AI calls: start_lesson('process_injection')
   → API: GET /api/v2/education/topic/process_injection
   → LessonManager returns lesson overview
   → AI shows: 4 modules (theory, code, labs)

6. AI calls: get_lesson_module('process_injection', 1)
   → API: GET /api/v2/education/lesson/process_injection/module/1
   → LessonManager returns Module 1 content
   → ProgressTracker records user started
   → AI teaches content interactively

7. After discussion, AI calls: complete_module('process_injection', 1)
   → API: POST /api/v2/education/progress/.../complete
   → ProgressTracker updates SQLite database
   → Returns: Progress updated, 1/4 modules done

8. [Repeat for modules 2-4]

9. AI calls: check_understanding('process_injection')
   → API: GET /api/v2/education/quiz/process_injection
   → Returns: 10 multiple choice questions (no answers)
   → AI presents questions one by one

10. User answers all questions

11. AI calls: submit_quiz('process_injection', {answers})
    → API: POST /api/v2/education/quiz/process_injection/submit
    → Grades quiz, records in SQLite
    → Returns: Score 90%, PASSED, explanations for each
    → AI shows results and explains incorrect answers

12. AI calls: get_recommended_lesson()
    → Analyzes completed techniques
    → Returns: "Shellcode Injection" (prerequisite met)
```

## File Structure

```
Noctis-MCP/
│
├── data/
│   ├── lessons.json          # 10 curated techniques with modules
│   ├── quizzes.json          # Fixed question banks (70+ questions)
│   └── education_progress.db # SQLite (auto-created by ProgressTracker)
│
├── server/
│   ├── education/
│   │   ├── __init__.py
│   │   ├── learning_engine.py    # ProgressTracker, achievements
│   │   └── lesson_manager.py     # Loads and serves lessons
│   │
│   ├── education_api.py      # Flask blueprint with 15 endpoints
│   └── noctis_server.py      # Registers education_bp blueprint
│
├── noctis_mcp_client/
│   └── noctis_mcp.py         # 9 MCP education tools + formatters
│
└── docs/
    ├── EDUCATION_SYSTEM.md   # This file
    └── ARCHITECTURE.md       # System-wide architecture
```

## Key Components

### 1. Lesson Manager (`server/education/lesson_manager.py`)

**Purpose**: Load and serve curated lesson content

**Key Methods**:
- `list_all_techniques(sort_by)` - Get all techniques sorted
- `get_technique(technique_id)` - Get complete technique
- `get_module_content(technique_id, module_number)` - Get specific module
- `get_recommended_next(completed_ids)` - Suggest next lesson
- `search_techniques(query)` - Search by keyword

**No RAG, No AI Generation**: Content is loaded from JSON as-is

### 2. Progress Tracker (`server/education/learning_engine.py`)

**Purpose**: Track user progress and achievements

**Database Schema**:
```sql
CREATE TABLE user_progress (
    technique_id TEXT UNIQUE,
    modules_completed TEXT,  -- JSON array [1, 2, 3]
    quiz_score INTEGER,
    quiz_attempts INTEGER,
    completed_at TEXT,
    time_spent_minutes INTEGER,
    status TEXT,  -- 'not_started', 'in_progress', 'completed'
    current_module INTEGER
);

CREATE TABLE achievements (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    icon TEXT,
    earned_at TEXT
);

CREATE TABLE quiz_attempts (
    technique_id TEXT,
    total_questions INTEGER,
    correct_answers INTEGER,
    score INTEGER,
    timestamp TEXT
);
```

**Key Methods**:
- `get_progress(technique_id)` - Get user progress
- `complete_module(technique_id, module_number)` - Mark module done
- `record_quiz_attempt(technique_id, total, correct)` - Save quiz result
- `check_and_award_achievements(technique_id, progress)` - Award badges

### 3. Education API (`server/education_api.py`)

**Flask Blueprint**: `/api/v2/education/*`

**Endpoints**:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/topics` | List all techniques |
| GET | `/topics/categories` | Group by category |
| GET | `/topic/<id>` | Get technique overview |
| GET | `/lesson/<id>/module/<n>` | Get module content |
| POST | `/progress/<id>/module/<n>/complete` | Mark module complete |
| GET | `/quiz/<id>` | Get quiz questions |
| POST | `/quiz/<id>/submit` | Submit quiz answers |
| GET | `/progress` | Get all progress |
| GET | `/progress/<id>` | Get technique progress |
| GET | `/recommend` | Get recommendation |
| GET | `/search?q=query` | Search lessons |
| GET | `/achievements` | Get earned achievements |
| GET | `/stats` | Get learning stats |
| GET | `/validate/<id>` | Check prerequisites |

### 4. MCP Education Tools (`noctis_mcp_client/noctis_mcp.py`)

**9 Tools for AI Agent**:

1. `list_learning_topics(sort_by, difficulty, category)`
   - Shows curriculum to user
   - Sorts by difficulty/category/title

2. `start_lesson(technique_id)`
   - Gets lesson overview
   - Shows modules and prerequisites

3. `get_lesson_module(technique_id, module_number)`
   - Delivers actual teaching content
   - Theory, code, labs, etc.

4. `complete_module(technique_id, module_number)`
   - Marks module as done
   - Updates progress in DB

5. `check_understanding(technique_id)`
   - Gets quiz questions
   - No answers included (prevents cheating)

6. `submit_quiz(technique_id, answers)`
   - Grades quiz
   - Returns score, explanations, achievements

7. `get_learning_progress()`
   - Shows all progress
   - Completed vs in-progress

8. `get_recommended_lesson()`
   - Suggests next topic
   - Based on prerequisites

9. `search_lessons(query)`
   - Finds topics by keyword
   - Searches title, description, category

### 5. Lesson Data (`data/lessons.json`)

**Structure**:
```json
{
  "techniques": [
    {
      "id": "process_injection",
      "title": "Process Injection Fundamentals",
      "category": "Code Injection",
      "difficulty": "beginner",
      "estimated_minutes": 45,
      "prerequisites": [],
      "description": "...",
      "modules": [
        {
          "module_number": 1,
          "title": "Introduction to Process Injection",
          "type": "theory",
          "content": "# Markdown content with theory...",
          "code_examples": []
        },
        {
          "module_number": 2,
          "title": "Classic DLL Injection - Code",
          "type": "code",
          "content": "# Code examples with explanations...",
          "code_examples": [
            {
              "language": "c",
              "title": "Complete DLL Injector",
              "filename": "injector.c",
              "description": "Full implementation..."
            }
          ]
        },
        ...
      ]
    },
    ...
  ]
}
```

**10 Techniques Included**:
1. Process Injection Fundamentals (beginner)
2. Shellcode Injection (intermediate)
3. Process Hollowing (advanced)
4. API Hooking (advanced)
5. Direct Syscalls & Unhooking (advanced)
6. PE File Manipulation (intermediate)
7. Code Obfuscation (intermediate)
8. Persistence Mechanisms (beginner)
9. Crypters and Packers (advanced)
10. C2 Protocols (intermediate)

### 6. Quiz Data (`data/quizzes.json`)

**Structure**:
```json
{
  "quizzes": {
    "process_injection": {
      "technique_title": "Process Injection Fundamentals",
      "total_questions": 10,
      "passing_score": 70,
      "questions": [
        {
          "id": "pi_q1",
          "type": "multiple_choice",
          "difficulty": "beginner",
          "question": "What is process injection?",
          "options": ["Option A", "Option B", "Option C", "Option D"],
          "correct_index": 0,
          "explanation": "Detailed explanation..."
        },
        ...
      ]
    },
    ...
  }
}
```

**70+ Questions Total** across all techniques

## User Experience Flow

### Typical Learning Session

```
User: "I want to learn malware development"

AI: "Great! I can teach you 10 different techniques. Here's the curriculum:

BEGINNER LEVEL:
  • Process Injection Fundamentals (45 min)
    ID: process_injection
    Learn the foundational technique of injecting code into running processes

  • Persistence Mechanisms (50 min)
    ID: persistence
    Implement various persistence techniques to survive reboots

INTERMEDIATE LEVEL:
  • Shellcode Injection Techniques (60 min) [Requires: process_injection]
    ID: shellcode_injection
    Learn to inject raw shellcode instead of DLLs

  [... more techniques ...]

Which technique would you like to start with?"

User: "process injection"

AI: "Excellent choice! Let me give you an overview of Process Injection:

🎓 Process Injection Fundamentals
Difficulty: BEGINNER
Estimated Time: 45 minutes

Description:
Learn the foundational technique of injecting code into running processes
to evade detection and gain execution context.

Modules (4):
  1. 📖 Introduction to Process Injection (theory)
  2. 📖 Classic DLL Injection - Theory (theory)
  3. 💻 Classic DLL Injection - Code Implementation (code)
  4. 🧪 Hands-On Lab: DLL Injection (lab)

Ready to start Module 1?"

User: "yes"

AI: [Fetches module content and teaches interactively]

"# Process Injection Overview

Process injection is a technique used to execute arbitrary code within
the address space of a separate live process. This is fundamental to
malware development and red team operations.

## Why Process Injection?

- **Evasion**: Execute code under a legitimate process (e.g., explorer.exe)
- **Persistence**: Survive process termination by migrating
- **Privilege Escalation**: Inject into higher-privileged processes
...

[Continues teaching with examples and discussion]

Do you have any questions about this module?"

User: "What's the difference between VirtualAlloc and VirtualAllocEx?"

AI: [Explains in detail based on module content]

"Great question! VirtualAlloc allocates memory in the current process,
while VirtualAllocEx allows you to allocate memory in a remote process.
For process injection, we use VirtualAllocEx because..."

User: "I understand now, let's move to the next module"

AI: [Marks module 1 complete, loads module 2]

Module 1 completed!
Progress: 1/4 modules completed

[... continues through all modules ...]

AI: "You've completed all 4 modules! Ready to test your understanding
with a quiz? It has 10 questions and you need 70% to pass."

User: "sure"

AI: "Great! Let's begin:

QUIZ: Process Injection Fundamentals

Question 1 [BEGINNER]:
What is the primary purpose of process injection?

Options:
  0. Execute code in another process's memory space
  1. Terminate running processes
  2. Monitor network traffic
  3. Encrypt files on disk

[User answers all 10 questions]

AI: "Quiz complete! Let me grade your answers...

QUIZ RESULTS

PASSED! Score: 90% (9/10 correct)

Detailed Results:

Question 1:
   Your answer: 0
   Correct answer: 0
   Note: Correct! Process injection allows executing arbitrary code within
         the address space of a separate live process.

Question 5:
   Your answer: 3
   Correct answer: 1
   Note: Classic DLL injection is easily detected because the DLL file must
         exist on disk and will appear in the target process's loaded
         module list, making it trivial for EDR to identify.

[... continues with all answers ...]

NEW ACHIEVEMENTS UNLOCKED:
  • First Lesson Complete - You've completed your first technique!
  • Quiz Master - Scored 70% or higher on a quiz

Congratulations! You've mastered Process Injection Fundamentals.
Would you like a recommendation for what to learn next?"

User: "yes"

AI: "Based on your progress, I recommend:

RECOMMENDED NEXT LESSON

Recommended: Shellcode Injection Techniques
   Difficulty: INTERMEDIATE
   Time: 60 minutes

   Learn to inject raw shellcode instead of DLLs for fileless execution
   and advanced evasion.

To start: Would you like to begin Shellcode Injection?"
```

## Differences from Other Systems

### vs Intelligence/RAG System

| Feature | Education System | Intelligence System |
|---------|-----------------|-------------------|
| Content Source | Fixed JSON files | RAG (ChromaDB) |
| Consistency | 100% identical for all users | Dynamic, may vary |
| Purpose | Teaching fundamentals | Research & latest intel |
| Updates | Manual curation | Auto-indexed from sources |
| Quality Control | Pre-reviewed | Dependent on sources |
| Appropriate For | Learning basics | Advanced research |

### vs Traditional LMS

| Feature | Noctis Education | Traditional LMS |
|---------|-----------------|-----------------|
| Interface | IDE chat (natural language) | Web UI with buttons |
| Teaching Method | AI tutor (adaptive) | Fixed video/text |
| Integration | Native in coding environment | Separate platform |
| Interactivity | Real-time Q&A | Comment sections |
| Practice | In IDE with real tools | Separate sandbox |

## Extensibility

### Adding New Techniques

1. **Create lesson content** in `data/lessons.json`:
```json
{
  "id": "new_technique",
  "title": "New Technique Title",
  "category": "Evasion",
  "difficulty": "intermediate",
  "estimated_minutes": 60,
  "prerequisites": ["process_injection"],
  "description": "...",
  "modules": [ ... ]
}
```

2. **Create quiz questions** in `data/quizzes.json`:
```json
{
  "new_technique": {
    "technique_title": "New Technique Title",
    "total_questions": 10,
    "passing_score": 70,
    "questions": [ ... ]
  }
}
```

3. **Restart server** - no code changes needed!

### Adding Achievement Types

Modify `server/education/learning_engine.py`:

```python
def check_and_award_achievements(self, technique_id: str, progress: UserProgress):
    achievements = []

    # Add new achievement logic
    if progress.quiz_score == 100:
        achievements.append(self.earn_achievement(Achievement(
            id="perfect_score",
            name="Perfect Score!",
            description="Achieved 100% on a quiz",
            icon="🎯"
        )))

    return achievements
```

## Security Considerations

1. **No User Authentication**: This is a local development tool
2. **SQLite Security**: Database stored locally, no network access
3. **Content Safety**: All lesson content is pre-reviewed
4. **Quiz Integrity**: Correct answers not exposed to client
5. **Progress Tampering**: Local database can be modified (acceptable for learning tool)

## Performance

- **Lesson Loading**: < 50ms (JSON parsing)
- **Progress Queries**: < 10ms (SQLite indexed queries)
- **Quiz Grading**: < 5ms (in-memory comparison)
- **API Response**: < 100ms (total round-trip)

## Future Enhancements

Potential additions (not currently implemented):

1. **Adaptive Difficulty**: Adjust content based on quiz performance
2. **Spaced Repetition**: Review quizzes at optimal intervals
3. **Code Challenges**: Validate written code against test cases
4. **Peer Comparison**: Anonymous leaderboards
5. **Certification**: Export completion certificates
6. **Multi-Language**: Lessons in multiple languages
7. **Video Supplements**: Embedded tutorial videos
8. **Community Contributions**: User-submitted techniques

## Troubleshooting

### "No topics available"
- Check `data/lessons.json` exists and is valid JSON
- Verify file permissions
- Check server logs for parsing errors

### "Quiz not found"
- Ensure technique ID matches in both lessons.json and quizzes.json
- Check server logs for quiz loading errors

### Progress not saving
- Check SQLite database path in config
- Verify write permissions on data directory
- Check for SQLite connection errors in logs

### Recommendations not working
- Verify prerequisite chains in lessons.json
- Check that progress is being marked as completed
- Ensure technique IDs match exactly

## Monitoring

### Check System Health

```bash
# View education stats
curl http://localhost:8888/api/v2/education/stats

# Returns:
{
  "curriculum": {
    "total_techniques": 10,
    "by_difficulty": {"beginner": 2, "intermediate": 4, "advanced": 4},
    "by_category": {"Code Injection": 3, "Evasion": 4, ...}
  },
  "progress": {
    "completed_techniques": 3,
    "in_progress_techniques": 2,
    "total_time_minutes": 145,
    "achievements_earned": 5
  }
}
```

### Database Queries

```sql
-- View all progress
SELECT * FROM user_progress;

-- View quiz history
SELECT * FROM quiz_attempts ORDER BY timestamp DESC LIMIT 10;

-- View achievements
SELECT * FROM achievements;
```

## Credits

- **System Design**: Claude (Anthropic)
- **Lesson Content**: Curated from open-source security research
- **Architecture**: MCP-based agentic AI system
- **Framework**: Flask + FastMCP + SQLite
