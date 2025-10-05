#!/usr/bin/env python3
"""
Standalone demo of improved MCP tool output formatting
"""

import textwrap
from typing import Dict

# Copy the formatting functions
def _format_error(error_msg: str) -> str:
    """Format error messages with clear visual structure"""
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " ❌ ERROR ".center(78) + "║",
        "╠" + "═" * 78 + "╣",
        "",
    ]
    
    wrapped = textwrap.wrap(str(error_msg), width=74)
    for line in wrapped:
        lines.append("║  " + line.ljust(76) + "║")
    
    lines.extend([
        "",
        "╚" + "═" * 78 + "╝",
        ""
    ])
    
    return "\n".join(lines)


def _format_search_results(data: Dict) -> str:
    """Format intelligence search results with enhanced spacing and structure"""
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " 🔍 INTELLIGENCE SEARCH RESULTS ".ljust(78) + "║",
        "╚" + "═" * 78 + "╝",
        ""
    ]
    
    results = data.get('results', [])
    total = data.get('total_results', 0)
    
    if total > 0:
        lines.append(f"✅ Found {total} intelligence source{'s' if total != 1 else ''}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
        
        for i, result in enumerate(results[:10], 1):
            source = result.get('source', 'unknown')
            title = result.get('title', 'No title')
            url = result.get('url', '')
            relevance = result.get('relevance_score', 0)
            content = result.get('content', '')
            
            source_emoji = {
                'knowledge_base': '📚',
                'github': '🐙', 
                'arxiv': '📄',
                'blog': '📝'
            }.get(source, '❓')
            
            lines.append(f"🔹 Result {i}/{min(len(results), 10)}")
            lines.append("")
            
            relevance_bar = '█' * int(relevance * 10) + '░' * (10 - int(relevance * 10))
            lines.append(f"   {source_emoji}  Source:     {source.upper()}")
            lines.append(f"   📊 Relevance:  {relevance:.2f}/1.0  [{relevance_bar}]")
            lines.append("")
            
            lines.append(f"   📝 Title:")
            for title_line in textwrap.wrap(title, width=70):
                lines.append(f"      {title_line}")
            lines.append("")
            
            if url:
                lines.append(f"   🔗 URL:")
                lines.append(f"      {url}")
                lines.append("")
            
            if content:
                lines.append(f"   📄 Preview:")
                preview = content[:300] + "..." if len(content) > 300 else content
                for content_line in textwrap.wrap(preview, width=70):
                    lines.append(f"      {content_line}")
                lines.append("")
            
            if i < min(len(results), 10):
                lines.append("─" * 80)
                lines.append("")
        
        lines.append("═" * 80)
    else:
        lines.append("❌ No intelligence sources found")
        lines.append("")
    
    lines.append("")
    return "\n".join(lines)


# Demo data and execution
print("\n")
print("╔" + "═"*78 + "╗")
print("║" + " MCP TOOL OUTPUT FORMATTING - BEFORE vs AFTER ".center(78) + "║")
print("╚" + "═"*78 + "╝")

print("\n\n" + "🔴 OLD FORMAT (cramped, hard to read):")
print("─" * 80)
print("""
🔍 === INTELLIGENCE SEARCH RESULTS ===

✅ Found 2 intelligence sources:

📋 [1] 🐙 GITHUB
 📊 Relevance: 0.92 [█████████ ]
 📝 Title: Advanced Process Injection with Direct Syscalls
 🔗 URL: https://github.com/example/syscall-injection
 📄 Content: This repository demonstrates advanced process injection techniques using direct system calls to bypass EDR hooks. The implementation includes NTDLL unhooking, Heaven's Gate for WoW64 processes, and custom syscall stubs generated at runtime...

📋 [2] 📄 ARXIV
 📊 Relevance: 0.87 [████████  ]
 📝 Title: Evasion Techniques Against Modern Endpoint Detection Systems
 🔗 URL: https://arxiv.org/abs/12345
 📄 Content: This paper presents a comprehensive analysis of evasion techniques effective against modern EDR solutions...
""")

print("\n\n" + "🟢 NEW FORMAT (clean, spaced, professional):")
print("─" * 80)

sample_data = {
    'results': [
        {
            'source': 'github',
            'title': 'Advanced Process Injection with Direct Syscalls',
            'url': 'https://github.com/example/syscall-injection',
            'relevance_score': 0.92,
            'content': 'This repository demonstrates advanced process injection techniques using direct system calls to bypass EDR hooks. The implementation includes NTDLL unhooking, Heaven\'s Gate for WoW64 processes, and custom syscall stubs generated at runtime. Tested against Windows Defender, CrowdStrike Falcon, and SentinelOne with high success rates.'
        },
        {
            'source': 'arxiv',
            'title': 'Evasion Techniques Against Modern Endpoint Detection Systems',
            'url': 'https://arxiv.org/abs/12345',
            'relevance_score': 0.87,
            'content': 'This paper presents a comprehensive analysis of evasion techniques effective against modern EDR solutions. We demonstrate that direct system calls, combined with API hashing and string encryption, can significantly reduce detection rates across multiple endpoint protection platforms.'
        }
    ],
    'total_results': 2
}

print(_format_search_results(sample_data))

print("\n\n" + "🔴 OLD ERROR FORMAT:")
print("─" * 80)
print("\n[ERROR] Failed to connect to Noctis API server at http://localhost:8888\n")

print("\n\n" + "🟢 NEW ERROR FORMAT:")
print("─" * 80)
print(_format_error("Failed to connect to Noctis API server at http://localhost:8888. Please ensure the server is running by executing: python server/noctis_server.py --port 8888"))

print("\n\n")
print("═" * 80)
print("KEY IMPROVEMENTS:")
print("═" * 80)
print("""
✨ Clean visual hierarchy with box borders
📏 Consistent spacing between sections
🎯 Clear section headers with emojis
📊 Visual progress bars for scores
🔍 Better text wrapping for readability
📦 Organized information grouping
⚡ Professional, modern appearance
🎨 Easy-to-scan layout structure
""")
