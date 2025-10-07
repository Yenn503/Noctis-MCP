"""
Intelligence Processor - Converts RAG search results into structured, actionable guidance

Processes results from 4 sources:
- Knowledge files: Strategic OPSEC guidance (WHY)
- Blogs: Current detection status (WHAT'S DETECTED NOW)
- GitHub: Real-world implementation patterns (HOW)
- VX-API: Function signatures (BUILDING BLOCKS)

Returns structured intelligence that AI agents can use to generate code.
"""

import re
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class IntelligenceProcessor:
    """Processes RAG results into structured guidance for AI code generation"""

    def __init__(self):
        # Detection keywords
        self.detection_keywords = [
            'detected', 'detection', 'caught', 'flagged', 'blocked',
            'suspicious', 'alert', 'signature', 'hooked', 'monitored'
        ]

        # Positive recommendation keywords
        self.positive_keywords = [
            'bypass', 'evade', 'undetected', 'works', 'successful',
            'recommended', 'better', 'use instead', 'alternative', 'effective'
        ]

        # Pattern indicators for GitHub code
        self.pattern_indicators = [
            'HANDLE', 'DWORD', 'LPVOID', 'BOOL', 'typedef',
            'VirtualAlloc', 'CreateThread', 'WriteProcessMemory'
        ]

    def process_intelligence(
        self,
        rag_results: List[Dict],
        query: str,
        target_av: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Process raw RAG results into structured intelligence

        Args:
            rag_results: Raw results from RAG search
            query: Original search query
            target_av: Target AV/EDR if specified

        Returns:
            Structured intelligence with recommendations, patterns, warnings
        """
        if not rag_results:
            return self._empty_intelligence()

        # Categorize by source
        knowledge = [r for r in rag_results if r.get('source') == 'knowledge_base']
        github = [r for r in rag_results if r.get('source') == 'github']
        vx_api = [r for r in rag_results if r.get('source') == 'vx_api']
        blogs = [r for r in rag_results if r.get('source') in ['blog', 'security_blogs']]

        logger.info(f"Processing intelligence: {len(knowledge)} knowledge, {len(github)} github, "
                   f"{len(vx_api)} vx_api, {len(blogs)} blog results")

        # Process each source type differently
        strategic_guidance = self._process_knowledge(knowledge, target_av)
        current_detections = self._process_blogs(blogs, target_av)
        implementation_patterns = self._process_github(github)
        function_signatures = self._process_vx_api(vx_api)

        # Synthesize into actionable intelligence
        recommendations = self._synthesize_recommendations(
            strategic_guidance, current_detections, implementation_patterns, target_av
        )
        warnings = self._extract_warnings(strategic_guidance + current_detections, target_av)
        opsec_analysis = self._generate_opsec_analysis(recommendations, warnings, target_av)
        summary = self._generate_summary(recommendations, warnings, current_detections, target_av)

        return {
            "summary": summary,
            "recommendations": recommendations,
            "warnings": warnings,
            "detection_patterns": current_detections.get('patterns', []),
            "implementation_patterns": implementation_patterns,
            "function_signatures": function_signatures,
            "opsec_analysis": opsec_analysis,
            "sources_analyzed": {
                "knowledge_base": len(knowledge),
                "github_repos": len(github),
                "security_blogs": len(blogs),
                "vx_api": len(vx_api)
            }
        }

    def _process_knowledge(self, results: List[Dict], target_av: Optional[str]) -> List[Dict]:
        """Process knowledge files for strategic OPSEC guidance"""
        guidance = []

        for result in results:
            content = result.get('content', '')

            # Extract OPSEC scores
            opsec_match = re.search(r'OPSEC.*?(\d+)/10', content, re.IGNORECASE)
            opsec_score = int(opsec_match.group(1)) if opsec_match else None

            # Extract technique names (look for headers or capitalized terms)
            technique_matches = re.findall(r'##\s+(.+)', content)  # Markdown headers
            if not technique_matches:
                technique_matches = re.findall(r'\*\*(.+?)\*\*', content)  # Bold text

            # Extract key recommendations
            is_positive = any(kw in content.lower() for kw in self.positive_keywords)

            if technique_matches and (is_positive or opsec_score):
                technique = technique_matches[0].strip()

                # Extract WHY (look for sentences explaining advantages)
                why_sentences = []
                for sentence in content.split('.'):
                    if any(kw in sentence.lower() for kw in ['because', 'advantage', 'benefit', 'effective']):
                        why_sentences.append(sentence.strip())

                guidance.append({
                    'technique': technique,
                    'opsec_score': opsec_score,
                    'reasoning': ' '.join(why_sentences[:2])[:300] if why_sentences else content[:200],
                    'source': 'knowledge',
                    'av_specific': target_av and target_av.lower() in content.lower()
                })

        return guidance

    def _process_blogs(self, results: List[Dict], target_av: Optional[str]) -> Dict:
        """Process security blogs for CURRENT detection status"""
        detections = {'patterns': [], 'updates': [], 'bypasses': []}

        for result in results:
            content = result.get('content', '')
            title = result.get('title', '')

            # Look for version/date mentions (indicates recency)
            version_match = re.search(r'v?\d+\.\d+(?:\.\d+)?', content)
            date_match = re.search(r'20\d{2}[-/]\d{1,2}', content)

            # Categorize information
            if any(kw in content.lower() for kw in self.detection_keywords):
                # This is detection information
                sentences = content.split('.')
                for sentence in sentences:
                    if any(kw in sentence.lower() for kw in self.detection_keywords):
                        detection_info = {
                            'info': sentence.strip()[:250],
                            'recent': bool(version_match or date_match)
                        }
                        if target_av and target_av.lower() in sentence.lower():
                            detection_info['av_specific'] = True
                        detections['patterns'].append(detection_info)
                        break

            elif any(kw in content.lower() for kw in self.positive_keywords):
                # This is bypass information
                detections['bypasses'].append({
                    'title': title[:150],
                    'method': content[:300],
                    'recent': bool(version_match or date_match)
                })

            # Track security updates/changes
            if any(word in title.lower() for word in ['update', 'v7', 'v6', '2024', '2025']):
                detections['updates'].append({
                    'update': title[:150],
                    'details': content[:200]
                })

        return detections

    def _process_github(self, results: List[Dict]) -> List[Dict]:
        """Process GitHub repos for implementation PATTERNS (not raw code)"""
        patterns = []

        for result in results:
            content = result.get('content', '')
            title = result.get('title', '')

            # Check if this contains actual code
            has_code = any(indicator in content for indicator in self.pattern_indicators)

            if has_code:
                # Extract high-level pattern, NOT the actual code
                pattern = {
                    'name': title[:100] if title else 'Implementation Pattern',
                    'approach': self._extract_approach(content),
                    'key_functions': self._extract_key_functions(content),
                    'structure': self._extract_structure(content)
                }

                if pattern['approach'] or pattern['key_functions']:
                    patterns.append(pattern)

        return patterns[:5]  # Top 5 patterns

    def _extract_approach(self, content: str) -> str:
        """Extract high-level approach from code (not the code itself)"""
        approaches = []

        # Look for comment blocks that explain approach
        comment_blocks = re.findall(r'/\*\*?(.*?)\*/', content, re.DOTALL)
        for block in comment_blocks:
            clean = block.strip()
            if len(clean) > 50 and len(clean) < 300:
                approaches.append(clean)

        # Look for descriptive variable/function names that reveal approach
        if 'indirect' in content.lower() and 'syscall' in content.lower():
            approaches.append("Uses indirect syscall pattern")
        if 'heaven' in content.lower() or 'hell' in content.lower():
            approaches.append("Implements dynamic SSN resolution")
        if 'shellcode' in content.lower() and 'encrypt' in content.lower():
            approaches.append("Encrypts shellcode before injection")

        return ' | '.join(approaches[:2]) if approaches else ""

    def _extract_key_functions(self, content: str) -> List[str]:
        """Extract key function names used (not their implementations)"""
        functions = []

        # NT API functions
        nt_functions = re.findall(r'\b(Nt\w+)\s*\(', content)
        functions.extend(nt_functions[:5])

        # Zw API functions
        zw_functions = re.findall(r'\b(Zw\w+)\s*\(', content)
        functions.extend(zw_functions[:5])

        # Win32 API functions
        win32_functions = re.findall(r'\b(VirtualAlloc\w*|CreateThread\w*|WriteProcessMemory|LoadLibrary\w*)\s*\(', content)
        functions.extend(win32_functions[:5])

        return list(set(functions))[:10]  # Unique, max 10

    def _extract_structure(self, content: str) -> str:
        """Extract code structure pattern (not actual code)"""
        structure = []

        # Detect structure from function definitions
        if re.search(r'BOOL.*Init', content, re.IGNORECASE):
            structure.append("Initialization phase")
        if re.search(r'BOOL.*Inject', content, re.IGNORECASE):
            structure.append("Injection phase")
        if re.search(r'BOOL.*Execute', content, re.IGNORECASE):
            structure.append("Execution phase")
        if re.search(r'BOOL.*Clean', content, re.IGNORECASE):
            structure.append("Cleanup phase")

        return " → ".join(structure) if structure else "Modular implementation"

    def _process_vx_api(self, results: List[Dict]) -> List[Dict]:
        """Process VX-API results for function signatures"""
        signatures = []

        for result in results:
            content = result.get('content', '')
            title = result.get('title', '')

            # Extract function signature patterns
            # Look for function declarations
            func_patterns = [
                r'(NTSTATUS|BOOL|DWORD|HANDLE)\s+(\w+)\s*\([^)]+\)',
                r'typedef\s+\w+\s*\(\s*\w+\s*\*\s*(\w+)\s*\)\s*\([^)]+\)'
            ]

            for pattern in func_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    func_name = match[1] if isinstance(match, tuple) and len(match) > 1 else match
                    if func_name and len(func_name) > 2:
                        signatures.append({
                            'function': func_name,
                            'context': content[:200]  # Brief context
                        })

        return signatures[:15]  # Top 15 relevant functions

    def _synthesize_recommendations(
        self,
        strategic: List[Dict],
        current: Dict,
        patterns: List[Dict],
        target_av: Optional[str]
    ) -> List[Dict]:
        """Synthesize recommendations from all sources"""
        recommendations = []

        # Start with strategic guidance from knowledge
        for strat in strategic:
            rec = {
                'technique': strat['technique'],
                'opsec_score': strat.get('opsec_score', 7),
                'reason': strat['reasoning'],
                'source_strategic': True
            }

            # Check if recent blogs support/contradict this
            is_supported = False
            is_contradicted = False

            for bypass in current.get('bypasses', []):
                if strat['technique'].lower() in bypass.get('title', '').lower():
                    is_supported = True
                    if bypass.get('recent'):
                        rec['opsec_score'] = min(rec['opsec_score'] + 1, 10)

            for detection in current.get('patterns', []):
                if strat['technique'].lower() in detection.get('info', '').lower():
                    is_contradicted = True
                    if detection.get('recent'):
                        rec['opsec_score'] = max(rec['opsec_score'] - 2, 1)

            # Check if GitHub patterns show implementation
            has_pattern = any(strat['technique'].lower() in p.get('name', '').lower()
                            for p in patterns)
            if has_pattern:
                rec['has_implementation'] = True

            # Add context
            if is_contradicted:
                rec['note'] = "⚠ Recent blog posts indicate detection"
            elif is_supported:
                rec['note'] = "✓ Confirmed working in recent posts"

            if strat.get('av_specific'):
                rec['av_specific'] = True

            recommendations.append(rec)

        # Sort by OPSEC score
        recommendations.sort(key=lambda x: x['opsec_score'], reverse=True)
        return recommendations[:5]

    def _extract_warnings(self, results: List[Dict], target_av: Optional[str]) -> List[str]:
        """Extract warnings from strategic and current intelligence"""
        warnings = []

        for result in results:
            content = result.get('info', '') or result.get('reasoning', '')

            if any(kw in content.lower() for kw in self.detection_keywords):
                # Extract warning
                sentences = content.split('.')
                for sentence in sentences:
                    if any(kw in sentence.lower() for kw in self.detection_keywords):
                        warning = sentence.strip()
                        if len(warning) > 30:
                            # Make actionable
                            if not warning.lower().startswith(('avoid', 'do not', 'warning')):
                                warning = f"⚠ {warning}"
                            warnings.append(warning[:250])
                            break

        return list(set(warnings))[:5]

    def _generate_opsec_analysis(self, recommendations: List[Dict], warnings: List[str], target_av: Optional[str]) -> str:
        """Generate OPSEC analysis"""
        if not recommendations:
            return "Insufficient intelligence for OPSEC assessment."

        avg_opsec = sum(r['opsec_score'] for r in recommendations) / len(recommendations)

        parts = []

        if avg_opsec >= 8:
            parts.append("OPSEC: HIGH - Recommended techniques show strong evasion potential.")
        elif avg_opsec >= 6:
            parts.append("OPSEC: MEDIUM - Techniques viable with careful implementation.")
        else:
            parts.append("OPSEC: LOW - High detection risk, consider alternatives.")

        if target_av:
            av_specific = [r for r in recommendations if r.get('av_specific')]
            if av_specific:
                parts.append(f"{target_av}-specific recommendations available.")

        if warnings:
            parts.append(f"{len(warnings)} detection warnings identified.")

        return ' '.join(parts)

    def _generate_summary(
        self,
        recommendations: List[Dict],
        warnings: List[str],
        current: Dict,
        target_av: Optional[str]
    ) -> str:
        """Generate intelligence summary"""
        parts = []

        if recommendations:
            top = recommendations[0]
            parts.append(f"Top: {top['technique']} (OPSEC {top['opsec_score']}/10).")

        if current.get('updates'):
            parts.append(f"Found {len(current['updates'])} recent security updates.")

        if current.get('bypasses'):
            parts.append(f"{len(current['bypasses'])} working bypasses identified.")

        if warnings:
            parts.append(f"{len(warnings)} potential issues detected.")

        if target_av:
            parts.append(f"Analysis for {target_av}.")

        return ' '.join(parts) if parts else "Intelligence analysis complete."

    def _empty_intelligence(self) -> Dict[str, Any]:
        """Return empty intelligence structure"""
        return {
            "summary": "No intelligence found.",
            "recommendations": [],
            "warnings": [],
            "detection_patterns": [],
            "implementation_patterns": [],
            "function_signatures": [],
            "opsec_analysis": "Insufficient data.",
            "sources_analyzed": {"knowledge_base": 0, "github_repos": 0, "security_blogs": 0, "vx_api": 0}
        }
