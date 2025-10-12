#!/usr/bin/env python3
"""
Offline LLM Engine for OSINT Analysis
Uses local models via Transformers - no API keys required
Optimized for OSINT investigation analysis and natural language understanding
"""

import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Structured analysis result from LLM"""
    summary: str
    key_findings: List[str]
    recommended_actions: List[Dict[str, Any]]
    confidence: float
    entities_found: List[Dict[str, str]]
    risk_assessment: str
    investigation_leads: List[Dict[str, Any]]
    timestamp: datetime


class OfflineLLMEngine:
    """
    Robust offline LLM engine for OSINT investigations.
    Uses local models that don't require API keys.
    
    Supported models (in order of recommendation):
    1. microsoft/Phi-3-mini-4k-instruct (3.8B parameters) - Best balance
    2. TinyLlama/TinyLlama-1.1B-Chat-v1.0 (1.1B) - Fastest, lower memory
    3. HuggingFaceH4/zephyr-7b-beta (7B) - Most capable, higher memory
    """
    
    def __init__(
        self,
        model_name: str = "microsoft/Phi-3-mini-4k-instruct",
        device: str = "cpu",
        use_cache: bool = True
    ):
        self.model_name = model_name
        self.device = device
        self.use_cache = use_cache
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        
        # Initialize on first use to avoid loading at import time
        self._initialized = False
        
        logger.info(f"Offline LLM Engine configured with model: {model_name}")
    
    def _initialize_model(self):
        """Lazy initialization of the model"""
        if self._initialized:
            return
        
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
            import torch
            
            logger.info(f"Loading model {self.model_name}...")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            # Load model with appropriate settings
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float32 if self.device == "cpu" else torch.float16,
                device_map="auto" if self.device != "cpu" else None,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            
            # Create pipeline for easier inference
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                max_new_tokens=512,
                do_sample=True,
                temperature=0.7,
                top_p=0.95,
                device=0 if self.device == "cuda" else -1
            )
            
            self._initialized = True
            logger.info(f"Model {self.model_name} loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")
            logger.warning("Falling back to rule-based analysis")
            self._initialized = False
    
    def analyze_investigation_data(
        self,
        investigation_data: Dict[str, Any],
        focus: str = "comprehensive"
    ) -> AnalysisResult:
        """
        Analyze investigation data and provide structured insights.
        
        Args:
            investigation_data: Complete investigation results
            focus: Analysis focus (comprehensive, threats, connections, timeline)
        """
        if not self._initialized:
            self._initialize_model()
        
        # Extract key information
        targets = investigation_data.get('targets', [])
        results = investigation_data.get('results', {})
        investigation_type = investigation_data.get('investigation_type', 'unknown')
        
        # Build analysis prompt
        prompt = self._build_analysis_prompt(targets, results, investigation_type, focus)
        
        # Generate analysis
        if self._initialized and self.pipeline:
            try:
                analysis_text = self._generate_with_model(prompt)
            except Exception as e:
                logger.error(f"Model generation failed: {e}")
                analysis_text = self._rule_based_analysis(investigation_data)
        else:
            analysis_text = self._rule_based_analysis(investigation_data)
        
        # Parse and structure the analysis
        return self._parse_analysis(analysis_text, investigation_data)
    
    def _build_analysis_prompt(
        self,
        targets: List[str],
        results: Dict[str, Any],
        investigation_type: str,
        focus: str
    ) -> str:
        """Build comprehensive analysis prompt"""
        
        # Summarize results
        result_summary = []
        for module, data in results.items():
            if isinstance(data, dict):
                count = len(data) if isinstance(data, dict) else 1
                result_summary.append(f"- {module}: {count} findings")
        
        results_text = "\n".join(result_summary) if result_summary else "No results yet"
        
        prompt = f"""You are an expert OSINT analyst. Analyze the following investigation:

Investigation Type: {investigation_type}
Targets: {', '.join(targets)}

Results Summary:
{results_text}

Provide a structured analysis including:
1. Executive Summary (2-3 sentences)
2. Key Findings (list 3-5 most important discoveries)
3. Recommended Next Steps (prioritized actions)
4. Risk Assessment (low/medium/high with justification)
5. Investigation Leads (specific targets to pursue next and why)

Focus: {focus}

Analysis:"""
        
        return prompt
    
    def _generate_with_model(self, prompt: str) -> str:
        """Generate analysis using the loaded model"""
        if not self.pipeline:
            raise RuntimeError("Pipeline not initialized")
        
        # Generate response
        outputs = self.pipeline(
            prompt,
            max_new_tokens=512,
            num_return_sequences=1,
            pad_token_id=self.tokenizer.eos_token_id
        )
        
        # Extract generated text
        generated_text = outputs[0]['generated_text']
        
        # Remove the prompt from the output
        if prompt in generated_text:
            generated_text = generated_text.replace(prompt, "").strip()
        
        return generated_text
    
    def _rule_based_analysis(self, investigation_data: Dict[str, Any]) -> str:
        """Fallback rule-based analysis when model is unavailable"""
        
        targets = investigation_data.get('targets', [])
        results = investigation_data.get('results', {})
        
        # Count findings
        total_findings = sum(
            len(data) if isinstance(data, (list, dict)) else 1
            for data in results.values()
        )
        
        # Detect entities
        entities = self._extract_entities(results)
        
        # Generate structured analysis
        analysis = f"""
**Executive Summary:**
Investigation of {', '.join(targets)} has yielded {total_findings} findings across {len(results)} modules.

**Key Findings:**
- Total data points collected: {total_findings}
- Unique entities identified: {len(entities)}
- Modules executed: {', '.join(results.keys())}

**Recommended Next Steps:**
1. Deep-dive analysis on identified entities
2. Cross-reference findings across modules
3. Investigate high-priority connections

**Risk Assessment:**
Medium - Further analysis recommended based on initial findings.

**Investigation Leads:**
{self._format_leads(entities)}
"""
        return analysis
    
    def _extract_entities(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract entities from results"""
        entities = []
        
        # Common patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        result_str = json.dumps(results)
        
        # Find emails
        for email in re.findall(email_pattern, result_str):
            entities.append({'type': 'email', 'value': email})
        
        # Find domains
        for domain in re.findall(domain_pattern, result_str):
            if '@' not in domain:  # Exclude email domains
                entities.append({'type': 'domain', 'value': domain})
        
        # Find IPs
        for ip in re.findall(ip_pattern, result_str):
            entities.append({'type': 'ip', 'value': ip})
        
        # Deduplicate
        seen = set()
        unique_entities = []
        for entity in entities:
            key = f"{entity['type']}:{entity['value']}"
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)
        
        return unique_entities[:20]  # Limit to top 20
    
    def _format_leads(self, entities: List[Dict[str, str]]) -> str:
        """Format investigation leads"""
        if not entities:
            return "- No specific leads identified yet"
        
        leads = []
        for entity in entities[:5]:
            entity_type = entity['type']
            value = entity['value']
            
            if entity_type == 'email':
                leads.append(f"- Email: {value} - Check breach databases and social profiles")
            elif entity_type == 'domain':
                leads.append(f"- Domain: {value} - Enumerate subdomains and check DNS records")
            elif entity_type == 'ip':
                leads.append(f"- IP: {value} - Scan ports and check geolocation")
        
        return '\n'.join(leads)
    
    def _parse_analysis(
        self,
        analysis_text: str,
        investigation_data: Dict[str, Any]
    ) -> AnalysisResult:
        """Parse analysis text into structured result"""
        
        # Extract sections
        summary = self._extract_section(analysis_text, ['executive summary', 'summary'])
        findings = self._extract_list_section(analysis_text, ['key findings', 'findings'])
        actions = self._extract_list_section(analysis_text, ['next steps', 'recommended', 'actions'])
        risk = self._extract_section(analysis_text, ['risk assessment', 'risk'])
        
        # Extract entities
        entities = self._extract_entities(investigation_data.get('results', {}))
        
        # Create investigation leads
        leads = []
        for entity in entities[:10]:
            lead = {
                'target': entity['value'],
                'type': entity['type'],
                'reason': self._generate_lead_reason(entity),
                'priority': 'high' if entity['type'] == 'email' else 'medium',
                'modules': self._suggest_modules_for_entity(entity['type'])
            }
            leads.append(lead)
        
        # Format recommended actions
        formatted_actions = []
        for i, action in enumerate(actions[:5], 1):
            formatted_actions.append({
                'priority': i,
                'action': action,
                'estimated_time': '5-15 minutes',
                'value': 'high' if i <= 2 else 'medium'
            })
        
        # Determine confidence
        confidence = 0.85 if self._initialized else 0.70
        
        return AnalysisResult(
            summary=summary or "Analysis complete - review findings below",
            key_findings=findings[:10],
            recommended_actions=formatted_actions,
            confidence=confidence,
            entities_found=entities[:20],
            risk_assessment=risk or "Medium - requires further investigation",
            investigation_leads=leads,
            timestamp=datetime.now()
        )
    
    def _extract_section(self, text: str, keywords: List[str]) -> str:
        """Extract a text section based on keywords"""
        text_lower = text.lower()
        
        for keyword in keywords:
            if keyword in text_lower:
                # Find the section
                start_idx = text_lower.find(keyword)
                # Find the next section or end
                next_section_idx = len(text)
                for other_keyword in ['key findings', 'recommended', 'risk', 'investigation leads']:
                    if other_keyword != keyword:
                        idx = text_lower.find(other_keyword, start_idx + len(keyword))
                        if idx != -1 and idx < next_section_idx:
                            next_section_idx = idx
                
                section = text[start_idx:next_section_idx].strip()
                # Remove the header
                lines = section.split('\n')
                return '\n'.join(lines[1:]).strip()
        
        return ""
    
    def _extract_list_section(self, text: str, keywords: List[str]) -> List[str]:
        """Extract a list section based on keywords"""
        section_text = self._extract_section(text, keywords)
        if not section_text:
            return []
        
        # Extract list items (lines starting with -, *, or numbers)
        items = []
        for line in section_text.split('\n'):
            line = line.strip()
            if line and (line.startswith('-') or line.startswith('*') or 
                        (len(line) > 2 and line[0].isdigit() and line[1] in '.)')):
                # Remove list markers
                item = re.sub(r'^[-*\d.)\s]+', '', line).strip()
                if item:
                    items.append(item)
        
        return items
    
    def _generate_lead_reason(self, entity: Dict[str, str]) -> str:
        """Generate reason for investigating a lead"""
        entity_type = entity['type']
        
        reasons = {
            'email': 'Email addresses can reveal breach exposure, social profiles, and associated accounts',
            'domain': 'Domains may expose infrastructure, subdomains, and organizational relationships',
            'ip': 'IP addresses can show geolocation, hosting provider, and network infrastructure',
            'phone': 'Phone numbers may link to individuals, businesses, and geographic locations',
            'username': 'Usernames often reused across platforms, enabling cross-platform tracking'
        }
        
        return reasons.get(entity_type, 'Entity may provide valuable intelligence connections')
    
    def _suggest_modules_for_entity(self, entity_type: str) -> List[str]:
        """Suggest OSINT modules for entity type"""
        module_map = {
            'email': ['email_intel', 'breach_search', 'social_media_footprint'],
            'domain': ['domain_recon', 'dns_intel', 'subdomain_enum', 'certificate_transparency'],
            'ip': ['ip_intel', 'network_analysis', 'geospatial_intel'],
            'phone': ['phone_intel', 'geospatial_intel'],
            'username': ['social_media_footprint', 'github_search']
        }
        
        return module_map.get(entity_type, ['domain_recon'])
    
    def explain_finding(
        self,
        finding: Dict[str, Any],
        context: str = ""
    ) -> Dict[str, Any]:
        """
        Explain a specific finding in user-friendly terms.
        
        Args:
            finding: The finding to explain
            context: Additional context about the investigation
            
        Returns:
            Detailed explanation with significance and next steps
        """
        explanation = {
            'what_it_is': self._describe_finding(finding),
            'why_it_matters': self._explain_significance(finding),
            'confidence': self._assess_finding_confidence(finding),
            'related_findings': [],
            'next_steps': self._suggest_next_steps_for_finding(finding),
            'risk_indicators': self._identify_risk_indicators(finding)
        }
        
        return explanation
    
    def _describe_finding(self, finding: Dict[str, Any]) -> str:
        """Describe what the finding is in simple terms"""
        finding_type = finding.get('type', 'unknown')
        value = finding.get('value', '')
        
        descriptions = {
            'email': f"Email address '{value}' discovered in investigation",
            'domain': f"Domain '{value}' identified in target infrastructure",
            'ip': f"IP address '{value}' connected to target",
            'subdomain': f"Subdomain '{value}' part of target's web presence",
            'breach': f"Data breach exposure detected for '{value}'",
            'social_profile': f"Social media profile found for '{value}'"
        }
        
        return descriptions.get(finding_type, f"Finding of type '{finding_type}' identified")
    
    def _explain_significance(self, finding: Dict[str, Any]) -> str:
        """Explain why the finding matters"""
        finding_type = finding.get('type', 'unknown')
        
        significance = {
            'email': "Email addresses can reveal breach exposure, enable social engineering, and connect to other accounts",
            'domain': "Domains show organizational infrastructure and may reveal additional attack surfaces",
            'ip': "IP addresses indicate hosting locations and can expose related services",
            'subdomain': "Subdomains often host critical services and may have weaker security",
            'breach': "Breach data can include passwords, personal info, and security questions",
            'social_profile': "Social profiles reveal personal information, connections, and behavior patterns"
        }
        
        return significance.get(finding_type, "This finding may provide additional investigation leads")
    
    def _assess_finding_confidence(self, finding: Dict[str, Any]) -> str:
        """Assess confidence in the finding"""
        # In a real implementation, this would use more sophisticated logic
        source = finding.get('source', 'unknown')
        verified = finding.get('verified', False)
        
        if verified:
            return "High - Verified from multiple sources"
        elif source in ['official_db', 'breach_db']:
            return "High - From authoritative source"
        elif source in ['dns', 'whois']:
            return "Medium-High - From DNS records"
        else:
            return "Medium - Requires verification"
    
    def _suggest_next_steps_for_finding(self, finding: Dict[str, Any]) -> List[str]:
        """Suggest next investigative steps"""
        finding_type = finding.get('type', 'unknown')
        
        next_steps_map = {
            'email': [
                "Check breach databases for password exposure",
                "Search social media platforms for associated profiles",
                "Look for other accounts using same email pattern"
            ],
            'domain': [
                "Enumerate all subdomains",
                "Check DNS records for additional IPs",
                "Search for SSL certificates"
            ],
            'ip': [
                "Scan for open ports and services",
                "Check geolocation and hosting provider",
                "Look for other domains hosted on same IP"
            ]
        }
        
        return next_steps_map.get(finding_type, ["Investigate further using related modules"])
    
    def _identify_risk_indicators(self, finding: Dict[str, Any]) -> List[str]:
        """Identify potential risk indicators"""
        risks = []
        
        if finding.get('type') == 'breach':
            risks.append("PASSWORD_EXPOSURE")
        
        if finding.get('type') == 'subdomain' and 'admin' in finding.get('value', ''):
            risks.append("ADMIN_INTERFACE_EXPOSED")
        
        if finding.get('open_ports'):
            risks.append("EXPOSED_SERVICES")
        
        return risks if risks else ["NO_IMMEDIATE_RISKS"]


# Singleton instance
_engine_instance = None


def get_offline_llm_engine() -> OfflineLLMEngine:
    """Get or create singleton instance of offline LLM engine"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = OfflineLLMEngine()
    return _engine_instance
