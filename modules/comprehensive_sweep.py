"""
Comprehensive Investigation Sweep Module
========================================

Orchestrates all passive investigation modules for complete intelligence gathering.
Runs systematic sweeps across all available passive intelligence sources to provide
comprehensive leads and investigation pivots while maintaining strict OPSEC.

This module serves as the "master orchestrator" that:
- Runs all passive modules in coordinated sequence
- Aggregates and cross-references findings
- Identifies investigation leads and pivot points
- Maintains OPSEC through passive-only techniques
- Provides comprehensive reporting and analysis
"""

import asyncio
import json
import logging
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Any, Optional

from utils.osint_utils import OSINTUtils


class ComprehensiveInvestigationSweep(OSINTUtils):
    """
    Master orchestrator for comprehensive passive intelligence gathering.
    Runs all available passive modules systematically while maintaining OPSEC.
    """

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)

        # Define the core passive investigation modules to sweep
        self.core_modules = {
            'domain': [
                'certificate_transparency',
                'domain_recon',
                'whois_history',
                'dns_intelligence'
            ],
            'network': [
                'ip_intel',
                'passive_dns_enum',
                'network_analysis'
            ],
            'web': [
                'web_scraper',
                'wayback_machine',
                'search_engine_dorking',
                'web_discovery'
            ],
            'code': [
                'github_search',
                'code_analysis'
            ],
            'breach': [
                'public_breach_search',
                'paste_site_monitor'
            ],
            'social': [
                'social_media_footprint'
            ],
            'email': [
                'email_intel'
            ],
            'business': [
                'company_intel'
            ],
            'financial': [
                'financial_intel'
            ],
            'forensics': [
                'digital_forensics'
            ],
            'security': [
                'pattern_matching'
            ]
        }

        # OPSEC-safe modules (no active scanning)
        self.opsec_safe_modules = [
            'certificate_transparency', 'domain_recon', 'whois_history',
            'ip_intel', 'passive_dns_enum', 'web_scraper', 'wayback_machine',
            'search_engine_dorking', 'github_search', 'public_breach_search',
            'paste_site_monitor', 'social_media_footprint', 'email_intel',
            'company_intel', 'financial_intel', 'dns_intelligence',
            'web_discovery', 'code_analysis', 'network_analysis',
            'digital_forensics', 'pattern_matching'
        ]

    def comprehensive_sweep(self, target: str, target_type: str = "domain",
                          max_concurrent: int = 3, timeout: int = 300) -> Dict[str, Any]:
        """
        Perform comprehensive passive intelligence sweep across all modules.

        Args:
            target: Target to investigate (domain, IP, email, etc.)
            target_type: Type of target ('domain', 'ip', 'email', 'company', etc.)
            max_concurrent: Maximum concurrent module executions
            timeout: Overall timeout in seconds

        Returns:
            Comprehensive investigation results
        """
        self.logger.info(f"Starting comprehensive investigation sweep for: {target} ({target_type})")

        start_time = time.time()
        results = {
            'target': target,
            'target_type': target_type,
            'timestamp': datetime.now().isoformat(),
            'sweep_id': f"sweep_{int(start_time)}",
            'modules_executed': [],
            'findings': defaultdict(list),
            'leads': [],
            'pivot_points': [],
            'cross_references': [],
            'risk_assessment': {},
            'opsec_status': 'maintained',
            'execution_stats': {}
        }

        # Determine which modules to run based on target type
        modules_to_run = self._select_modules_for_target(target_type)

        self.logger.info(f"Selected {len(modules_to_run)} modules for {target_type} investigation")

        # Execute modules with controlled concurrency
        module_results = self._execute_modules_concurrent(
            modules_to_run, target, target_type, max_concurrent, timeout
        )

        # Process and aggregate results
        results['modules_executed'] = list(module_results.keys())
        results['execution_stats'] = self._calculate_execution_stats(module_results, start_time)

        # Extract findings and leads
        findings, leads, pivots = self._process_module_results(module_results, target, target_type)
        results['findings'] = findings
        results['leads'] = leads
        results['pivot_points'] = pivots

        # Cross-reference findings
        results['cross_references'] = self._cross_reference_findings(findings)

        # Risk assessment
        results['risk_assessment'] = self._assess_investigation_risks(results)

        # Final OPSEC check
        results['opsec_status'] = self._verify_opsec_compliance(results)

        total_time = time.time() - start_time
        results['execution_stats']['total_time'] = total_time

        self.logger.info(f"Comprehensive sweep completed in {total_time:.2f}s")
        return dict(results)  # Convert defaultdict to regular dict

    def _select_modules_for_target(self, target_type: str) -> List[str]:
        """Select appropriate modules based on target type."""
        if target_type == "domain":
            return self.core_modules['domain'] + self.core_modules['web'] + \
                   self.core_modules['breach'] + ['github_search', 'company_intel']
        elif target_type == "ip":
            return self.core_modules['network'] + ['ip_intel', 'passive_dns_enum']
        elif target_type == "email":
            return self.core_modules['email'] + self.core_modules['breach'] + \
                   self.core_modules['social'] + ['paste_site_monitor']
        elif target_type == "company":
            return self.core_modules['business'] + self.core_modules['web'] + \
                   self.core_modules['financial'] + ['social_media_footprint']
        elif target_type == "person":
            return self.core_modules['social'] + self.core_modules['breach'] + \
                   ['email_intel', 'financial_intel', 'github_search']
        else:
            # Generic sweep - run all OPSEC-safe modules
            return self.opsec_safe_modules

    def _execute_modules_concurrent(self, modules: List[str], target: str,
                                  target_type: str, max_concurrent: int,
                                  timeout: int) -> Dict[str, Any]:
        """Execute modules concurrently with proper error handling."""
        results = {}

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all module executions
            future_to_module = {}
            for module_name in modules:
                future = executor.submit(self._execute_single_module,
                                       module_name, target, target_type)
                future_to_module[future] = module_name

            # Collect results as they complete
            for future in as_completed(future_to_module, timeout=timeout):
                module_name = future_to_module[future]
                try:
                    result = future.result(timeout=30)  # Individual module timeout
                    results[module_name] = result
                    self.logger.debug(f"Module {module_name} completed successfully")
                except Exception as e:
                    self.logger.warning(f"Module {module_name} failed: {str(e)}")
                    results[module_name] = {
                        'success': False,
                        'error': str(e),
                        'module': module_name,
                        'timestamp': datetime.now().isoformat()
                    }

        return results

    def _execute_single_module(self, module_name: str, target: str, target_type: str) -> Dict[str, Any]:
        """Execute a single module with proper error handling."""
        try:
            # Import the module dynamically
            module = self._import_module(module_name)
            if not module:
                raise ImportError(f"Could not import module: {module_name}")

            # Instantiate the module
            instance = module()

            # Execute the analysis
            if hasattr(instance, 'analyze_target'):
                result = instance.analyze_target(target, target_type)
            elif hasattr(instance, 'run'):
                result = instance.run(target)
            else:
                raise AttributeError(f"Module {module_name} has no analysis method")

            return {
                'success': True,
                'module': module_name,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'success': False,
                'module': module_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def _import_module(self, module_name: str):
        """Dynamically import a module from the modules package."""
        try:
            # Import from modules package
            module = __import__(f'modules.{module_name}', fromlist=[module_name])

            # Get the class (usually PascalCase version of module name)
            class_name = self._module_name_to_class_name(module_name)

            # Try different class name variations
            for name in [class_name, f"{class_name}Intelligence", f"{class_name}Analyzer"]:
                if hasattr(module, name):
                    return getattr(module, name)

            # If no specific class found, return the module itself
            return module

        except ImportError:
            self.logger.warning(f"Could not import module: {module_name}")
            return None

    def _module_name_to_class_name(self, module_name: str) -> str:
        """Convert module name to class name (snake_case to PascalCase)."""
        return ''.join(word.capitalize() for word in module_name.split('_'))

    def _process_module_results(self, module_results: Dict[str, Any], target: str, target_type: str):
        """Process and aggregate results from all modules."""
        findings = defaultdict(list)
        leads = []
        pivots = []

        for module_name, result in module_results.items():
            if not result.get('success', False):
                continue

            module_data = result.get('result', {})

            # Categorize findings
            if isinstance(module_data, dict):
                for key, value in module_data.items():
                    if value:  # Only add non-empty results
                        findings[key].append({
                            'module': module_name,
                            'data': value,
                            'timestamp': result.get('timestamp')
                        })

            # Extract leads and pivot points
            leads.extend(self._extract_leads_from_result(module_name, module_data, target, target_type))
            pivots.extend(self._extract_pivots_from_result(module_name, module_data, target, target_type))

        return findings, leads, pivots

    def _extract_leads_from_result(self, module_name: str, result: Any, target: str, target_type: str) -> List[Dict]:
        """Extract investigation leads from module results."""
        leads = []

        if not isinstance(result, dict):
            return leads

        # Domain-related leads
        if 'subdomains' in result and result['subdomains']:
            for subdomain in result['subdomains'][:10]:  # Limit to top 10
                leads.append({
                    'type': 'subdomain',
                    'value': subdomain,
                    'source': module_name,
                    'confidence': 'high',
                    'description': f'Found subdomain: {subdomain}'
                })

        # Email-related leads
        if 'emails' in result and result['emails']:
            for email in result['emails'][:5]:  # Limit to top 5
                leads.append({
                    'type': 'email',
                    'value': email,
                    'source': module_name,
                    'confidence': 'medium',
                    'description': f'Found associated email: {email}'
                })

        # IP address leads
        if 'ip_addresses' in result and result['ip_addresses']:
            for ip in result['ip_addresses'][:5]:
                leads.append({
                    'type': 'ip_address',
                    'value': ip,
                    'source': module_name,
                    'confidence': 'high',
                    'description': f'Found associated IP: {ip}'
                })

        # Social media leads
        if 'social_profiles' in result and result['social_profiles']:
            for profile in result['social_profiles'][:3]:
                leads.append({
                    'type': 'social_profile',
                    'value': profile.get('url', profile.get('username', str(profile))),
                    'source': module_name,
                    'confidence': 'medium',
                    'description': f'Found social profile: {profile.get("platform", "unknown")}'
                })

        return leads

    def _extract_pivots_from_result(self, module_name: str, result: Any, target: str, target_type: str) -> List[Dict]:
        """Extract pivot points for further investigation."""
        pivots = []

        if not isinstance(result, dict):
            return pivots

        # Company-related pivots
        if 'company_info' in result and result['company_info']:
            company_data = result['company_info']
            if isinstance(company_data, dict):
                pivots.append({
                    'type': 'company_investigation',
                    'target': company_data.get('name', 'Unknown Company'),
                    'source': module_name,
                    'reason': 'Company association found',
                    'data': company_data
                })

        # Financial pivots
        if 'financial_records' in result and result['financial_records']:
            pivots.append({
                'type': 'financial_investigation',
                'target': target,
                'source': module_name,
                'reason': 'Financial records discovered',
                'data': result['financial_records']
            })

        # Breach data pivots
        if 'breach_data' in result and result['breach_data']:
            pivots.append({
                'type': 'breach_analysis',
                'target': target,
                'source': module_name,
                'reason': 'Breach data found',
                'data': result['breach_data']
            })

        # Code repository pivots
        if 'repositories' in result and result['repositories']:
            for repo in result['repositories'][:3]:
                pivots.append({
                    'type': 'code_analysis',
                    'target': repo.get('url', repo.get('name', str(repo))),
                    'source': module_name,
                    'reason': 'Code repository found',
                    'data': repo
                })

        return pivots

    def _cross_reference_findings(self, findings: Dict[str, List]) -> List[Dict]:
        """Cross-reference findings across modules for validation."""
        cross_references = []

        # Look for corroborating evidence
        emails = set()
        domains = set()
        ips = set()

        # Collect entities from findings
        for finding_type, finding_list in findings.items():
            for finding in finding_list:
                data = finding.get('data', {})

                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            # Try to extract entities from strings
                            if '@' in item and '.' in item:
                                emails.add(item)
                            elif self._is_ip_address(item):
                                ips.add(item)
                            elif self._is_domain(item):
                                domains.add(item)
                elif isinstance(data, dict):
                    # Extract from dict values
                    for key, value in data.items():
                        if isinstance(value, str):
                            if '@' in value and '.' in value:
                                emails.add(value)
                            elif self._is_ip_address(value):
                                ips.add(value)
                            elif self._is_domain(value):
                                domains.add(value)

        # Create cross-reference entries
        if len(emails) > 1:
            cross_references.append({
                'type': 'email_correlation',
                'entities': list(emails),
                'confidence': 'high',
                'description': f'Multiple emails found across {len(emails)} sources'
            })

        if len(domains) > 1:
            cross_references.append({
                'type': 'domain_correlation',
                'entities': list(domains),
                'confidence': 'high',
                'description': f'Multiple domains found across {len(domains)} sources'
            })

        if len(ips) > 1:
            cross_references.append({
                'type': 'ip_correlation',
                'entities': list(ips),
                'confidence': 'high',
                'description': f'Multiple IPs found across {len(ips)} sources'
            })

        return cross_references

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address."""
        import re
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, text))

    def _is_domain(self, text: str) -> bool:
        """Check if text is a domain name."""
        import re
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, text)) and not self._is_ip_address(text)

    def _calculate_execution_stats(self, module_results: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Calculate execution statistics."""
        total_modules = len(module_results)
        successful_modules = sum(1 for r in module_results.values() if r.get('success', False))
        failed_modules = total_modules - successful_modules

        return {
            'total_modules': total_modules,
            'successful_modules': successful_modules,
            'failed_modules': failed_modules,
            'success_rate': successful_modules / total_modules if total_modules > 0 else 0,
            'start_time': start_time,
            'end_time': time.time()
        }

    def _assess_investigation_risks(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risks associated with the investigation."""
        risk_score = 0
        risk_factors = []

        # Check for sensitive data exposure
        findings = results.get('findings', {})
        if 'breach_data' in findings:
            risk_score += 2
            risk_factors.append('Breach data discovered')

        if 'financial_records' in findings:
            risk_score += 3
            risk_factors.append('Financial data found')

        if 'personal_info' in findings:
            risk_score += 2
            risk_factors.append('Personal information discovered')

        # Check module execution success
        stats = results.get('execution_stats', {})
        success_rate = stats.get('success_rate', 0)
        if success_rate < 0.5:
            risk_score += 1
            risk_factors.append('Low module success rate')

        # Determine risk level
        if risk_score >= 5:
            risk_level = 'high'
        elif risk_score >= 3:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendations': self._generate_risk_recommendations(risk_level)
        }

    def _generate_risk_recommendations(self, risk_level: str) -> List[str]:
        """Generate risk mitigation recommendations."""
        recommendations = [
            'Continue using only passive investigation techniques',
            'Avoid direct contact with discovered entities',
            'Document all findings with proper attribution'
        ]

        if risk_level == 'high':
            recommendations.extend([
                'Consider limiting scope of investigation',
                'Implement additional OPSEC measures',
                'Consult with legal experts before proceeding'
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                'Verify findings through multiple sources',
                'Maintain detailed investigation logs'
            ])

        return recommendations

    def _verify_opsec_compliance(self, results: Dict[str, Any]) -> str:
        """Verify OPSEC compliance of the investigation."""
        # Check if any non-passive modules were used
        executed_modules = results.get('modules_executed', [])

        non_passive_modules = [
            mod for mod in executed_modules
            if mod not in self.opsec_safe_modules
        ]

        if non_passive_modules:
            return f'opsec_violation: Non-passive modules used: {non_passive_modules}'

        # Check for risky findings
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment.get('risk_level') == 'high':
            return 'opsec_concern: High-risk findings discovered'

        return 'maintained'

    def generate_investigation_report(self, sweep_results: Dict[str, Any]) -> str:
        """Generate a comprehensive investigation report."""
        report = []
        report.append("# Comprehensive Investigation Report")
        report.append(f"**Target:** {sweep_results['target']} ({sweep_results['target_type']})")
        report.append(f"**Timestamp:** {sweep_results['timestamp']}")
        report.append(f"**Sweep ID:** {sweep_results['sweep_id']}")
        report.append("")

        # Execution Summary
        stats = sweep_results.get('execution_stats', {})
        report.append("## Execution Summary")
        report.append(f"- **Modules Executed:** {stats.get('total_modules', 0)}")
        report.append(f"- **Successful:** {stats.get('successful_modules', 0)}")
        report.append(f"- **Failed:** {stats.get('failed_modules', 0)}")
        report.append(f"- **Success Rate:** {stats.get('success_rate', 0):.1%}")
        report.append("")

        # Key Findings
        findings = sweep_results.get('findings', {})
        if findings:
            report.append("## Key Findings")
            for finding_type, finding_list in findings.items():
                if finding_list:
                    report.append(f"### {finding_type.replace('_', ' ').title()}")
                    for finding in finding_list[:5]:  # Limit to top 5 per type
                        module = finding.get('module', 'unknown')
                        report.append(f"- **{module}:** {str(finding.get('data', ''))[:100]}...")
                    report.append("")

        # Investigation Leads
        leads = sweep_results.get('leads', [])
        if leads:
            report.append("## Investigation Leads")
            for lead in leads[:10]:  # Top 10 leads
                report.append(f"- **{lead['type'].upper()}:** {lead['value']} ({lead['confidence']} confidence)")
                report.append(f"  *Source:* {lead['source']}")
                report.append(f"  *Description:* {lead['description']}")
            report.append("")

        # Pivot Points
        pivots = sweep_results.get('pivot_points', [])
        if pivots:
            report.append("## Pivot Points")
            for pivot in pivots:
                report.append(f"- **{pivot['type'].replace('_', ' ').title()}:** {pivot['target']}")
                report.append(f"  *Reason:* {pivot['reason']}")
                report.append(f"  *Source:* {pivot['source']}")
            report.append("")

        # Risk Assessment
        risk = sweep_results.get('risk_assessment', {})
        report.append("## Risk Assessment")
        report.append(f"- **Risk Level:** {risk.get('risk_level', 'unknown').upper()}")
        report.append(f"- **Risk Score:** {risk.get('risk_score', 0)}")
        if risk.get('risk_factors'):
            report.append("- **Risk Factors:**")
            for factor in risk['risk_factors']:
                report.append(f"  - {factor}")
        report.append("")

        # OPSEC Status
        opsec = sweep_results.get('opsec_status', 'unknown')
        report.append("## OPSEC Status")
        report.append(f"- **Status:** {opsec.upper()}")
        report.append("")

        return '\n'.join(report)