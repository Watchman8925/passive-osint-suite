# LLM and Autonomous Investigation - Comprehensive Guide

## Overview

This guide details the enhanced LLM capabilities and autonomous investigation features that address:
1. Robust offline LLM with no API keys required
2. Detailed analysis with user-friendly breakdowns
3. Progressive finding cataloging without data loss
4. Lead recommendations with explanations
5. Enhanced reporting capabilities

---

## 🤖 Offline LLM Engine

### What It Is

A robust local LLM system that runs entirely offline using transformer models. **No API keys required.**

### Supported Models

1. **microsoft/Phi-3-mini-4k-instruct** (Recommended)
   - 3.8B parameters
   - Best balance of speed and capability
   - Optimized for reasoning tasks

2. **TinyLlama/TinyLlama-1.1B-Chat-v1.0**
   - 1.1B parameters
   - Fastest, lowest memory
   - Good for basic analysis

3. **HuggingFaceH4/zephyr-7b-beta**
   - 7B parameters
   - Most capable
   - Requires more memory

### Features

✅ **No API costs** - Runs entirely locally  
✅ **Privacy-focused** - Data never leaves your system  
✅ **Detailed analysis** - Structured, comprehensive insights  
✅ **User-friendly output** - Plain English explanations  
✅ **Automatic fallback** - Uses rule-based analysis if model unavailable  

### API Usage

```bash
# Analyze investigation with offline LLM
curl -X POST http://localhost:8000/api/enhanced/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "inv_123",
    "focus": "comprehensive"
  }'
```

### Response Format

```json
{
  "investigation_id": "inv_123",
  "analysis": {
    "summary": "Investigation of example.com has yielded 45 findings...",
    "key_findings": [
      "5 subdomains discovered with public exposure",
      "2 email addresses found in breach databases",
      "Administrative interface accessible at admin.example.com"
    ],
    "recommended_actions": [
      {
        "priority": 1,
        "action": "Investigate admin interface exposure",
        "estimated_time": "5-15 minutes",
        "value": "high"
      }
    ],
    "confidence": 0.85,
    "entities_found": [
      {"type": "email", "value": "admin@example.com"},
      {"type": "domain", "value": "mail.example.com"}
    ],
    "risk_assessment": "Medium - Several exposures require attention",
    "investigation_leads": [
      {
        "target": "admin@example.com",
        "type": "email",
        "reason": "Administrative email may have elevated breach exposure",
        "priority": "high",
        "modules": ["email_intel", "breach_search"]
      }
    ]
  },
  "generated_at": "2025-10-11T23:00:00Z",
  "model_used": "Offline LLM (Phi-3)"
}
```

### Python Usage

```python
from core.offline_llm_engine import get_offline_llm_engine

# Get engine
engine = get_offline_llm_engine()

# Analyze investigation
analysis = engine.analyze_investigation_data(
    investigation_data={
        'id': 'inv_123',
        'name': 'Target Investigation',
        'targets': ['example.com'],
        'results': {
            'domain_recon': {...},
            'subdomain_enum': {...}
        }
    },
    focus='comprehensive'
)

print(f"Summary: {analysis.summary}")
print(f"Key Findings: {analysis.key_findings}")
print(f"Leads: {len(analysis.investigation_leads)}")
```

### Explaining Individual Findings

```python
# Get detailed explanation of a finding
finding = {
    'type': 'breach',
    'value': 'admin@example.com',
    'source': 'breach_search'
}

explanation = engine.explain_finding(finding)

print(f"What it is: {explanation['what_it_is']}")
print(f"Why it matters: {explanation['why_it_matters']}")
print(f"Next steps: {explanation['next_steps']}")
print(f"Risk indicators: {explanation['risk_indicators']}")
```

---

## 📊 Investigation Tracking System

### What It Is

A persistent SQLite-based system that catalogs ALL findings and builds progressively **without losing data**.

### Features

✅ **No data loss** - All findings stored permanently  
✅ **Progressive building** - Continuous accumulation of intelligence  
✅ **Relationship tracking** - Links between findings  
✅ **Lead management** - Track what to investigate next  
✅ **Timeline tracking** - When each discovery was made  
✅ **Export capabilities** - JSON and Markdown formats  

### Creating Investigation Tracking

```bash
# Create tracking for an investigation
curl -X POST "http://localhost:8000/api/investigation/tracking/create?investigation_id=inv_123&name=Target%20Investigation"
```

### Adding Findings

```bash
# Add a finding
curl -X POST http://localhost:8000/api/investigation/tracking/finding \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "inv_123",
    "finding_type": "email",
    "value": "admin@example.com",
    "source_module": "email_intel",
    "confidence": 0.95,
    "metadata": {
      "discovered_in": "WHOIS record",
      "breach_count": 2
    }
  }'
```

### Getting All Findings

```bash
# Get all findings
curl http://localhost:8000/api/investigation/tracking/inv_123/findings

# Filter by type
curl "http://localhost:8000/api/investigation/tracking/inv_123/findings?finding_type=email"
```

### Response

```json
{
  "investigation_id": "inv_123",
  "total_findings": 45,
  "findings": [
    {
      "id": "finding_20251011_230000_123456",
      "type": "email",
      "value": "admin@example.com",
      "source": "email_intel",
      "discovered_at": "2025-10-11T23:00:00Z",
      "confidence": 0.95,
      "status": "pending",
      "notes": ""
    }
  ]
}
```

### Investigation Leads

```bash
# Get all leads
curl http://localhost:8000/api/investigation/tracking/inv_123/leads

# Filter by status
curl "http://localhost:8000/api/investigation/tracking/inv_123/leads?status=pending"
```

### Lead Response

```json
{
  "investigation_id": "inv_123",
  "total_leads": 12,
  "leads": [
    {
      "id": "lead_20251011_230100_789012",
      "target": "mail.example.com",
      "type": "domain",
      "reason": "Subdomain hosting mail services may expose additional infrastructure",
      "priority": "high",
      "suggested_modules": ["domain_recon", "dns_intel", "port_scanner"],
      "status": "pending",
      "findings_count": 0,
      "estimated_value": "high"
    }
  ]
}
```

### Python Usage

```python
from core.investigation_tracker import get_investigation_tracker

tracker = get_investigation_tracker()

# Create investigation
tracker.create_investigation("inv_123", "Target Investigation")

# Add findings
finding_id = tracker.add_finding(
    investigation_id="inv_123",
    finding_type="email",
    value="admin@example.com",
    source_module="email_intel",
    confidence=0.95,
    metadata={"breach_count": 2}
)

# Add lead
lead_id = tracker.add_lead(
    investigation_id="inv_123",
    target="mail.example.com",
    target_type="domain",
    reason="Mail server subdomain identified",
    priority="high",
    suggested_modules=["domain_recon", "dns_intel"]
)

# Get summary
summary = tracker.get_investigation_summary("inv_123")
print(f"Total findings: {summary['total_findings']}")
print(f"Total leads: {summary['total_leads']}")

# Export
filepath = tracker.export_investigation("inv_123", format="markdown")
print(f"Exported to: {filepath}")
```

---

## 📋 User-Friendly Reporting

### What It Is

Enhanced reporting that breaks down findings into clear, understandable sections:

1. **What We Know** - Confirmed facts
2. **What We Think** - Analysis and patterns
3. **What We Can Find** - Investigation leads
4. **Why It Matters** - Significance explained

### Generating Reports

```bash
curl -X POST http://localhost:8000/api/reports/user-friendly \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "inv_123",
    "include_analysis": true,
    "include_leads": true
  }'
```

### Report Structure

```json
{
  "report_id": "report_20251011_230200",
  "investigation_id": "inv_123",
  "investigation_name": "Target Investigation",
  
  "executive_summary": {
    "text": "Investigation of example.com collected 45 data points across 5 categories...",
    "total_findings": 45,
    "total_leads": 12,
    "progress_percentage": 75.0
  },
  
  "what_we_know": {
    "infrastructure": {
      "title": "Infrastructure & Technical Assets",
      "description": "Domains, IPs, and technical infrastructure we identified",
      "items": [
        {
          "value": "mail.example.com",
          "source": "subdomain_enum",
          "confidence": 0.95,
          "explanation": "Additional web property that may host services",
          "verified": true
        }
      ]
    },
    "identities": {
      "title": "People & Identities",
      "items": [...]
    },
    "exposures": {
      "title": "Security Exposures",
      "items": [...]
    }
  },
  
  "what_we_think": {
    "patterns_detected": {
      "title": "Patterns We Detected",
      "items": [
        "Multiple subdomains identified (8), suggesting complex infrastructure",
        "All emails from same domain, indicating centralized organization"
      ]
    },
    "connections": {
      "title": "Connections We See",
      "items": [
        "5 findings have identified relationships"
      ]
    },
    "anomalies": {
      "title": "Unusual Findings",
      "items": [
        "2 findings have low confidence - require verification"
      ]
    }
  },
  
  "what_we_can_find": {
    "critical": {
      "title": "Critical Leads - Investigate Immediately",
      "count": 2,
      "leads": [
        {
          "target": "admin.example.com",
          "type": "domain",
          "reason": "Administrative interface detected",
          "why_it_matters": "Admin interfaces often have weaker security",
          "suggested_modules": ["domain_recon", "port_scanner"],
          "estimated_time": "10-20 minutes",
          "potential_findings": ["Administrative access", "User accounts", "System configuration"]
        }
      ]
    },
    "high_priority": {...},
    "other": {...}
  },
  
  "why_it_matters": {
    "overall": "This investigation provides insight into digital footprint and security posture...",
    "key_impacts": [
      {
        "category": "Security Risk",
        "explanation": "Breach exposure means credentials may be compromised",
        "action_needed": "Reset passwords and enable 2FA"
      }
    ],
    "potential_uses": [
      "Security assessment and vulnerability identification",
      "Threat intelligence and risk evaluation",
      "Digital footprint mapping"
    ]
  },
  
  "risk_assessment": {
    "level": "Medium",
    "score": 6,
    "color": "yellow",
    "factors": [
      "Found 2 breach exposure(s) - credentials may be compromised",
      "1 administrative interface found"
    ],
    "recommendation": "Action recommended - address findings within 1-2 weeks"
  },
  
  "recommendations": [
    {
      "priority": "critical",
      "action": "Review and update all exposed credentials immediately",
      "reason": "Breach data was discovered",
      "estimated_time": "30-60 minutes"
    }
  ],
  
  "timeline": [...],
  "statistics": {...}
}
```

### Python Usage

```python
from core.enhanced_reporting import EnhancedReportGenerator
from core.investigation_tracker import get_investigation_tracker

# Get findings and leads
tracker = get_investigation_tracker()
findings = tracker.get_all_findings("inv_123")
leads = tracker.get_all_leads("inv_123")

# Convert to dict format
findings_dict = [
    {
        'finding_type': f.finding_type,
        'value': f.value,
        'source_module': f.source_module,
        'confidence': f.confidence
    }
    for f in findings
]

# Generate report
generator = EnhancedReportGenerator()
report = generator.generate_user_friendly_report(
    investigation_data={'id': 'inv_123', 'name': 'Target'},
    findings=findings_dict,
    leads=[...],
    analysis={...}
)

print(f"Report ID: {report['report_id']}")
print(f"Summary: {report['executive_summary']['text']}")
print(f"Risk Level: {report['risk_assessment']['level']}")
```

---

## 🔄 Complete Workflow Example

### 1. Start Investigation with Tracking

```bash
# Create tracking
curl -X POST "http://localhost:8000/api/investigation/tracking/create?investigation_id=inv_example&name=Example%20Investigation"
```

### 2. Execute Modules and Add Findings

```bash
# Execute domain recon
curl -X POST http://localhost:8000/api/modules/execute \
  -d '{"module_name": "domain_recon", "parameters": {"target": "example.com"}}'

# Add findings from results
curl -X POST http://localhost:8000/api/investigation/tracking/finding \
  -d '{
    "investigation_id": "inv_example",
    "finding_type": "subdomain",
    "value": "mail.example.com",
    "source_module": "domain_recon",
    "confidence": 0.9
  }'
```

### 3. Get AI Analysis

```bash
# Get offline LLM analysis
curl -X POST http://localhost:8000/api/enhanced/analyze \
  -d '{"investigation_id": "inv_example", "focus": "comprehensive"}'
```

### 4. Get Investigation Leads

```bash
# Get pending leads
curl "http://localhost:8000/api/investigation/tracking/inv_example/leads?status=pending"
```

### 5. Generate User-Friendly Report

```bash
# Generate comprehensive report
curl -X POST http://localhost:8000/api/reports/user-friendly \
  -d '{
    "investigation_id": "inv_example",
    "include_analysis": true,
    "include_leads": true
  }'
```

### 6. Export Everything

```bash
# Export as Markdown
curl "http://localhost:8000/api/investigation/tracking/inv_example/export?format=markdown" \
  --output investigation_report.md
```

---

## 🎯 Key Improvements Summary

### 1. Module Testing
- Comprehensive test suite (`test_all_modules.py`)
- Automated testing of all 38+ modules
- JSON report generation
- Identifies missing dependencies

### 2. Robust LLM
- **No API keys required** - runs offline
- Multiple model support (Phi-3, TinyLlama, Zephyr)
- Automatic fallback to rule-based analysis
- Privacy-focused (data never leaves system)

### 3. Ease of Use
- Plain English explanations
- User-friendly report structure
- Clear "What/Why/How" breakdowns
- Prioritized action items

### 4. Detailed Analysis
- Structured findings categorization
- Pattern and anomaly detection
- Connection mapping
- Risk assessment
- Timeline tracking

### 5. Progressive Cataloging
- SQLite-based persistent storage
- No data loss - ever
- Builds progressively
- Relationship tracking
- Complete export capabilities

### 6. Lead Recommendations
- AI-powered lead suggestions
- Priority-based ordering
- Explanations for each lead
- Suggested modules for investigation
- Estimated time and value

### 7. Enhanced Reporting
- "What We Know" - Facts
- "What We Think" - Analysis
- "What We Can Find" - Leads
- "Why It Matters" - Significance
- Risk assessment
- Actionable recommendations

---

## 🔧 Configuration

### Environment Variables

```bash
# Offline LLM Configuration
OFFLINE_LLM_MODEL=microsoft/Phi-3-mini-4k-instruct
OFFLINE_LLM_DEVICE=cpu  # or cuda for GPU
OFFLINE_LLM_USE_CACHE=true

# Investigation Tracking
INVESTIGATION_DATA_PATH=./investigation_data
```

### Model Selection

Choose based on your needs:

| Model | Size | Speed | Memory | Best For |
|-------|------|-------|--------|----------|
| Phi-3 | 3.8B | Medium | 8GB | Balanced use |
| TinyLlama | 1.1B | Fast | 4GB | Quick analysis |
| Zephyr | 7B | Slow | 16GB | Deep analysis |

---

## 📞 Support & Troubleshooting

### LLM Not Loading

```bash
# Check transformers installation
pip install transformers torch

# Try fallback model
export OFFLINE_LLM_MODEL=TinyLlama/TinyLlama-1.1B-Chat-v1.0
```

### Module Test Failures

```bash
# Install missing dependencies
pip install dnspython

# Run test again
python test_all_modules.py
```

### Database Issues

```bash
# Check database
ls -lh investigation_data/investigation_tracker.db

# Reset if needed (WARNING: loses data)
rm -rf investigation_data/
```

---

## 📚 Additional Resources

- **Module Testing Guide**: See `test_all_modules.py` 
- **API Documentation**: http://localhost:8000/docs
- **Main Guide**: `ENHANCEMENTS_GUIDE.md`
- **Feature Showcase**: `FEATURE_SHOWCASE.md`

---

**Version:** 2.2.0  
**Last Updated:** October 2025  
**Status:** Production Ready
