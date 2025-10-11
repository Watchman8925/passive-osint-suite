# OSINT Suite Enhancements Guide

## Overview

This guide documents the new enhancements made to the Passive OSINT Suite to improve user experience, functionality, and autonomous investigation capabilities.

## 🚀 New Features

### 1. Quick Installation Script

**File:** `quick_install.sh`

A simplified one-command installation script that automatically detects your environment and installs the suite with minimal user interaction.

**Features:**
- Auto-detects Docker availability
- Generates secure keys automatically
- Starts all services with a single command
- Works on Linux, macOS, and Windows (WSL)

**Usage:**
```bash
./quick_install.sh
```

**What it does:**
1. Creates and configures `.env` file
2. Generates secure secret keys
3. Installs dependencies (or starts Docker containers)
4. Launches API server
5. Provides access URLs

---

### 2. Natural Language Command Interface

**File:** `core/nlp_command_parser.py`

A powerful NLP parser that converts plain English commands into OSINT module executions.

**Supported Command Patterns:**

| Command | Intent | Target Type | Modules Executed |
|---------|--------|-------------|------------------|
| `investigate example.com` | INVESTIGATE | DOMAIN | domain_recon, dns_intel, certificate_transparency |
| `search for breaches of user@example.com` | SEARCH | EMAIL | breach_search, email_intel |
| `analyze social media for john_doe` | ANALYZE | USERNAME | social_media_footprint |
| `find subdomains of example.com` | SEARCH | DOMAIN | subdomain_enum, dns_intel |
| `lookup whois for example.com` | LOOKUP | DOMAIN | domain_recon, whois_history |
| `check SSL certificates for example.com` | INVESTIGATE | DOMAIN | certificate_transparency |
| `scan IP address 8.8.8.8` | SCAN | IP | ip_intel, network_analysis |
| `search github for username johndoe` | SEARCH | GITHUB | github_search |
| `investigate company Acme Corp` | INVESTIGATE | COMPANY | company_intel, financial_intel |

**API Endpoints:**

```bash
# Parse command (without execution)
POST /api/nlp/parse
{
  "command": "investigate example.com"
}

# Execute command
POST /api/nlp/execute
{
  "command": "investigate example.com",
  "investigation_id": "inv_123",  # optional
  "execute": true
}

# Get examples
GET /api/nlp/examples
```

**Python Usage:**
```python
from core.nlp_command_parser import NLPCommandParser

parser = NLPCommandParser()
result = parser.parse("investigate example.com")

print(f"Intent: {result.intent.value}")
print(f"Target: {result.target}")
print(f"Modules: {result.modules}")
print(f"Confidence: {result.confidence}")
```

---

### 3. Chat History Management

**File:** `core/chat_history_manager.py`

A complete chat history system with SQLite backend for storing and managing investigation conversations.

**Features:**
- Persistent conversation storage
- Investigation-linked chats
- Full-text message search
- Conversation export (JSON/Markdown)
- Statistics and analytics

**API Endpoints:**

```bash
# Create conversation
POST /api/chat/conversations
{
  "investigation_id": "inv_123",  # optional
  "title": "Example Investigation Chat"
}

# Add message
POST /api/chat/messages
{
  "conversation_id": "conv_20231011_123456",
  "role": "user",
  "content": "investigate example.com"
}

# Get conversation
GET /api/chat/conversations/{conversation_id}

# List conversations
GET /api/chat/conversations?investigation_id=inv_123&limit=50

# Search messages
GET /api/chat/search?query=example.com

# Export conversation
GET /api/chat/conversations/{conversation_id}/export?format=markdown

# Get statistics
GET /api/chat/stats
```

**Python Usage:**
```python
from core.chat_history_manager import ChatHistoryManager

manager = ChatHistoryManager()

# Create conversation
conv_id = manager.create_conversation(
    investigation_id='inv_123',
    title='Investigation Chat'
)

# Add messages
manager.add_message(conv_id, 'user', 'investigate example.com')
manager.add_message(conv_id, 'assistant', 'Starting investigation...')

# Get conversation
conversation = manager.get_conversation(conv_id)
print(f"Messages: {len(conversation.messages)}")

# Export
filepath = manager.export_conversation(conv_id, format='markdown')
```

---

### 4. Autopivoting and Autonomous Investigations

**File:** `core/ai_engine.py` (enhanced)

AI-powered autonomous investigation with automatic pivot detection and exploration.

**Features:**
- AI suggests high-value pivot points
- Automatic multi-level investigation expansion
- Confidence scoring for pivots
- Priority-based exploration
- Comprehensive investigation trees

**API Endpoints:**

```bash
# Get pivot suggestions
POST /api/autopivot/suggest
{
  "investigation_id": "inv_123",
  "max_pivots": 5
}

# Start autonomous investigation
POST /api/autopivot/autonomous
{
  "target": "example.com",
  "target_type": "domain",
  "max_depth": 3,
  "max_pivots_per_level": 3
}
```

**Response Example:**
```json
{
  "status": "completed",
  "investigation_tree": {
    "initial_target": "example.com",
    "total_targets_investigated": 12,
    "total_pivots": 8,
    "levels": [
      {
        "target": "example.com",
        "pivots": [
          {
            "target": "mail.example.com",
            "target_type": "domain",
            "reason": "Mail server subdomain identified",
            "confidence": 0.9,
            "priority": "high",
            "recommended_modules": ["domain_recon", "dns_intel"]
          }
        ]
      }
    ]
  }
}
```

**Python Usage:**
```python
from core.ai_engine import OSINTAIEngine

engine = OSINTAIEngine(
    api_key="your-key",
    enable_autopivot=True
)

# Get pivot suggestions
pivots = await engine.suggest_autopivots(
    investigation_data=investigation,
    max_pivots=5
)

# Execute autonomous investigation
result = await engine.execute_autonomous_investigation(
    initial_target="example.com",
    target_type="domain",
    max_depth=3,
    max_pivots_per_level=3
)
```

---

### 5. Comprehensive Module Testing

**File:** `test_all_modules.py`

Automated testing suite for all OSINT modules.

**Features:**
- Tests module imports
- Tests module instantiation
- Tests module methods
- Generates detailed reports
- Saves results to JSON

**Usage:**
```bash
# Run all module tests
python test_all_modules.py

# Output:
# ============================================================
#                 OSINT Suite - Module Test Suite
# ============================================================
#
# Test 1: Module Registry
# ✓ MODULE_REGISTRY loaded with 38 modules
#
# Test 2: Module Imports
# ✓ domain_recon (DomainRecon)
# ✓ email_intel (EmailIntel)
# ...
#
# Test 3: Module Instantiation
# ✓ domain_recon instantiated
# ✓ domain_recon has methods: search, analyze
# ...
#
# ============================================================
#                    Test Results Summary
# ============================================================
# Total Modules Tested: 38
# Passed: 35
# Failed: 3
# Success Rate: 92.1%
```

**Report Output:**
```json
{
  "timestamp": "2023-10-11T22:49:14.459Z",
  "total_modules": 38,
  "passed": 35,
  "failed": 3,
  "success_rate": 92.1,
  "results": {
    "domain_recon": {
      "import": true,
      "instantiate": true,
      "methods": {
        "search": true,
        "analyze": true
      }
    }
  }
}
```

---

### 6. React Chat Interface Component

**File:** `web/src/components/chat/ChatInterface.tsx`

A modern, responsive chat interface for the web UI with natural language command support.

**Features:**
- Real-time message display
- Natural language command input
- Auto-saves conversations
- Export conversations
- Markdown support
- Loading indicators
- Error handling

**Usage in React:**
```tsx
import { ChatInterface } from './components/chat/ChatInterface';

function App() {
  return (
    <div className="h-screen">
      <ChatInterface
        investigationId="inv_123"
        apiUrl="http://localhost:8000"
        onClose={() => console.log('Chat closed')}
      />
    </div>
  );
}
```

---

## 🔧 Configuration

### Environment Variables

Add these to your `.env` file:

```bash
# Chat History Storage
CHAT_HISTORY_PATH=./chat_history

# Autopivot Configuration
ENABLE_AUTOPIVOT=true
MAX_AUTOPIVOT_DEPTH=3
MAX_PIVOTS_PER_LEVEL=3

# AI Configuration (for autopivoting)
OPENAI_API_KEY=your_openai_key
AI_MODEL=gpt-4
AI_PROVIDER=openai  # or anthropic, perplexity
```

---

## 📊 Usage Examples

### Example 1: Natural Language Investigation

```bash
# Start investigation with natural language
curl -X POST http://localhost:8000/api/nlp/execute \
  -H "Content-Type: application/json" \
  -d '{
    "command": "investigate example.com and find all subdomains",
    "execute": true
  }'

# Response:
{
  "status": "executed",
  "parsed": {
    "intent": "investigate",
    "target": "example.com",
    "modules": ["domain_recon", "subdomain_enum"]
  },
  "results": {
    "domain_recon": {...},
    "subdomain_enum": {...}
  }
}
```

### Example 2: Autonomous Investigation

```bash
# Start autonomous investigation
curl -X POST http://localhost:8000/api/autopivot/autonomous \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "target_type": "domain",
    "max_depth": 2,
    "max_pivots_per_level": 3
  }'

# The system will automatically:
# 1. Investigate example.com
# 2. Find related entities (subdomains, IPs, emails)
# 3. Investigate those entities
# 4. Continue until max_depth reached
```

### Example 3: Chat-Based Investigation

```python
import requests

API_URL = "http://localhost:8000"

# Create conversation
conv = requests.post(f"{API_URL}/api/chat/conversations", json={
    "title": "My Investigation"
}).json()

conv_id = conv["conversation_id"]

# Send commands via chat
commands = [
    "investigate example.com",
    "find email breaches for admin@example.com",
    "search for social media profiles"
]

for cmd in commands:
    # Add user message
    requests.post(f"{API_URL}/api/chat/messages", json={
        "conversation_id": conv_id,
        "role": "user",
        "content": cmd
    })
    
    # Execute command
    result = requests.post(f"{API_URL}/api/nlp/execute", json={
        "command": cmd,
        "execute": True
    }).json()
    
    # Add assistant response
    requests.post(f"{API_URL}/api/chat/messages", json={
        "conversation_id": conv_id,
        "role": "assistant",
        "content": f"Executed: {result['status']}"
    })

# Export conversation
response = requests.get(
    f"{API_URL}/api/chat/conversations/{conv_id}/export?format=markdown"
)

with open("investigation_chat.md", "wb") as f:
    f.write(response.content)
```

---

## 🧪 Testing

### Test Natural Language Parser

```bash
# Test the NLP parser
python -c "
from core.nlp_command_parser import NLPCommandParser
parser = NLPCommandParser()
result = parser.parse('investigate example.com')
print(f'Intent: {result.intent.value}')
print(f'Target: {result.target}')
print(f'Modules: {result.modules}')
"
```

### Test Chat History

```bash
# Test chat history manager
python -c "
from core.chat_history_manager import ChatHistoryManager
manager = ChatHistoryManager()
conv_id = manager.create_conversation(title='Test')
manager.add_message(conv_id, 'user', 'test message')
stats = manager.get_stats()
print(f'Total conversations: {stats[\"total_conversations\"]}')
"
```

### Test All Modules

```bash
# Run comprehensive module tests
python test_all_modules.py

# Check the generated report
cat module_test_results_*.json | jq .
```

---

## 📈 Performance Considerations

### Chat History
- SQLite database stores all conversations
- Indexes on conversation_id and timestamp for fast queries
- Automatic pagination for large result sets
- Export functionality for archiving

### NLP Parser
- Pattern-based parsing (no external API calls)
- Confidence scoring for ambiguous commands
- Fallback to basic text extraction
- <100ms parsing time for typical commands

### Autopivoting
- Configurable depth and pivot limits
- Parallel execution where possible
- Caching of intermediate results
- Rate limiting to prevent API overload

---

## 🔒 Security

### API Authentication
All new endpoints support the existing authentication:
- JWT tokens
- Rate limiting
- RBAC integration

### Chat History
- Conversations linked to users/investigations
- No cross-user access
- Encrypted storage option available
- Audit trail integration

### NLP Commands
- Input validation
- Command parsing sandboxed
- No arbitrary code execution
- Module whitelist enforced

---

## 🐛 Troubleshooting

### Chat History Not Saving

```bash
# Check database
ls -lh chat_history/chat_history.db

# Test manually
python -c "
from core.chat_history_manager import ChatHistoryManager
manager = ChatHistoryManager()
print('Chat history initialized')
"
```

### NLP Commands Not Working

```bash
# Check API endpoint
curl http://localhost:8000/api/nlp/examples

# Test parser
python core/nlp_command_parser.py
```

### Autopivot Not Finding Pivots

```bash
# Check AI engine configuration
echo $OPENAI_API_KEY
echo $ENABLE_AUTOPIVOT

# Test AI engine
python -c "
from core.ai_engine import OSINTAIEngine
engine = OSINTAIEngine(
    api_key='your-key',
    enable_autopivot=True
)
print('AI engine initialized')
"
```

---

## 📝 Contributing

To add new NLP command patterns:

1. Edit `core/nlp_command_parser.py`
2. Add patterns to `target_patterns` dict
3. Add module mappings to `module_mapping` dict
4. Update `keyword_modules` dict
5. Test with `parser.parse("your new command")`

To add new chat features:

1. Extend `ChatHistoryManager` class
2. Add new API endpoints in `api/api_server.py`
3. Update React component in `web/src/components/chat/`

---

## 🚀 Future Enhancements

Planned improvements:
- [ ] Voice command support
- [ ] Multi-language NLP support
- [ ] Advanced autopivot strategies
- [ ] Chat history analytics dashboard
- [ ] Integration with external LLMs
- [ ] Collaborative investigation chats
- [ ] Real-time pivot suggestions
- [ ] Investigation playbook system

---

## 📞 Support

For questions or issues:
- Check the main [README.md](README.md)
- Review [USER_MANUAL.md](USER_MANUAL.md)
- See API documentation at http://localhost:8000/docs
- File issues on GitHub

---

**Version:** 2.1.0  
**Last Updated:** October 2025  
**Author:** OSINT Suite Development Team
