# Elasticsearch Configuration and Index Mappings for OSINT Suite

# elasticsearch.yml configuration
cluster.name: osint-suite-cluster
node.name: osint-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 127.0.0.1
http.port: 9200

# Security (enable in production)
xpack.security.enabled: false
xpack.monitoring.enabled: true
xpack.graph.enabled: true
xpack.ml.enabled: true

# Memory settings
bootstrap.memory_lock: true

# Index settings for OSINT data
index.number_of_shards: 1
index.number_of_replicas: 0

# ============================================================================
# INDEX MAPPINGS
# ============================================================================

# Investigations Index
PUT /investigations
{
  "mappings": {
    "properties": {
      "id": { "type": "keyword" },
      "name": { "type": "text", "analyzer": "standard" },
      "description": { "type": "text", "analyzer": "standard" },
      "target_type": { "type": "keyword" },
      "target_value": { "type": "keyword" },
      "status": { "type": "keyword" },
      "priority": { "type": "keyword" },
      "created_by": { "type": "keyword" },
      "created_at": { "type": "date" },
      "updated_at": { "type": "date" },
      "completed_at": { "type": "date" },
      "progress_percentage": { "type": "integer" },
      "tags": { "type": "keyword" },
      "metadata": { "type": "object" }
    }
  },
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  }
}

# Domain Intelligence Index
PUT /domain_intelligence
{
  "mappings": {
    "properties": {
      "domain": { "type": "keyword" },
      "whois_data": { "type": "object" },
      "dns_records": { "type": "object" },
      "ssl_certificates": { "type": "object" },
      "subdomains": { "type": "keyword" },
      "technologies": { "type": "object" },
      "security_score": { "type": "integer" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# IP Intelligence Index
PUT /ip_intelligence
{
  "mappings": {
    "properties": {
      "ip_address": { "type": "ip" },
      "geolocation": {
        "type": "object",
        "properties": {
          "country": { "type": "keyword" },
          "city": { "type": "keyword" },
          "coordinates": { "type": "geo_point" }
        }
      },
      "asn_info": { "type": "object" },
      "threat_intelligence": { "type": "object" },
      "services": { "type": "object" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# Email Intelligence Index
PUT /email_intelligence
{
  "mappings": {
    "properties": {
      "email": { "type": "keyword" },
      "domain_part": { "type": "keyword" },
      "breaches": {
        "type": "nested",
        "properties": {
          "source": { "type": "keyword" },
          "date": { "type": "date" },
          "passwords": { "type": "keyword" }
        }
      },
      "social_profiles": { "type": "object" },
      "professional_info": { "type": "object" },
      "risk_score": { "type": "integer" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# Cryptocurrency Intelligence Index
PUT /crypto_intelligence
{
  "mappings": {
    "properties": {
      "address": { "type": "keyword" },
      "currency": { "type": "keyword" },
      "balance": { "type": "double" },
      "transaction_count": { "type": "integer" },
      "first_seen": { "type": "date" },
      "last_seen": { "type": "date" },
      "exchanges": { "type": "object" },
      "risk_score": { "type": "integer" },
      "patterns": { "type": "object" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# Flight Intelligence Index
PUT /flight_intelligence
{
  "mappings": {
    "properties": {
      "aircraft_registration": { "type": "keyword" },
      "icao_code": { "type": "keyword" },
      "aircraft_type": { "type": "keyword" },
      "owner_info": { "type": "object" },
      "flight_history": {
        "type": "nested",
        "properties": {
          "flight_number": { "type": "keyword" },
          "departure": { "type": "keyword" },
          "arrival": { "type": "keyword" },
          "date": { "type": "date" }
        }
      },
      "route_patterns": { "type": "object" },
      "risk_indicators": { "type": "object" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# Social Media Intelligence Index
PUT /social_media_intelligence
{
  "mappings": {
    "properties": {
      "platform": { "type": "keyword" },
      "username": { "type": "keyword" },
      "profile_url": { "type": "keyword" },
      "profile_data": { "type": "object" },
      "posts_data": {
        "type": "nested",
        "properties": {
          "content": { "type": "text", "analyzer": "standard" },
          "date": { "type": "date" },
          "engagement": { "type": "integer" }
        }
      },
      "connections": { "type": "object" },
      "risk_score": { "type": "integer" },
      "last_scanned": { "type": "date" },
      "created_at": { "type": "date" }
    }
  }
}

# Audit Log Index
PUT /audit_log
{
  "mappings": {
    "properties": {
      "user_id": { "type": "keyword" },
      "action": { "type": "keyword" },
      "resource_type": { "type": "keyword" },
      "resource_id": { "type": "keyword" },
      "details": { "type": "object" },
      "ip_address": { "type": "ip" },
      "user_agent": { "type": "text" },
      "timestamp": { "type": "date" }
    }
  },
  "settings": {
    "index.lifecycle.name": "audit_log_policy",
    "index.lifecycle.rollover_alias": "audit_log"
  }
}

# ============================================================================
# SEARCH TEMPLATES
# ============================================================================

# Investigation search template
PUT /_scripts/investigation_search
{
  "script": {
    "lang": "mustache",
    "source": {
      "query": {
        "bool": {
          "must": [
            {{#query}}
            {
              "multi_match": {
                "query": "{{query}}",
                "fields": ["name^3", "description^2", "target_value", "tags"]
              }
            },
            {{/query}}
            {{#status}}
            { "term": { "status": "{{status}}" } },
            {{/status}}
            {{#priority}}
            { "term": { "priority": "{{priority}}" } },
            {{/priority}}
            {{#date_from}}
            { "range": { "created_at": { "gte": "{{date_from}}" } } },
            {{/date_from}}
            {{#date_to}}
            { "range": { "created_at": { "lte": "{{date_to}}" } } },
            {{/date_to}}
          ]
        }
      },
      "sort": [
        { "created_at": { "order": "desc" } }
      ],
      "size": "{{size}}"
    }
  }
}

# Risk analysis search template
PUT /_scripts/risk_analysis
{
  "script": {
    "lang": "mustache",
    "source": {
      "query": {
        "bool": {
          "must": [
            { "range": { "risk_score": { "gte": "{{min_risk}}" } } }
          ],
          "should": [
            {{#entity_types}}
            { "term": { "target_type": "{{.}}" } },
            {{/entity_types}}
          ]
        }
      },
      "sort": [
        { "risk_score": { "order": "desc" } }
      ],
      "size": 100
    }
  }
}

# ============================================================================
# LIFECYCLE POLICIES
# ============================================================================

# Audit log lifecycle policy
PUT /_ilm/policy/audit_log_policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "50gb",
            "max_age": "30d"
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          }
        }
      },
      "cold": {
        "min_age": "90d",
        "actions": {
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "1y",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}

# Intelligence data lifecycle policy
PUT /_ilm/policy/intelligence_data_policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}