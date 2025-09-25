#!/usr/bin/env python3
"""
Cross Reference Engine Module
Advanced cross-referencing of intelligence data across multiple sources.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter
import re
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CrossReferenceEngine:
    """Advanced cross-reference engine for intelligence data"""

    def __init__(self):
        self.enabled = True

        # Entity types to cross-reference
        self.entity_types = {
            'person': ['name', 'alias', 'person', 'individual'],
            'organization': ['company', 'organization', 'org', 'business', 'corporation'],
            'location': ['address', 'city', 'country', 'location', 'place'],
            'email': ['email', 'e-mail'],
            'phone': ['phone', 'telephone', 'mobile', 'cell'],
            'domain': ['domain', 'website', 'url', 'site'],
            'ip': ['ip', 'ip_address', 'ipv4', 'ipv6'],
            'social': ['username', 'handle', 'profile', 'account']
        }

        # Relationship types
        self.relationship_types = [
            'associated_with', 'connected_to', 'related_to', 'linked_to',
            'works_for', 'located_at', 'owns', 'controls'
        ]

        logger.info("CrossReferenceEngine initialized with entity linking")

    def cross_reference(self, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Cross-reference multiple intelligence sources"""
        try:
            if not sources:
                return {"matches": [], "confidence": 0.0, "entity_count": 0}

            # Extract entities from all sources
            all_entities = []
            for i, source in enumerate(sources):
                entities = self._extract_entities(source)
                for entity in entities:
                    entity['source_index'] = i
                    entity['source_id'] = source.get('id', f'source_{i}')
                all_entities.extend(entities)

            # Find matches between entities
            matches = self._find_entity_matches(all_entities)

            # Calculate confidence scores
            confidence = self._calculate_confidence(matches, len(sources))

            # Build relationship network
            relationships = self._build_relationships(matches, sources)

            return {
                "matches": matches,
                "confidence": confidence,
                "entity_count": len(all_entities),
                "unique_entities": len(set(e['value'].lower() for e in all_entities)),
                "relationships": relationships,
                "network_density": self._calculate_network_density(relationships, len(all_entities))
            }

        except Exception as e:
            logger.error(f"Failed to cross-reference sources: {e}")
            return {"matches": [], "confidence": 0.0, "entity_count": 0, "error": str(e)}

    def _extract_entities(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract entities from a single source"""
        entities = []

        # Extract from structured fields
        for entity_type, field_names in self.entity_types.items():
            for field_name in field_names:
                if field_name in source:
                    value = source[field_name]
                    if isinstance(value, str) and value.strip():
                        entities.append({
                            'type': entity_type,
                            'field': field_name,
                            'value': value.strip(),
                            'confidence': 0.9  # High confidence for structured data
                        })
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item.strip():
                                entities.append({
                                    'type': entity_type,
                                    'field': field_name,
                                    'value': item.strip(),
                                    'confidence': 0.9
                                })

        # Extract from unstructured text
        text_entities = self._extract_from_text(source)
        entities.extend(text_entities)

        return entities

    def _extract_from_text(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract entities from unstructured text content"""
        entities = []

        # Get all text content
        text_content = self._get_text_content(source)
        if not text_content:
            return entities

        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text_content)
        for email in emails:
            entities.append({
                'type': 'email',
                'field': 'extracted',
                'value': email,
                'confidence': 0.8
            })

        # Extract phone numbers (basic pattern)
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        phones = re.findall(phone_pattern, text_content)
        for phone in phones:
            entities.append({
                'type': 'phone',
                'field': 'extracted',
                'value': phone,
                'confidence': 0.7
            })

        # Extract domains/URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text_content)
        for url in urls:
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                if domain:
                    entities.append({
                        'type': 'domain',
                        'field': 'extracted',
                        'value': domain,
                        'confidence': 0.8
                    })
            except:
                pass

        # Extract potential person names (basic - capitalized words)
        words = re.findall(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', text_content)
        for name in words[:5]:  # Limit to avoid false positives
            entities.append({
                'type': 'person',
                'field': 'extracted',
                'value': name,
                'confidence': 0.5  # Lower confidence for extracted names
            })

        return entities

    def _get_text_content(self, source: Dict[str, Any]) -> str:
        """Extract text content from source"""
        text_parts = []

        for field in ['content', 'text', 'description', 'title', 'summary', 'body']:
            if field in source and source[field]:
                text_parts.append(str(source[field]))

        return ' '.join(text_parts)

    def _find_entity_matches(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find matches between entities across sources"""
        matches = []
        processed = set()

        for i, entity1 in enumerate(entities):
            for j, entity2 in enumerate(entities):
                if i >= j or (i, j) in processed:
                    continue

                # Check if entities match
                if self._entities_match(entity1, entity2):
                    match = {
                        'entity1': entity1,
                        'entity2': entity2,
                        'match_type': self._determine_match_type(entity1, entity2),
                        'confidence': self._calculate_match_confidence(entity1, entity2),
                        'sources': [entity1['source_index'], entity2['source_index']]
                    }
                    matches.append(match)
                    processed.add((i, j))

        return matches

    def _entities_match(self, entity1: Dict[str, Any], entity2: Dict[str, Any]) -> bool:
        """Check if two entities match"""
        # Must be same type
        if entity1['type'] != entity2['type']:
            return False

        # Exact match
        if entity1['value'].lower() == entity2['value'].lower():
            return True

        # Fuzzy matching for names and organizations
        if entity1['type'] in ['person', 'organization']:
            return self._fuzzy_name_match(entity1['value'], entity2['value'])

        # Email domain matching
        if entity1['type'] == 'email':
            domain1 = entity1['value'].split('@')[-1] if '@' in entity1['value'] else ''
            domain2 = entity2['value'].split('@')[-1] if '@' in entity2['value'] else ''
            return bool(domain1 and domain2 and domain1.lower() == domain2.lower())

        return False

    def _fuzzy_name_match(self, name1: str, name2: str) -> bool:
        """Fuzzy matching for names and organizations"""
        # Simple fuzzy match - could be enhanced with difflib or similar
        name1_lower = name1.lower()
        name2_lower = name2.lower()

        # Exact match after removing common suffixes
        suffixes = [' inc', ' llc', ' corp', ' ltd', ' co', ' company']
        for suffix in suffixes:
            name1_lower = name1_lower.replace(suffix, '')
            name2_lower = name2_lower.replace(suffix, '')

        # Check if one contains the other
        return name1_lower in name2_lower or name2_lower in name1_lower

    def _determine_match_type(self, entity1: Dict[str, Any], entity2: Dict[str, Any]) -> str:
        """Determine the type of match"""
        if entity1['value'].lower() == entity2['value'].lower():
            return 'exact'
        elif entity1['type'] in ['person', 'organization']:
            return 'fuzzy_name'
        elif entity1['type'] == 'email':
            return 'domain'
        else:
            return 'partial'

    def _calculate_match_confidence(self, entity1: Dict[str, Any], entity2: Dict[str, Any]) -> float:
        """Calculate confidence score for entity match"""
        base_confidence = min(entity1.get('confidence', 0.5), entity2.get('confidence', 0.5))

        # Boost confidence for exact matches
        if entity1['value'].lower() == entity2['value'].lower():
            base_confidence *= 1.2

        # Boost confidence for structured data matches
        if entity1.get('field') != 'extracted' and entity2.get('field') != 'extracted':
            base_confidence *= 1.1

        return min(1.0, base_confidence)

    def _calculate_confidence(self, matches: List[Dict[str, Any]], source_count: int) -> float:
        """Calculate overall confidence score for cross-referencing"""
        if not matches:
            return 0.0

        # Average confidence of all matches
        avg_match_confidence = sum(m['confidence'] for m in matches) / len(matches)

        # Factor in coverage (how many sources are connected)
        connected_sources = set()
        for match in matches:
            connected_sources.update(match['sources'])

        coverage_ratio = len(connected_sources) / source_count

        # Combined score
        return min(1.0, (avg_match_confidence * 0.7) + (coverage_ratio * 0.3))

    def _build_relationships(self, matches: List[Dict[str, Any]], sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build relationship network from matches"""
        relationships = []

        # Group matches by entity pairs
        entity_relationships = defaultdict(list)

        for match in matches:
            entity_pair = tuple(sorted([
                f"{match['entity1']['type']}:{match['entity1']['value']}",
                f"{match['entity2']['type']}:{match['entity2']['value']}"
            ]))
            entity_relationships[entity_pair].append(match)

        # Create relationship objects
        for entity_pair, match_list in entity_relationships.items():
            entity1_type, entity1_value = entity_pair[0].split(':', 1)
            entity2_type, entity2_value = entity_pair[1].split(':', 1)

            # Determine relationship type
            rel_type = self._infer_relationship_type(entity1_type, entity2_type, match_list)

            relationships.append({
                'entity1': {'type': entity1_type, 'value': entity1_value},
                'entity2': {'type': entity2_type, 'value': entity2_value},
                'relationship_type': rel_type,
                'strength': len(match_list),
                'confidence': sum(m['confidence'] for m in match_list) / len(match_list),
                'sources': list(set(s for m in match_list for s in m['sources']))
            })

        return relationships

    def _infer_relationship_type(self, type1: str, type2: str, matches: List[Dict[str, Any]]) -> str:
        """Infer relationship type from entity types and match context"""
        # Same type relationships
        if type1 == type2:
            return 'associated_with'

        # Person-Organization relationships
        if {type1, type2} == {'person', 'organization'}:
            return 'works_for'

        # Person-Location relationships
        if {type1, type2} == {'person', 'location'}:
            return 'located_at'

        # Organization-Location relationships
        if {type1, type2} == {'organization', 'location'}:
            return 'located_at'

        # Default relationship
        return 'connected_to'

    def _calculate_network_density(self, relationships: List[Dict[str, Any]], entity_count: int) -> float:
        """Calculate network density (connections vs possible connections)"""
        if entity_count <= 1:
            return 0.0

        max_possible_connections = entity_count * (entity_count - 1) / 2
        actual_connections = len(relationships)

        return actual_connections / max_possible_connections if max_possible_connections > 0 else 0.0

    def find_connections(self, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find connections between entities"""
        try:
            if not entities:
                return {"connections": [], "network_density": 0.0}

            # Find matches between provided entities
            matches = self._find_entity_matches(entities)

            # Build relationship network
            relationships = self._build_relationships(matches, [])

            # Find clusters/networks
            clusters = self._find_clusters(entities, relationships)

            return {
                "connections": relationships,
                "network_density": self._calculate_network_density(relationships, len(entities)),
                "clusters": clusters,
                "central_entities": self._find_central_entities(relationships),
                "isolation_score": self._calculate_isolation_score(entities, relationships)
            }

        except Exception as e:
            logger.error(f"Failed to find connections: {e}")
            return {"connections": [], "network_density": 0.0, "error": str(e)}

    def _find_clusters(self, entities: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[List[str]]:
        """Find connected clusters in the entity network"""
        # Simple clustering algorithm
        clusters = []
        visited = set()

        entity_ids = [f"{e['type']}:{e['value']}" for e in entities]

        for entity_id in entity_ids:
            if entity_id in visited:
                continue

            # Start new cluster
            cluster = []
            queue = [entity_id]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue

                visited.add(current)
                cluster.append(current)

                # Find connected entities
                for rel in relationships:
                    entity1_id = f"{rel['entity1']['type']}:{rel['entity1']['value']}"
                    entity2_id = f"{rel['entity2']['type']}:{rel['entity2']['value']}"

                    if entity1_id == current and entity2_id not in visited:
                        queue.append(entity2_id)
                    elif entity2_id == current and entity1_id not in visited:
                        queue.append(entity1_id)

            if len(cluster) > 1:  # Only include clusters with multiple entities
                clusters.append(cluster)

        return clusters

    def _find_central_entities(self, relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find most central entities in the network"""
        entity_connections = defaultdict(int)

        for rel in relationships:
            entity1_id = f"{rel['entity1']['type']}:{rel['entity1']['value']}"
            entity2_id = f"{rel['entity2']['type']}:{rel['entity2']['value']}"

            entity_connections[entity1_id] += 1
            entity_connections[entity2_id] += 1

        # Sort by connection count
        sorted_entities = sorted(entity_connections.items(), key=lambda x: x[1], reverse=True)

        return [
            {"entity_id": entity_id, "connections": count}
            for entity_id, count in sorted_entities[:5]  # Top 5
        ]

    def _calculate_isolation_score(self, entities: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> float:
        """Calculate how isolated entities are from each other"""
        if not entities:
            return 1.0

        connected_entities = set()
        for rel in relationships:
            connected_entities.add(f"{rel['entity1']['type']}:{rel['entity1']['value']}")
            connected_entities.add(f"{rel['entity2']['type']}:{rel['entity2']['value']}")

        total_entities = len(entities)
        isolated_count = total_entities - len(connected_entities)

        return isolated_count / total_entities if total_entities > 0 else 1.0