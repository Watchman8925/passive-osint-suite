"""
Graph Database Adapter for Relationship Mapping
Advanced entity resolution and relationship analysis using Neo4j
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

try:
    from neo4j import AsyncDriver, AsyncGraphDatabase
    # from neo4j.exceptions import ServiceUnavailable  # Unused

    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    AsyncGraphDatabase = None
    AsyncDriver = None


logger = logging.getLogger(__name__)


@dataclass
class Entity:
    """Represents an entity in the graph database"""

    id: str
    type: str  # person, organization, domain, ip, email, etc.
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    labels: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class Relationship:
    """Represents a relationship between entities"""

    source_id: str
    target_id: str
    type: str  # owns, controls, communicates_with, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source: str = ""  # source of this relationship intelligence
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class GraphQuery:
    """Graph query with parameters"""

    query: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    return_type: str = "entities"  # entities, relationships, paths, stats


INSECURE_NEO4J_PASSWORDS = {
    "password",
    "neo4j",
    "change-this-default-password",
    "changeme",
    "",
}


class GraphDatabaseAdapter:
    """
    Neo4j adapter for advanced relationship mapping and entity resolution.
    Provides graph-based intelligence correlation and analysis.
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: Optional[str] = None,
    ):
        if password is None or password in INSECURE_NEO4J_PASSWORDS:
            raise ValueError(
                "A secure Neo4j password must be provided via the NEO4J_PASSWORD "
                "environment variable."
            )

        if not NEO4J_AVAILABLE:
            raise ImportError(
                "neo4j driver is required. Install with: pip install neo4j"
            )

        self.uri = uri
        self.user = user
        self.password = password
        self.driver: Optional[Any] = None
        self.connected = False

    async def connect(self) -> bool:
        """Establish connection to Neo4j database"""
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password)
            )
            # Test connection
            await self.driver.verify_connectivity()
            self.connected = True
            logger.info("Successfully connected to Neo4j database")

            # Initialize schema
            await self._initialize_schema()

            return True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self.connected = False
            return False

    async def disconnect(self):
        """Close database connection"""
        if self.driver:
            await self.driver.close()
            self.connected = False
            logger.info("Disconnected from Neo4j database")

    async def _initialize_schema(self):
        """Initialize database schema and constraints"""
        try:
            async with self.driver.session() as session:
                # Create constraints for entity uniqueness
                await session.run(
                    """
                    CREATE CONSTRAINT entity_id_unique IF NOT EXISTS
                    FOR (e:Entity) REQUIRE e.id IS UNIQUE
                """
                )

                # Create indexes for performance
                await session.run(
                    """
                    CREATE INDEX entity_type_idx IF NOT EXISTS
                    FOR (e:Entity) ON (e.type)
                """
                )

                await session.run(
                    """
                    CREATE INDEX entity_name_idx IF NOT EXISTS
                    FOR (e:Entity) ON (e.name)
                """
                )

                # Create relationship indexes
                await session.run(
                    """
                    CREATE INDEX relationship_type_idx IF NOT EXISTS
                    FOR ()-[r:RELATES_TO]-() ON (r.type)
                """
                )

                logger.info("Database schema initialized")

        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")

    async def create_entity(self, entity: Entity) -> bool:
        """Create or update an entity in the graph"""
        if not self.connected:
            return False

        try:
            async with self.driver.session() as session:
                # Convert sets to lists for JSON serialization
                labels_list = list(entity.labels) if entity.labels else []

                result = await session.run(
                    """
                    MERGE (e:Entity {id: $id})
                    ON CREATE SET
                        e.type = $type,
                        e.name = $name,
                        e.properties = $properties,
                        e.labels = $labels,
                        e.created_at = $created_at,
                        e.updated_at = $updated_at
                    ON MATCH SET
                        e.name = $name,
                        e.properties = $properties,
                        e.labels = $labels,
                        e.updated_at = $updated_at
                    RETURN e.id
                """,
                    {
                        "id": entity.id,
                        "type": entity.type,
                        "name": entity.name,
                        "properties": json.dumps(entity.properties),
                        "labels": labels_list,
                        "created_at": entity.created_at.isoformat(),
                        "updated_at": entity.updated_at.isoformat(),
                    },
                )

                record = await result.single()
                return record is not None

        except Exception as e:
            logger.error(f"Failed to create entity {entity.id}: {e}")
            return False

    async def create_relationship(self, relationship: Relationship) -> bool:
        """Create a relationship between entities"""
        if not self.connected:
            return False

        try:
            async with self.driver.session() as session:
                result = await session.run(
                    """
                    MATCH (source:Entity {id: $source_id})
                    MATCH (target:Entity {id: $target_id})
                    MERGE (source)-[r:RELATES_TO {type: $type}]->(target)
                    ON CREATE SET
                        r.properties = $properties,
                        r.confidence = $confidence,
                        r.source = $source,
                        r.created_at = $created_at
                    ON MATCH SET
                        r.properties = $properties,
                        r.confidence = CASE WHEN r.confidence < $confidence THEN $confidence ELSE r.confidence END,
                        r.source = CASE WHEN r.source = '' THEN $source ELSE r.source END
                    RETURN r
                """,
                    {
                        "source_id": relationship.source_id,
                        "target_id": relationship.target_id,
                        "type": relationship.type,
                        "properties": json.dumps(relationship.properties),
                        "confidence": relationship.confidence,
                        "source": relationship.source,
                        "created_at": relationship.created_at.isoformat(),
                    },
                )

                record = await result.single()
                return record is not None

        except Exception as e:
            logger.error(f"Failed to create relationship: {e}")
            return False

    async def find_entity_by_name(
        self, name: str, entity_type: Optional[str] = None
    ) -> Optional[Entity]:
        """Find an entity by name"""
        if not self.connected:
            return None

        try:
            async with self.driver.session() as session:
                if entity_type:
                    result = await session.run(
                        """
                        MATCH (e:Entity {name: $name, type: $type})
                        RETURN e
                    """,
                        {"name": name, "type": entity_type},
                    )
                else:
                    result = await session.run(
                        """
                        MATCH (e:Entity {name: $name})
                        RETURN e
                    """,
                        {"name": name},
                    )

                record = await result.single()
                if record:
                    entity_data = record["e"]
                    return Entity(
                        id=entity_data["id"],
                        type=entity_data["type"],
                        name=entity_data["name"],
                        properties=json.loads(entity_data.get("properties", "{}")),
                        labels=set(entity_data.get("labels", [])),
                        created_at=datetime.fromisoformat(entity_data["created_at"]),
                        updated_at=datetime.fromisoformat(entity_data["updated_at"]),
                    )

        except Exception as e:
            logger.error(f"Failed to find entity by name {name}: {e}")

        return None

    async def find_related_entities(
        self,
        entity_id: str,
        relationship_type: Optional[str] = None,
        max_depth: int = 2,
    ) -> List[Dict[str, Any]]:
        """Find entities related to the given entity"""
        if not self.connected:
            return []

        try:
            async with self.driver.session() as session:
                if relationship_type:
                    result = await session.run(
                        """
                        MATCH (source:Entity {id: $entity_id})-[r:RELATES_TO {type: $rel_type}]-(target:Entity)
                        RETURN target, r, 'direct' as connection_type
                    """,
                        {"entity_id": entity_id, "rel_type": relationship_type},
                    )
                else:
                    # Find direct and indirect relationships
                    result = await session.run(
                        """
                        MATCH path = (source:Entity {id: $entity_id})-[r:RELATES_TO*1..2]-(target:Entity)
                        WHERE source <> target
                        RETURN target, r, length(path) as depth
                        ORDER BY depth, r.confidence DESC
                        LIMIT 50
                    """,
                        {"entity_id": entity_id},
                    )

                related = []
                async for record in result:
                    target_data = record["target"]
                    relationship_data = record["r"]

                    related.append(
                        {
                            "entity": {
                                "id": target_data["id"],
                                "type": target_data["type"],
                                "name": target_data["name"],
                                "properties": json.loads(
                                    target_data.get("properties", "{}")
                                ),
                            },
                            "relationship": {
                                "type": relationship_data.get("type", "unknown"),
                                "confidence": relationship_data.get("confidence", 1.0),
                                "source": relationship_data.get("source", ""),
                                "properties": json.loads(
                                    relationship_data.get("properties", "{}")
                                ),
                            },
                            "depth": record.get("depth", 1),
                        }
                    )

                return related

        except Exception as e:
            logger.error(f"Failed to find related entities for {entity_id}: {e}")
            return []

    async def find_shortest_path(
        self, source_id: str, target_id: str
    ) -> Optional[List[Dict[str, Any]]]:
        """Find the shortest path between two entities"""
        if not self.connected:
            return None

        try:
            async with self.driver.session() as session:
                result = await session.run(
                    """
                    MATCH path = shortestPath(
                        (source:Entity {id: $source_id})-[*]-(target:Entity {id: $target_id})
                    )
                    RETURN path
                """,
                    {"source_id": source_id, "target_id": target_id},
                )

                record = await result.single()
                if record:
                    path = record["path"]
                    # Process path data (simplified)
                    return [
                        {
                            "nodes": len(path.nodes),
                            "relationships": len(path.relationships),
                            "path_data": str(path),  # Simplified representation
                        }
                    ]

        except Exception as e:
            logger.error(f"Failed to find shortest path: {e}")

        return None

    async def detect_communities(self) -> List[Dict[str, Any]]:
        """Detect communities/clusters in the graph"""
        if not self.connected:
            return []

        try:
            async with self.driver.session() as session:
                # Use Louvain community detection algorithm
                result = await session.run(
                    """
                    CALL gds.louvain.stream({
                        nodeProjection: 'Entity',
                        relationshipProjection: 'RELATES_TO'
                    })
                    YIELD nodeId, communityId, intermediateCommunityIds
                    RETURN communityId, count(*) as size
                    ORDER BY size DESC
                    LIMIT 20
                """
                )

                communities = []
                async for record in result:
                    communities.append(
                        {"community_id": record["communityId"], "size": record["size"]}
                    )

                return communities

        except Exception as e:
            logger.error(f"Failed to detect communities: {e}")
            return []

    async def calculate_centrality(
        self, entity_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Calculate centrality measures for entities"""
        if not self.connected:
            return []

        try:
            async with self.driver.session() as session:
                if entity_type:
                    result = await session.run(
                        """
                        CALL gds.degree.stream({
                            nodeProjection: 'Entity',
                            relationshipProjection: 'RELATES_TO',
                            nodeQuery: 'MATCH (n:Entity) WHERE n.type = $entity_type RETURN id(n) as id',
                            relationshipQuery: 'MATCH (n)-[r:RELATES_TO]-(m) RETURN id(n) as source, id(m) as target'
                        })
                        YIELD nodeId, score
                        RETURN nodeId, score
                        ORDER BY score DESC
                        LIMIT 50
                    """,
                        {"entity_type": entity_type},
                    )
                else:
                    result = await session.run(
                        """
                        CALL gds.degree.stream({
                            nodeProjection: 'Entity',
                            relationshipProjection: 'RELATES_TO'
                        })
                        YIELD nodeId, score
                        RETURN nodeId, score
                        ORDER BY score DESC
                        LIMIT 50
                    """
                    )

                centrality_scores = []
                async for record in result:
                    centrality_scores.append(
                        {
                            "node_id": record["nodeId"],
                            "centrality_score": record["score"],
                        }
                    )

                return centrality_scores

        except Exception as e:
            logger.error(f"Failed to calculate centrality: {e}")
            return []

    async def import_investigation_data(
        self, investigation_data: Dict[str, Any]
    ) -> Dict[str, int]:
        """Import investigation data into the graph database"""
        if not self.connected:
            return {"entities": 0, "relationships": 0}

        entities_created = 0
        relationships_created = 0

        try:
            # Extract entities from investigation data
            entities = self._extract_entities_from_investigation(investigation_data)
            relationships = self._extract_relationships_from_investigation(
                investigation_data, entities
            )

            # Create entities
            for entity in entities:
                if await self.create_entity(entity):
                    entities_created += 1

            # Create relationships
            for relationship in relationships:
                if await self.create_relationship(relationship):
                    relationships_created += 1

            logger.info(
                f"Imported {entities_created} entities and {relationships_created} relationships"
            )

        except Exception as e:
            logger.error(f"Failed to import investigation data: {e}")

        return {"entities": entities_created, "relationships": relationships_created}

    def _extract_entities_from_investigation(
        self, data: Dict[str, Any]
    ) -> List[Entity]:
        """Extract entities from investigation data"""
        entities = []

        # Extract domain entities
        if "domain_data" in data:
            domain_info = data["domain_data"]
            if "domain" in domain_info:
                entities.append(
                    Entity(
                        id=f"domain_{domain_info['domain']}",
                        type="domain",
                        name=domain_info["domain"],
                        properties={
                            "registrar": domain_info.get("registrar", ""),
                            "creation_date": domain_info.get("creation_date", ""),
                            "subdomains": domain_info.get("subdomains_found", 0),
                        },
                        labels={"domain", "investigation_target"},
                    )
                )

        # Extract IP entities
        if "ip_data" in data:
            ip_info = data["ip_data"]
            if "ips" in ip_info:
                for ip in ip_info["ips"]:
                    entities.append(
                        Entity(
                            id=f"ip_{ip}",
                            type="ip_address",
                            name=ip,
                            properties={
                                "geolocation": ip_info.get("geolocation", {}),
                                "blacklisted": ip in ip_info.get("blacklisted_ips", []),
                            },
                            labels={"ip", "network"},
                        )
                    )

        # Extract email entities
        if "email_data" in data:
            email_info = data["email_data"]
            if "emails" in email_info:
                for email in email_info["emails"]:
                    entities.append(
                        Entity(
                            id=f"email_{email}",
                            type="email",
                            name=email,
                            properties={
                                "breached": email
                                in email_info.get("breached_emails", []),
                                "domain": email.split("@")[1] if "@" in email else "",
                            },
                            labels={"email", "communication"},
                        )
                    )

        # Extract person entities
        if "social_data" in data:
            social_info = data["social_data"]
            if "profiles" in social_info:
                for profile in social_info["profiles"]:
                    entities.append(
                        Entity(
                            id=f"person_{profile.get('username', profile.get('name', 'unknown'))}",
                            type="person",
                            name=profile.get(
                                "name", profile.get("username", "Unknown")
                            ),
                            properties={
                                "username": profile.get("username", ""),
                                "platform": profile.get("platform", ""),
                                "url": profile.get("url", ""),
                            },
                            labels={"person", "social_media"},
                        )
                    )

        return entities

    def _extract_relationships_from_investigation(
        self, data: Dict[str, Any], entities: List[Entity]
    ) -> List[Relationship]:
        """Extract relationships from investigation data"""
        relationships = []
        entity_map = {entity.id: entity for entity in entities}

        # Domain to IP relationships
        if "domain_data" in data and "ip_data" in data:
            ip_info = data["ip_data"]

            domain_entity = next((e for e in entities if e.type == "domain"), None)
            if domain_entity:
                for ip in ip_info.get("ips", []):
                    ip_entity_id = f"ip_{ip}"
                    if ip_entity_id in entity_map:
                        relationships.append(
                            Relationship(
                                source_id=domain_entity.id,
                                target_id=ip_entity_id,
                                type="resolves_to",
                                properties={"dns_record": "A"},
                                confidence=0.9,
                                source="dns_resolution",
                            )
                        )

        # Email to domain relationships
        if "email_data" in data:
            email_info = data["email_data"]
            for email in email_info.get("emails", []):
                if "@" in email:
                    domain = email.split("@")[1]
                    domain_entity_id = f"domain_{domain}"
                    email_entity_id = f"email_{email}"

                    if domain_entity_id in entity_map and email_entity_id in entity_map:
                        relationships.append(
                            Relationship(
                                source_id=email_entity_id,
                                target_id=domain_entity_id,
                                type="belongs_to",
                                properties={"email_provider": domain},
                                confidence=1.0,
                                source="email_parsing",
                            )
                        )

        # Person to social profile relationships
        if "social_data" in data:
            social_info = data["social_data"]
            for profile in social_info.get("profiles", []):
                person_entity_id = (
                    f"person_{profile.get('username', profile.get('name', 'unknown'))}"
                )
                if person_entity_id in entity_map:
                    # Create platform entity if it doesn't exist
                    platform_entity_id = (
                        f"platform_{profile.get('platform', 'unknown')}"
                    )
                    if platform_entity_id not in entity_map:
                        entities.append(
                            Entity(
                                id=platform_entity_id,
                                type="platform",
                                name=profile.get("platform", "Unknown Platform"),
                                labels={"platform", "social_media"},
                            )
                        )
                        entity_map[platform_entity_id] = entities[-1]

                    relationships.append(
                        Relationship(
                            source_id=person_entity_id,
                            target_id=platform_entity_id,
                            type="has_profile_on",
                            properties={
                                "username": profile.get("username", ""),
                                "url": profile.get("url", ""),
                            },
                            confidence=0.8,
                            source="social_media_analysis",
                        )
                    )

        return relationships

    async def get_graph_statistics(self) -> Dict[str, Any]:
        """Get comprehensive graph database statistics"""
        if not self.connected:
            return {"connected": False}

        try:
            async with self.driver.session() as session:
                # Entity counts by type
                entity_result = await session.run(
                    """
                    MATCH (e:Entity)
                    RETURN e.type as type, count(*) as count
                    ORDER BY count DESC
                """
                )

                entity_counts = {}
                async for record in entity_result:
                    entity_counts[record["type"]] = record["count"]

                # Relationship counts by type
                rel_result = await session.run(
                    """
                    MATCH ()-[r:RELATES_TO]->()
                    RETURN r.type as type, count(*) as count
                    ORDER BY count DESC
                """
                )

                relationship_counts = {}
                async for record in rel_result:
                    relationship_counts[record["type"]] = record["count"]

                # General statistics
                stats_result = await session.run(
                    """
                    MATCH (e:Entity)
                    OPTIONAL MATCH ()-[r:RELATES_TO]->()
                    RETURN count(DISTINCT e) as entities,
                           count(DISTINCT r) as relationships
                """
                )

                stats_record = await stats_result.single()

                return {
                    "connected": True,
                    "entities": {
                        "total": stats_record["entities"],
                        "by_type": entity_counts,
                    },
                    "relationships": {
                        "total": stats_record["relationships"],
                        "by_type": relationship_counts,
                    },
                    "timestamp": datetime.now().isoformat(),
                }

        except Exception as e:
            logger.error(f"Failed to get graph statistics: {e}")
            return {"connected": False, "error": str(e)}

    async def export_graph_data(self, format: str = "json") -> Optional[str]:
        """Export graph data for external analysis"""
        if not self.connected:
            return None

        try:
            async with self.driver.session() as session:
                # Export entities
                entity_result = await session.run(
                    """
                    MATCH (e:Entity)
                    RETURN e.id, e.type, e.name, e.properties, e.labels
                """
                )

                entities = []
                async for record in entity_result:
                    entities.append(
                        {
                            "id": record["e.id"],
                            "type": record["e.type"],
                            "name": record["e.name"],
                            "properties": json.loads(record.get("e.properties", "{}")),
                            "labels": record["e.labels"],
                        }
                    )

                # Export relationships
                rel_result = await session.run(
                    """
                    MATCH (source)-[r:RELATES_TO]->(target)
                    RETURN source.id, target.id, r.type, r.properties, r.confidence
                """
                )

                relationships = []
                async for record in rel_result:
                    relationships.append(
                        {
                            "source": record["source.id"],
                            "target": record["target.id"],
                            "type": record["r.type"],
                            "properties": json.loads(record.get("r.properties", "{}")),
                            "confidence": record["r.confidence"],
                        }
                    )

                export_data = {
                    "entities": entities,
                    "relationships": relationships,
                    "exported_at": datetime.now().isoformat(),
                    "format": format,
                }

                return json.dumps(export_data, indent=2)

        except Exception as e:
            logger.error(f"Failed to export graph data: {e}")
            return None
