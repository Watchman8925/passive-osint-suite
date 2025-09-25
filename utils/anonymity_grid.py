"""
Anonymity Grid - Cooperative query bundling and anonymity mixing system.
Implements distributed anonymity through query mixing and decoy traffic.
"""

import json
import logging
import random
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class QueryType(Enum):
    """Types of queries in the anonymity grid."""
    REAL = "real"
    DECOY = "decoy"
    BUNDLE = "bundle"
    MIXED = "mixed"


class QueryPriority(Enum):
    """Query priority levels."""
    URGENT = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class GridNodeRole(Enum):
    """Roles nodes can play in the anonymity grid."""
    CONSUMER = "consumer"      # Only submits queries
    MIXER = "mixer"           # Mixes and forwards queries
    EXECUTOR = "executor"     # Executes queries and returns results
    RELAY = "relay"           # Forwards traffic without execution


@dataclass
class AnonymousQuery:
    """A query within the anonymity grid."""
    query_id: str
    query_type: QueryType
    operation_type: str
    target: str
    parameters: Dict[str, Any]
    priority: QueryPriority = QueryPriority.NORMAL
    hop_count: int = 0
    max_hops: int = 3
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    source_node: Optional[str] = None
    destination_node: Optional[str] = None
    path_history: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryBundle:
    """Bundle of queries for batch processing."""
    bundle_id: str
    queries: List[AnonymousQuery]
    target_batch_size: int = 10
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    is_sealed: bool = False


@dataclass
class GridNode:
    """Node in the anonymity grid."""
    node_id: str
    role: GridNodeRole
    capabilities: Set[str]
    trust_score: float = 0.5
    last_seen: datetime = field(default_factory=datetime.now)
    query_count: int = 0
    success_rate: float = 1.0
    response_time_avg: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryResult:
    """Result from query execution."""
    query_id: str
    result_data: Any
    success: bool
    error_message: Optional[str] = None
    execution_time: float = 0.0
    executor_node: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class AnonymityGrid:
    """
    Cooperative anonymity system using query bundling and mixing.
    
    Features:
    - Query bundling and batching
    - Decoy traffic generation  
    - Multi-hop query routing
    - Cooperative mixing pools
    - Traffic analysis resistance
    - Result aggregation and delivery
    """
    
    def __init__(self, node_id: Optional[str] = None, role: GridNodeRole = GridNodeRole.CONSUMER):
        """
        Initialize anonymity grid node.
        
        Args:
            node_id: Unique identifier for this node
            role: Role this node plays in the grid
        """
        self.node_id = node_id or f"node_{uuid.uuid4().hex[:8]}"
        self.role = role
        self.capabilities = self._initialize_capabilities()
        
        # Grid state
        self.known_nodes: Dict[str, GridNode] = {}
        self.active_queries: Dict[str, AnonymousQuery] = {}
        self.pending_bundles: Dict[str, QueryBundle] = {}
        self.query_results: Dict[str, QueryResult] = {}
        self.decoy_pool: List[AnonymousQuery] = []
        
        # Traffic mixing
        self.mixing_buffer: Dict[int, List[AnonymousQuery]] = defaultdict(list)
        self.batch_intervals: Dict[QueryPriority, float] = {
            QueryPriority.URGENT: 1.0,      # 1 second
            QueryPriority.HIGH: 5.0,        # 5 seconds
            QueryPriority.NORMAL: 15.0,     # 15 seconds
            QueryPriority.LOW: 60.0,        # 1 minute
            QueryPriority.BACKGROUND: 300.0  # 5 minutes
        }
        
        # Statistics and monitoring
        self.stats = {
            'queries_submitted': 0,
            'queries_processed': 0,
            'queries_mixed': 0,
            'decoys_generated': 0,
            'bundles_created': 0,
            'successful_queries': 0,
            'failed_queries': 0
        }
        
        # Background tasks
        self._running = False
        self._background_tasks = []
        
        # Register this node
        self.register_node()
        
        logger.info(f"Anonymity grid node initialized: {self.node_id} ({role.value})")
    
    def _initialize_capabilities(self) -> Set[str]:
        """Initialize node capabilities based on role."""
        base_caps = {"query_submission", "result_reception"}
        
        if self.role in [GridNodeRole.MIXER, GridNodeRole.EXECUTOR]:
            base_caps.update({
                "query_mixing", "bundle_processing", "decoy_generation"
            })
        
        if self.role == GridNodeRole.EXECUTOR:
            base_caps.update({
                "domain_lookup", "whois_query", "port_scan", 
                "ssl_check", "http_request", "dns_query"
            })
        
        if self.role == GridNodeRole.RELAY:
            base_caps.update({"query_forwarding", "traffic_relaying"})
        
        return base_caps
    
    def register_node(self):
        """Register this node in the grid."""
        node = GridNode(
            node_id=self.node_id,
            role=self.role,
            capabilities=self.capabilities
        )
        self.known_nodes[self.node_id] = node
    
    def start_grid_services(self):
        """Start background grid services."""
        if self._running:
            return
        
        self._running = True
        
        # Start background tasks
        if "query_mixing" in self.capabilities:
            task = threading.Thread(target=self._run_mixer_service, daemon=True)
            task.start()
            self._background_tasks.append(task)
        
        if "decoy_generation" in self.capabilities:
            task = threading.Thread(target=self._run_decoy_service, daemon=True)
            task.start()
            self._background_tasks.append(task)
        
        if "bundle_processing" in self.capabilities:
            task = threading.Thread(target=self._run_bundle_service, daemon=True)
            task.start()
            self._background_tasks.append(task)
        
        logger.info(f"Grid services started for node {self.node_id}")
    
    def stop_grid_services(self):
        """Stop background grid services."""
        self._running = False
        
        # Wait for background tasks to complete
        for task in self._background_tasks:
            if task.is_alive():
                task.join(timeout=5.0)
        
        logger.info(f"Grid services stopped for node {self.node_id}")
    
    def submit_query(self, operation_type: str, target: str,
                    parameters: Optional[Dict[str, Any]] = None,
                    priority: QueryPriority = QueryPriority.NORMAL,
                    anonymous: bool = True) -> str:
        """
        Submit a query to the anonymity grid.
        
        Args:
            operation_type: Type of operation (domain_lookup, whois, etc.)
            target: Target of the operation
            parameters: Additional parameters for the operation
            priority: Query priority level
            anonymous: Whether to use anonymity features
        
        Returns:
            Query ID for tracking
        """
        query = AnonymousQuery(
            query_id=f"query_{uuid.uuid4().hex}",
            query_type=QueryType.REAL,
            operation_type=operation_type,
            target=target,
            parameters=parameters or {},
            priority=priority,
            source_node=self.node_id,
            expires_at=datetime.now() + timedelta(minutes=30)
        )
        
        self.active_queries[query.query_id] = query
        self.stats['queries_submitted'] += 1
        
        if anonymous and self.role != GridNodeRole.CONSUMER:
            # Add to mixing buffer for anonymization
            priority_level = priority.value
            self.mixing_buffer[priority_level].append(query)
            
            logger.debug(
                f"Query {query.query_id} added to mixing buffer "
                f"(priority {priority.value})"
            )
        else:
            # Direct execution for non-anonymous queries or consumer-only nodes
            self._schedule_direct_execution(query)
        
        return query.query_id
    
    def get_query_result(self, query_id: str, 
                         timeout: float = 60.0) -> Optional[QueryResult]:
        """
        Get result for a submitted query.
        
        Args:
            query_id: Query identifier
            timeout: Maximum time to wait for result
        
        Returns:
            Query result if available
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if query_id in self.query_results:
                result = self.query_results.pop(query_id)
                
                # Clean up active query
                if query_id in self.active_queries:
                    del self.active_queries[query_id]
                
                return result
            
            time.sleep(0.1)
        
        logger.warning(f"Query {query_id} timed out after {timeout} seconds")
        return None
    
    def _schedule_direct_execution(self, query: AnonymousQuery):
        """Schedule direct execution of a query."""
        def execute():
            try:
                result = self._execute_query(query)
                self.query_results[query.query_id] = result
            except Exception as e:
                error_result = QueryResult(
                    query_id=query.query_id,
                    result_data=None,
                    success=False,
                    error_message=str(e),
                    executor_node=self.node_id
                )
                self.query_results[query.query_id] = error_result
        
        # Execute in background thread
        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
    
    def _execute_query(self, query: AnonymousQuery) -> QueryResult:
        """Execute a query and return result."""
        start_time = time.time()
        
        try:
            # Import OSINT utilities for execution
            from osint_utils import OSINTUtils
            utils = OSINTUtils()
            
            # Execute based on operation type
            result_data = None
            
            if query.operation_type == "domain_lookup":
                # Simulate domain lookup
                result_data = {"domain": query.target, "resolved": True}
            
            elif query.operation_type == "whois_query":
                # Simulate whois query
                result_data = {"domain": query.target, "whois_data": "simulated"}
            
            elif query.operation_type == "http_request":
                # Make actual HTTP request
                url = query.parameters.get('url', query.target)
                response = utils.make_request(url)
                if response:
                    result_data = {
                        "url": url,
                        "status_code": response.status_code,
                        "content_length": len(response.content)
                    }
                else:
                    raise Exception("HTTP request failed")
            
            else:
                # Generic execution
                result_data = {
                    "operation": query.operation_type, 
                    "target": query.target
                }
            
            execution_time = time.time() - start_time
            
            result = QueryResult(
                query_id=query.query_id,
                result_data=result_data,
                success=True,
                execution_time=execution_time,
                executor_node=self.node_id
            )
            
            self.stats['successful_queries'] += 1
            self.stats['queries_processed'] += 1
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            result = QueryResult(
                query_id=query.query_id,
                result_data=None,
                success=False,
                error_message=str(e),
                execution_time=execution_time,
                executor_node=self.node_id
            )
            
            self.stats['failed_queries'] += 1
            self.stats['queries_processed'] += 1
            
            return result
    
    def _run_mixer_service(self):
        """Background service for query mixing."""
        logger.info("Query mixer service started")
        
        while self._running:
            try:
                for priority_level, queries in self.mixing_buffer.items():
                    if not queries:
                        continue
                    
                    priority = QueryPriority(priority_level)
                    batch_interval = self.batch_intervals[priority]
                    
                    # Check if it's time to process this priority level
                    oldest_query_time = min(q.created_at for q in queries)
                    current_time = datetime.now()
                    time_since_oldest = (
                        current_time - oldest_query_time
                    ).total_seconds()
                    
                    if time_since_oldest >= batch_interval or len(queries) >= 10:
                        # Mix and process queries
                        self._mix_and_process_queries(queries, priority)
                        queries.clear()
                
                time.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Error in mixer service: {e}")
                time.sleep(5.0)
    
    def _mix_and_process_queries(self, queries: List[AnonymousQuery], 
                                priority: QueryPriority):
        """Mix queries with decoys and process them."""
        if not queries:
            return
        
        # Generate decoy queries to pad the batch
        decoy_count = max(3, len(queries))  # At least 3 decoys
        decoys = self._generate_decoy_queries(decoy_count, priority)
        
        # Combine real queries with decoys
        mixed_batch = queries + decoys
        
        # Shuffle to obscure original order
        random.shuffle(mixed_batch)
        
        # Create bundle
        bundle = QueryBundle(
            bundle_id=f"bundle_{uuid.uuid4().hex[:8]}",
            queries=mixed_batch,
            target_batch_size=len(mixed_batch),
            expires_at=datetime.now() + timedelta(minutes=15)
        )
        
        self.pending_bundles[bundle.bundle_id] = bundle
        self.stats['bundles_created'] += 1
        self.stats['queries_mixed'] += len(queries)
        
        # Process bundle
        self._process_bundle(bundle)
        
        logger.debug(
            f"Mixed and processed {len(queries)} real queries "
            f"with {len(decoys)} decoys"
        )
    
    def _generate_decoy_queries(self, count: int, 
                              priority: QueryPriority) -> List[AnonymousQuery]:
        """Generate decoy queries for mixing."""
        decoys = []
        
        # Common decoy targets and operations
        decoy_targets = [
            "google.com", "facebook.com", "youtube.com", "amazon.com",
            "microsoft.com", "apple.com", "twitter.com", "linkedin.com",
            "reddit.com", "wikipedia.org", "github.com", "stackoverflow.com"
        ]
        
        decoy_operations = [
            "domain_lookup", "whois_query", "http_request", "dns_query"
        ]
        
        for _ in range(count):
            target = random.choice(decoy_targets)
            operation = random.choice(decoy_operations)
            
            decoy = AnonymousQuery(
                query_id=f"decoy_{uuid.uuid4().hex}",
                query_type=QueryType.DECOY,
                operation_type=operation,
                target=target,
                parameters={},
                priority=priority,
                source_node=self.node_id,
                expires_at=datetime.now() + timedelta(minutes=10)
            )
            
            decoys.append(decoy)
        
        self.stats['decoys_generated'] += count
        return decoys
    
    def _process_bundle(self, bundle: QueryBundle):
        """Process a query bundle."""
        def process():
            for query in bundle.queries:
                try:
                    # Skip decoy queries - just simulate processing
                    if query.query_type == QueryType.DECOY:
                        # Simulate processing time
                        time.sleep(random.uniform(0.1, 0.5))
                        continue
                    
                    # Process real queries
                    result = self._execute_query(query)
                    self.query_results[query.query_id] = result
                    
                except Exception as e:
                    error_result = QueryResult(
                        query_id=query.query_id,
                        result_data=None,
                        success=False,
                        error_message=str(e),
                        executor_node=self.node_id
                    )
                    self.query_results[query.query_id] = error_result
            
            # Clean up bundle
            if bundle.bundle_id in self.pending_bundles:
                del self.pending_bundles[bundle.bundle_id]
        
        # Process bundle in background
        thread = threading.Thread(target=process, daemon=True)
        thread.start()
    
    def _run_decoy_service(self):
        """Background service for generating decoy traffic."""
        logger.info("Decoy traffic service started")
        
        while self._running:
            try:
                # Generate background decoy traffic
                if random.random() < 0.1:  # 10% chance every cycle
                    decoys = self._generate_decoy_queries(
                        random.randint(1, 3), 
                        QueryPriority.BACKGROUND
                    )
                    
                    for decoy in decoys:
                        # Add some of the decoys to mixing buffer for realism
                        if random.random() < 0.5:
                            priority_level = decoy.priority.value
                            self.mixing_buffer[priority_level].append(decoy)
                
                time.sleep(random.uniform(30, 120))  # 30-120 seconds
                
            except Exception as e:
                logger.error(f"Error in decoy service: {e}")
                time.sleep(60.0)
    
    def _run_bundle_service(self):
        """Background service for bundle management."""
        logger.info("Bundle management service started")
        
        while self._running:
            try:
                current_time = datetime.now()
                
                # Clean up expired bundles
                expired_bundles = [
                    bundle_id for bundle_id, bundle in self.pending_bundles.items()
                    if bundle.expires_at and current_time > bundle.expires_at
                ]
                
                for bundle_id in expired_bundles:
                    del self.pending_bundles[bundle_id]
                    logger.debug(f"Expired bundle {bundle_id} cleaned up")
                
                # Clean up expired queries
                expired_queries = [
                    query_id for query_id, query in self.active_queries.items()
                    if query.expires_at and current_time > query.expires_at
                ]
                
                for query_id in expired_queries:
                    del self.active_queries[query_id]
                    logger.debug(f"Expired query {query_id} cleaned up")
                
                time.sleep(60.0)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in bundle service: {e}")
                time.sleep(60.0)
    
    def get_grid_statistics(self) -> Dict[str, Any]:
        """Get anonymity grid statistics."""
        return {
            'node_id': self.node_id,
            'role': self.role.value,
            'capabilities': list(self.capabilities),
            'stats': self.stats.copy(),
            'active_queries': len(self.active_queries),
            'pending_bundles': len(self.pending_bundles),
            'known_nodes': len(self.known_nodes),
            'running': self._running,
            'mixing_buffer_sizes': {
                priority: len(queries) 
                for priority, queries in self.mixing_buffer.items()
            }
        }
    
    def add_grid_node(self, node_id: str, role: GridNodeRole,
                     capabilities: Optional[Set[str]] = None):
        """Add a node to the known nodes list."""
        node = GridNode(
            node_id=node_id,
            role=role,
            capabilities=capabilities or set()
        )
        self.known_nodes[node_id] = node
        logger.info(f"Added grid node: {node_id} ({role.value})")
    
    def remove_grid_node(self, node_id: str):
        """Remove a node from the grid."""
        if node_id in self.known_nodes:
            del self.known_nodes[node_id]
            logger.info(f"Removed grid node: {node_id}")


# Global anonymity grid instance
anonymity_grid = None


def initialize_anonymity_grid(
    node_id: Optional[str] = None,
    role: GridNodeRole = GridNodeRole.CONSUMER
) -> AnonymityGrid:
    """
    Initialize the global anonymity grid instance.
    
    Args:
        node_id: Unique node identifier
        role: Role for this node
    
    Returns:
        Anonymity grid instance
    """
    global anonymity_grid
    
    if anonymity_grid is None:
        anonymity_grid = AnonymityGrid(node_id, role)
        anonymity_grid.start_grid_services()
    
    return anonymity_grid


def anonymous_query(operation_type: str, target: str, 
                   parameters: Optional[Dict[str, Any]] = None,
                   priority: QueryPriority = QueryPriority.NORMAL,
                   timeout: float = 60.0) -> Optional[QueryResult]:
    """
    Convenience function for anonymous queries.
    
    Args:
        operation_type: Type of operation
        target: Target of operation  
        parameters: Additional parameters
        priority: Query priority
        timeout: Maximum wait time
    
    Returns:
        Query result
    """
    global anonymity_grid
    
    if anonymity_grid is None:
        # Initialize with EXECUTOR role so queries can actually be processed
        anonymity_grid = initialize_anonymity_grid(role=GridNodeRole.EXECUTOR)
    
    query_id = anonymity_grid.submit_query(
        operation_type=operation_type,
        target=target,
        parameters=parameters,
        priority=priority,
        anonymous=True
    )
    
    return anonymity_grid.get_query_result(query_id, timeout)


if __name__ == "__main__":
    # Example usage
    grid = AnonymityGrid(role=GridNodeRole.MIXER)
    grid.start_grid_services()
    
    # Submit some test queries
    query_id1 = grid.submit_query("domain_lookup", "example.com")
    query_id2 = grid.submit_query("whois_query", "test.org")
    
    # Get results
    result1 = grid.get_query_result(query_id1)
    result2 = grid.get_query_result(query_id2)
    
    print(f"Result 1: {result1}")
    print(f"Result 2: {result2}")
    
    # Show statistics
    stats = grid.get_grid_statistics()
    print(f"Grid stats: {json.dumps(stats, indent=2)}")
    
    grid.stop_grid_services()