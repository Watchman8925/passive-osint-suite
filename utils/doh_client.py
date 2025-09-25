"""
DNS over HTTPS (DoH) client with Tor proxy support.
Provides secure, private DNS resolution with caching and anti-fingerprinting.
"""

import asyncio
import base64
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import dns
    import dns.message
    import dns.rdataclass
    import dns.rdatatype
    import dns.rrset
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not available - DoH functionality limited")

# Import our proxied transport
try:
    from transport import transport as proxied_transport  # type: ignore
    TRANSPORT_AVAILABLE = True
except ImportError:
    TRANSPORT_AVAILABLE = False
    logging.warning("Proxied transport not available - DoH will use direct connections")

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """Represents a DNS record with TTL and caching metadata."""
    name: str
    rtype: str
    ttl: int
    data: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    def is_expired(self) -> bool:
        """Check if the DNS record has expired based on TTL."""
        return datetime.now() > (self.timestamp + timedelta(seconds=self.ttl))
    
    def remaining_ttl(self) -> int:
        """Get remaining TTL in seconds."""
        elapsed = (datetime.now() - self.timestamp).total_seconds()
        return max(0, int(self.ttl - elapsed))


@dataclass 
class DoHResponse:
    """DNS over HTTPS response with metadata."""
    question: str
    answers: List[DNSRecord]
    authority: List[DNSRecord] = field(default_factory=list)
    additional: List[DNSRecord] = field(default_factory=list)
    status: int = 0
    truncated: bool = False
    recursion_desired: bool = True
    recursion_available: bool = False
    authenticated_data: bool = False
    checking_disabled: bool = False
    response_time_ms: int = 0
    resolver_used: str = ""


class DoHClient:
    """
    DNS over HTTPS client with Tor proxy support and local caching.
    Implements RFC 8484 with anti-fingerprinting measures.
    """
    
    # Popular DoH resolvers (will be rotated for anti-fingerprinting)
    DEFAULT_RESOLVERS = [
        "https://cloudflare-dns.com/dns-query",      # Cloudflare
        "https://dns.google/dns-query",               # Google
        "https://dns.quad9.net/dns-query",           # Quad9
        "https://doh.opendns.com/dns-query",         # OpenDNS
        "https://dns.nextdns.io/dns-query",          # NextDNS
        "https://doh.cleanbrowsing.org/doh/security-filter/",  # CleanBrowsing
    ]
    
    def __init__(
        self,
        resolvers: Optional[List[str]] = None,
        cache_size: int = 1000,
        default_ttl: int = 300,
        min_ttl: int = 60,
        max_ttl: int = 3600,
        enable_cache: bool = True,
        rotate_resolvers: bool = True
    ):
        self.resolvers = resolvers or self.DEFAULT_RESOLVERS.copy()
        self.cache_size = cache_size
        self.default_ttl = default_ttl
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.enable_cache = enable_cache
        self.rotate_resolvers = rotate_resolvers
        
        # DNS cache: key = (name, rtype), value = DNSRecord
        self._cache: Dict[Tuple[str, str], DNSRecord] = {}
        self._cache_lock = threading.Lock()
        
        # Resolver rotation state
        self._current_resolver_index = 0
        self._resolver_failures: Dict[str, int] = {}
        self._resolver_lock = threading.Lock()
        
        # Statistics
        self._stats = {
            'queries_total': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'resolver_failures': 0,
            'avg_response_time': 0.0
        }
        self._stats_lock = threading.Lock()
        
        logger.info(f"DoH client initialized with {len(self.resolvers)} resolvers")
        if not TRANSPORT_AVAILABLE:
            logger.warning(
                "DoH client will use direct connections - anonymity compromised"
            )
    
    def _get_cache_key(self, name: str, rtype: str) -> Tuple[str, str]:
        """Generate cache key for DNS record."""
        return (name.lower().rstrip('.'), rtype.upper())
    
    def _cleanup_cache(self):
        """Remove expired entries and enforce cache size limit."""
        with self._cache_lock:
            # Remove expired entries
            expired_keys = [
                key for key, record in self._cache.items() 
                if record.is_expired()
            ]
            for key in expired_keys:
                del self._cache[key]
            
            # Enforce size limit (LRU-like: remove oldest entries)
            if len(self._cache) > self.cache_size:
                # Sort by timestamp and remove oldest
                sorted_items = sorted(
                    self._cache.items(), 
                    key=lambda x: x[1].timestamp
                )
                excess_count = len(self._cache) - self.cache_size
                for i in range(excess_count):
                    key = sorted_items[i][0]
                    del self._cache[key]
    
    def _get_from_cache(self, name: str, rtype: str) -> Optional[DNSRecord]:
        """Retrieve record from cache if valid."""
        if not self.enable_cache:
            return None
        
        cache_key = self._get_cache_key(name, rtype)
        
        with self._cache_lock:
            record = self._cache.get(cache_key)
            if record and not record.is_expired():
                with self._stats_lock:
                    self._stats['cache_hits'] += 1
                return record
            elif record:
                # Remove expired record
                del self._cache[cache_key]
        
        with self._stats_lock:
            self._stats['cache_misses'] += 1
        return None
    
    def _add_to_cache(self, record: DNSRecord):
        """Add record to cache."""
        if not self.enable_cache:
            return
        
        # Normalize TTL values
        record.ttl = max(self.min_ttl, min(self.max_ttl, record.ttl))
        
        cache_key = self._get_cache_key(record.name, record.rtype)
        
        with self._cache_lock:
            self._cache[cache_key] = record
        
        # Periodic cache cleanup
        if len(self._cache) > self.cache_size * 1.2:
            self._cleanup_cache()
    
    def _get_next_resolver(self) -> str:
        """Get next resolver using rotation or selection strategy."""
        with self._resolver_lock:
            if self.rotate_resolvers:
                # Simple round-robin with failure tracking
                attempts = 0
                while attempts < len(self.resolvers):
                    resolver = self.resolvers[self._current_resolver_index]
                    self._current_resolver_index = (
                        (self._current_resolver_index + 1) % len(self.resolvers)
                    )
                    
                    # Skip resolvers with recent failures
                    failure_count = self._resolver_failures.get(resolver, 0)
                    if failure_count < 3:  # Allow up to 3 failures before skipping
                        return resolver
                    
                    attempts += 1
                
                # If all resolvers have failures, reset and use first
                logger.warning("All resolvers have failures - resetting failure counts")
                self._resolver_failures.clear()
                return self.resolvers[0]
            else:
                return self.resolvers[0]
    
    def _record_resolver_failure(self, resolver: str):
        """Record a failure for the given resolver."""
        with self._resolver_lock:
            self._resolver_failures[resolver] = (
                self._resolver_failures.get(resolver, 0) + 1
            )
    
    def _create_dns_query(self, name: str, rtype: str) -> bytes:
        """Create DNS query in wire format."""
        if not DNS_AVAILABLE:
            raise RuntimeError("dnspython required for DNS query creation")
        
        # Create DNS message
        query = dns.message.make_query(name, rtype)  # type: ignore
        query.flags &= ~dns.flags.RD  # type: ignore # Remove recursion desired for DoH
        
        return query.to_wire()
    
    def _parse_dns_response(self, response_data: bytes, resolver: str) -> DoHResponse:
        """Parse DNS response from wire format."""
        if not DNS_AVAILABLE:
            raise RuntimeError("dnspython required for DNS response parsing")
        
        try:
            response = dns.message.from_wire(response_data)  # type: ignore
            
            # Extract answers
            answers = []
            for rrset in response.answer:
                for rdata in rrset:
                    record = DNSRecord(
                        name=str(rrset.name),
                        rtype=dns.rdatatype.to_text(rrset.rdtype),  # type: ignore
                        ttl=rrset.ttl,
                        data=str(rdata)
                    )
                    answers.append(record)
            
            # Extract authority records
            authority = []
            for rrset in response.authority:
                for rdata in rrset:
                    record = DNSRecord(
                        name=str(rrset.name),
                        rtype=dns.rdatatype.to_text(rrset.rdtype),  # type: ignore
                        ttl=rrset.ttl,
                        data=str(rdata)
                    )
                    authority.append(record)
            
            # Extract additional records
            additional = []
            for rrset in response.additional:
                for rdata in rrset:
                    record = DNSRecord(
                        name=str(rrset.name),
                        rtype=dns.rdatatype.to_text(rrset.rdtype),  # type: ignore
                        ttl=rrset.ttl,
                        data=str(rdata)
                    )
                    additional.append(record)
            
            return DoHResponse(
                question=str(response.question[0].name) if response.question else "",
                answers=answers,
                authority=authority,
                additional=additional,
                status=response.rcode(),
                truncated=bool(response.flags & dns.flags.TC),  # type: ignore
                recursion_desired=bool(response.flags & dns.flags.RD),  # type: ignore
                recursion_available=bool(response.flags & dns.flags.RA),  # type: ignore
                authenticated_data=bool(response.flags & dns.flags.AD),  # type: ignore
                checking_disabled=bool(response.flags & dns.flags.CD),  # type: ignore
                resolver_used=resolver
            )
            
        except Exception as e:
            logger.error(f"Failed to parse DNS response: {e}")
            raise
    
    async def resolve(
        self, 
        name: str, 
        rtype: str = 'A',
        use_cache: bool = True
    ) -> DoHResponse:
        """
        Resolve DNS name using DoH.
        
        Args:
            name: Domain name to resolve
            rtype: DNS record type (A, AAAA, MX, TXT, etc.)
            use_cache: Whether to use cached results
        
        Returns:
            DoHResponse with resolved records
        """
        with self._stats_lock:
            self._stats['queries_total'] += 1
        
        start_time = time.time()
        
        # Check cache first
        if use_cache:
            cached_record = self._get_from_cache(name, rtype)
            if cached_record:
                logger.debug(f"Cache hit for {name} {rtype}")
                return DoHResponse(
                    question=name,
                    answers=[cached_record],
                    response_time_ms=0,
                    resolver_used="cache"
                )
        
        # Prepare DNS query
        try:
            query_wire = self._create_dns_query(name, rtype)
            query_b64 = base64.urlsafe_b64encode(query_wire).decode().rstrip('=')
        except Exception as e:
            logger.error(f"Failed to create DNS query for {name}: {e}")
            raise
        
        # Try resolvers until successful
        last_error = None
        for attempt in range(len(self.resolvers)):
            resolver = self._get_next_resolver()
            
            try:
                # Construct DoH URL with query parameter
                url = f"{resolver}?dns={query_b64}"
                
                # Make request through our proxied transport
                if TRANSPORT_AVAILABLE:
                    response = await proxied_transport.get(  # type: ignore
                        url,
                        headers={
                            'Accept': 'application/dns-message',
                            'Content-Type': 'application/dns-message'
                        }
                    )
                else:
                    # Fallback to direct connection (compromises anonymity)
                    import httpx
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            url,
                            headers={
                                'Accept': 'application/dns-message',
                                'Content-Type': 'application/dns-message'
                            }
                        )
                
                if response.status_code == 200:
                    # Parse DNS response
                    doh_response = self._parse_dns_response(
                        response.content, 
                        resolver
                    )
                    
                    # Calculate response time
                    response_time = int((time.time() - start_time) * 1000)
                    doh_response.response_time_ms = response_time
                    
                    # Update statistics
                    with self._stats_lock:
                        self._stats['avg_response_time'] = (
                            (self._stats['avg_response_time'] * 
                             (self._stats['queries_total'] - 1) + response_time) /
                            self._stats['queries_total']
                        )
                    
                    # Cache the answers
                    if use_cache:
                        for answer in doh_response.answers:
                            self._add_to_cache(answer)
                    
                    logger.debug(
                        f"Resolved {name} {rtype} via {resolver} "
                        f"({len(doh_response.answers)} answers, {response_time}ms)"
                    )
                    
                    return doh_response
                else:
                    error_msg = f"DoH query failed: HTTP {response.status_code}"
                    logger.warning(f"{error_msg} from {resolver}")
                    last_error = RuntimeError(error_msg)
                    self._record_resolver_failure(resolver)
                    
            except Exception as e:
                logger.warning(f"DoH resolver {resolver} failed: {e}")
                last_error = e
                self._record_resolver_failure(resolver)
                
                with self._stats_lock:
                    self._stats['resolver_failures'] += 1
        
        # All resolvers failed
        error_msg = f"All DoH resolvers failed for {name} {rtype}"
        logger.error(error_msg)
        if last_error:
            raise last_error
        else:
            raise RuntimeError(error_msg)
    
    async def resolve_multiple(
        self, 
        queries: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], DoHResponse]:
        """
        Resolve multiple DNS queries concurrently.
        
        Args:
            queries: List of (name, rtype) tuples
        
        Returns:
            Dict mapping (name, rtype) to DoHResponse
        """
        tasks = []
        for name, rtype in queries:
            task = asyncio.create_task(self.resolve(name, rtype))
            tasks.append((name, rtype, task))
        
        results = {}
        for name, rtype, task in tasks:
            try:
                response = await task
                results[(name, rtype)] = response
            except Exception as e:
                logger.error(f"Failed to resolve {name} {rtype}: {e}")
                # Create error response
                results[(name, rtype)] = DoHResponse(
                    question=name,
                    answers=[],
                    status=2,  # SERVFAIL
                    resolver_used="error"
                )
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get client statistics."""
        with self._stats_lock:
            stats = self._stats.copy()
        
        stats.update({
            'cache_size': len(self._cache),
            'cache_hit_rate': (
                stats['cache_hits'] / 
                max(1, stats['cache_hits'] + stats['cache_misses'])
            ),
            'active_resolvers': len(self.resolvers),
            'resolver_failures_by_url': dict(self._resolver_failures)
        })
        
        return stats
    
    def clear_cache(self):
        """Clear the DNS cache."""
        with self._cache_lock:
            self._cache.clear()
        logger.info("DNS cache cleared")
    
    def reset_resolver_failures(self):
        """Reset resolver failure counts."""
        with self._resolver_lock:
            self._resolver_failures.clear()
        logger.info("Resolver failure counts reset")


# Global DoH client instance
doh_client = DoHClient()


async def resolve_dns(name: str, rtype: str = 'A') -> DoHResponse:
    """Convenience function for DNS resolution."""
    return await doh_client.resolve(name, rtype)


async def resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address (A record)."""
    try:
        response = await doh_client.resolve(domain, 'A')
        if response.answers:
            return response.answers[0].data
    except Exception as e:
        logger.error(f"Failed to resolve IP for {domain}: {e}")
    
    return None


async def resolve_ipv6(domain: str) -> Optional[str]:
    """Resolve domain to IPv6 address (AAAA record)."""
    try:
        response = await doh_client.resolve(domain, 'AAAA')
        if response.answers:
            return response.answers[0].data
    except Exception as e:
        logger.error(f"Failed to resolve IPv6 for {domain}: {e}")
    
    return None


def resolve_dns_sync(name: str, rtype: str = 'A') -> DoHResponse:
    """Synchronous version of DNS resolution."""
    try:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(resolve_dns(name, rtype))
        finally:
            loop.close()
    except Exception as e:
        logger.error(f"Failed to resolve {name} {rtype}: {e}")
        # Return error response
        return DoHResponse(
            question=name,
            answers=[],
            status=2,  # SERVFAIL
            resolver_used="error"
        )