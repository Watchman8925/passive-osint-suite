"""
Simple Relay / Bundle scheduler (Anonymity Grid MVP)

This module provides a small helper to schedule bundles of HTTP operations,
apply jitter and decoys, and forward each operation via a provided caller
(typically OSINTUtils.request_with_fallback).
"""
import random
import time
from typing import Any, Callable, Dict, List


class Relay:
    def __init__(self, caller: Callable, decoy_pool: List[Dict[str, Any]] = None, min_delay=0.5, max_delay=2.0):
        """
        caller: a callable with signature (method, url, **kwargs) -> response
        decoy_pool: list of request dicts for decoy traffic (e.g., {'method':'get','url':'https://example.com'})
        """
        self.caller = caller
        self.decoy_pool = decoy_pool or []
        self.min_delay = min_delay
        self.max_delay = max_delay

    def _jitter_sleep(self):
        time.sleep(random.uniform(self.min_delay, self.max_delay))

    def send_bundle(self, operations: List[Dict[str, Any]], include_decoys: int = 0, shuffle: bool = True):
        """Send a bundle of operations.

        operations: list of dicts: {'method':'get','url':..., 'kwargs':{...}}
        include_decoys: number of decoy operations to interleave from decoy_pool
        Returns a list of (operation, response) tuples.
        """
        ops = list(operations)
        # Add decoys
        for _ in range(include_decoys):
            if not self.decoy_pool:
                break
            ops.append(random.choice(self.decoy_pool))

        if shuffle:
            random.shuffle(ops)

        results = []
        for op in ops:
            # apply jitter before each op
            self._jitter_sleep()
            method = op.get('method', 'get')
            url = op.get('url')
            kwargs = op.get('kwargs', {})
            try:
                resp = self.caller(method, url, **kwargs)
                results.append((op, resp))
            except Exception as e:
                results.append((op, e))
        return results
