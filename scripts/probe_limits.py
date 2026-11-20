"""Bound dial concurrency by workload size and by the first physical entry host."""
from __future__ import annotations

from collections import Counter, deque
import threading


def choose_workers(count, ceiling, endpoint_keys, per_endpoint=8, adaptive=True):
    """Return a worker count within workload, endpoint and configured ceilings."""
    if count <= 0:
        return 1
    size_limit = max(4, ((count + 15) // 16) * 8) if adaptive else ceiling
    endpoint_limit = sum(min(amount, per_endpoint) for amount in Counter(endpoint_keys).values())
    return max(1, min(count, ceiling, size_limit, endpoint_limit or count))


def interleave_endpoints(indices, endpoint_keys):
    """Return lane indices in round-robin endpoint order to reduce queue blocking."""
    groups = {}
    for index in indices:
        groups.setdefault(endpoint_keys[index], deque()).append(index)
    pending = deque(groups.values())
    ordered = []
    while pending:
        group = pending.popleft()
        ordered.append(group.popleft())
        if group:
            pending.append(group)
    return ordered


class EndpointLimiter:
    """Limit simultaneous dials to each first entry host without logging hosts."""

    def __init__(self, keys, limit=8):
        """Build one bounded semaphore per endpoint key using a positive limit."""
        self.guards = {key: threading.BoundedSemaphore(max(1, int(limit))) for key in keys}

    def call(self, key, function, *args):
        """Run a callable under an endpoint permit and return its result."""
        with self.guards[key]:
            return function(*args)
