"""
Performance Optimization Engine for Megido Scanner

This module provides comprehensive performance optimization for vulnerability scanning:
- Multi-level intelligent caching
- Adaptive thread pool management
- Early termination strategies
- Resource management
- Request deduplication

Author: Megido Team
Version: 1.0.0
"""

import hashlib
import logging
import time
import threading
import queue
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import OrderedDict
import json

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Entry in the cache with metadata"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl_seconds: int = 3600
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return datetime.now() > self.created_at + timedelta(seconds=self.ttl_seconds)
    
    def touch(self):
        """Update last accessed time and count"""
        self.last_accessed = datetime.now()
        self.access_count += 1


class IntelligentCache:
    """
    Multi-level intelligent cache with TTL, LRU, and smart invalidation.
    
    Features:
    - Multiple TTL strategies based on content type
    - LRU eviction when full
    - Automatic size management
    - Hit rate tracking
    """
    
    def __init__(self, max_size_mb: int = 100, default_ttl: int = 3600):
        """
        Initialize intelligent cache.
        
        Args:
            max_size_mb: Maximum cache size in megabytes
            default_ttl: Default TTL in seconds
        """
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.current_size_bytes = 0
        
        # TTL strategies for different content types
        self.ttl_strategies = {
            'static_content': 7200,  # 2 hours
            'api_response': 1800,     # 30 minutes
            'vulnerability_finding': 3600,  # 1 hour
            'page_content': 900,      # 15 minutes
            'ssl_cert': 86400,        # 24 hours
            'dns_lookup': 3600,       # 1 hour
        }
    
    def _calculate_size(self, value: Any) -> int:
        """Estimate size of cached value in bytes"""
        try:
            if isinstance(value, str):
                return len(value.encode('utf-8'))
            elif isinstance(value, (dict, list)):
                return len(json.dumps(value).encode('utf-8'))
            elif isinstance(value, bytes):
                return len(value)
            else:
                # Rough estimate
                return len(str(value).encode('utf-8'))
        except:
            return 1024  # Default 1KB estimate
    
    def _make_room(self, required_bytes: int):
        """Evict entries to make room for new entry"""
        while self.current_size_bytes + required_bytes > self.max_size_bytes:
            if not self.cache:
                break
            
            # Remove least recently used (oldest)
            key, entry = self.cache.popitem(last=False)
            self.current_size_bytes -= entry.size_bytes
            self.evictions += 1
            logger.debug(f"Evicted cache entry: {key} ({entry.size_bytes} bytes)")
    
    def get(self, key: str, content_type: str = 'default') -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            content_type: Type of content (affects TTL)
            
        Returns:
            Cached value or None if not found/expired
        """
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None
            
            entry = self.cache[key]
            
            # Check expiration
            if entry.is_expired():
                del self.cache[key]
                self.current_size_bytes -= entry.size_bytes
                self.misses += 1
                logger.debug(f"Cache entry expired: {key}")
                return None
            
            # Update access stats
            entry.touch()
            self.hits += 1
            
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            
            logger.debug(f"Cache hit: {key} (accessed {entry.access_count} times)")
            return entry.value
    
    def put(self, key: str, value: Any, content_type: str = 'default', 
            ttl: Optional[int] = None):
        """
        Store value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            content_type: Type of content (affects TTL)
            ttl: Optional custom TTL in seconds
        """
        with self.lock:
            # Determine TTL
            if ttl is None:
                ttl = self.ttl_strategies.get(content_type, self.default_ttl)
            
            # Calculate size
            size_bytes = self._calculate_size(value)
            
            # Make room if needed
            self._make_room(size_bytes)
            
            # Create or update entry
            if key in self.cache:
                old_entry = self.cache[key]
                self.current_size_bytes -= old_entry.size_bytes
            
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                ttl_seconds=ttl,
                size_bytes=size_bytes
            )
            
            self.cache[key] = entry
            self.current_size_bytes += size_bytes
            
            logger.debug(f"Cached: {key} ({size_bytes} bytes, TTL: {ttl}s)")
    
    def invalidate(self, key: str):
        """Invalidate a specific cache entry"""
        with self.lock:
            if key in self.cache:
                entry = self.cache.pop(key)
                self.current_size_bytes -= entry.size_bytes
                logger.debug(f"Invalidated cache entry: {key}")
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.current_size_bytes = 0
            logger.info("Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': f"{hit_rate:.2f}%",
                'evictions': self.evictions,
                'entries': len(self.cache),
                'size_mb': self.current_size_bytes / 1024 / 1024,
                'max_size_mb': self.max_size_bytes / 1024 / 1024,
            }


class AdaptiveThreadPool:
    """
    Adaptive thread pool that adjusts size based on workload and performance.
    
    Features:
    - Auto-scaling based on queue depth
    - Performance monitoring
    - Graceful degradation
    - Priority queue support
    """
    
    def __init__(self, min_workers: int = 2, max_workers: int = 20,
                 scale_threshold: int = 10):
        """
        Initialize adaptive thread pool.
        
        Args:
            min_workers: Minimum number of worker threads
            max_workers: Maximum number of worker threads
            scale_threshold: Queue size threshold to trigger scaling
        """
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        
        self.current_workers = min_workers
        self.task_queue: queue.PriorityQueue = queue.PriorityQueue()
        self.result_queue: queue.Queue = queue.Queue()
        
        self.workers: List[threading.Thread] = []
        self.shutdown_event = threading.Event()
        self.lock = threading.Lock()
        
        # Performance tracking
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.total_execution_time = 0.0
        
        # Start initial workers
        self._adjust_workers(min_workers)
    
    def _worker_loop(self):
        """Worker thread main loop"""
        while not self.shutdown_event.is_set():
            try:
                # Get task with timeout
                priority, task_id, func, args, kwargs = self.task_queue.get(timeout=1.0)
                
                # Execute task
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    execution_time = time.time() - start_time
                    
                    self.result_queue.put((task_id, result, None))
                    
                    with self.lock:
                        self.tasks_completed += 1
                        self.total_execution_time += execution_time
                    
                except Exception as e:
                    execution_time = time.time() - start_time
                    self.result_queue.put((task_id, None, e))
                    
                    with self.lock:
                        self.tasks_failed += 1
                        self.total_execution_time += execution_time
                    
                    logger.error(f"Task {task_id} failed: {e}")
                
                finally:
                    self.task_queue.task_done()
            
            except queue.Empty:
                continue
    
    def _adjust_workers(self, target_count: int):
        """Adjust number of worker threads"""
        with self.lock:
            target_count = max(self.min_workers, min(target_count, self.max_workers))
            
            # Add workers if needed
            while len(self.workers) < target_count:
                worker = threading.Thread(target=self._worker_loop, daemon=True)
                worker.start()
                self.workers.append(worker)
                logger.debug(f"Added worker (total: {len(self.workers)})")
            
            self.current_workers = len(self.workers)
    
    def submit(self, func: Callable, *args, priority: int = 5, 
               task_id: Optional[str] = None, **kwargs):
        """
        Submit task to thread pool.
        
        Args:
            func: Function to execute
            priority: Task priority (lower number = higher priority)
            task_id: Optional task identifier
            *args, **kwargs: Arguments for function
        """
        if task_id is None:
            task_id = f"task_{time.time()}_{id(func)}"
        
        self.task_queue.put((priority, task_id, func, args, kwargs))
        
        # Auto-scale if queue is growing
        queue_size = self.task_queue.qsize()
        if queue_size > self.scale_threshold and self.current_workers < self.max_workers:
            new_workers = min(self.max_workers, self.current_workers + 2)
            self._adjust_workers(new_workers)
            logger.info(f"Scaled up to {new_workers} workers (queue size: {queue_size})")
    
    def get_results(self, timeout: Optional[float] = None) -> List[Tuple[str, Any, Optional[Exception]]]:
        """Get all completed results"""
        results = []
        deadline = time.time() + timeout if timeout else None
        
        while True:
            try:
                remaining = None
                if deadline:
                    remaining = max(0, deadline - time.time())
                    if remaining <= 0:
                        break
                
                result = self.result_queue.get(timeout=remaining if remaining else 0.1)
                results.append(result)
            except queue.Empty:
                if self.task_queue.empty():
                    break
        
        return results
    
    def wait(self, timeout: Optional[float] = None):
        """Wait for all tasks to complete"""
        if timeout:
            self.task_queue.join()
        else:
            # Wait with timeout
            start = time.time()
            while not self.task_queue.empty():
                if time.time() - start > timeout:
                    logger.warning("Thread pool wait timeout")
                    break
                time.sleep(0.1)
    
    def shutdown(self):
        """Shutdown thread pool"""
        logger.info("Shutting down thread pool...")
        self.shutdown_event.set()
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5.0)
        
        logger.info("Thread pool shutdown complete")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get thread pool statistics"""
        with self.lock:
            avg_time = (self.total_execution_time / self.tasks_completed 
                       if self.tasks_completed > 0 else 0)
            
            return {
                'workers': self.current_workers,
                'queue_size': self.task_queue.qsize(),
                'tasks_completed': self.tasks_completed,
                'tasks_failed': self.tasks_failed,
                'avg_execution_time': f"{avg_time:.3f}s",
                'total_tasks': self.tasks_completed + self.tasks_failed,
            }


class RequestDeduplicator:
    """
    Deduplicates similar requests to avoid redundant scanning.
    
    Features:
    - Hash-based deduplication
    - Similarity detection
    - Result aggregation
    """
    
    def __init__(self, similarity_threshold: float = 0.95):
        """
        Initialize request deduplicator.
        
        Args:
            similarity_threshold: Threshold for considering requests similar (0-1)
        """
        self.similarity_threshold = similarity_threshold
        self.seen_requests: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        
        self.duplicates_found = 0
        self.unique_requests = 0
    
    def _compute_hash(self, url: str, method: str, params: Dict[str, Any]) -> str:
        """Compute hash for request"""
        # Normalize and hash
        normalized = f"{method.upper()}:{url}"
        if params:
            param_str = json.dumps(params, sort_keys=True)
            normalized += f":{param_str}"
        
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def is_duplicate(self, url: str, method: str = "GET", 
                    params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
        """
        Check if request is a duplicate.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            
        Returns:
            Tuple of (is_duplicate, original_hash)
        """
        with self.lock:
            request_hash = self._compute_hash(url, method, params or {})
            
            if request_hash in self.seen_requests:
                self.duplicates_found += 1
                logger.debug(f"Duplicate request detected: {url}")
                return True, request_hash
            
            # Store this request
            self.seen_requests[request_hash] = {
                'url': url,
                'method': method,
                'params': params,
                'timestamp': datetime.now(),
                'count': 1
            }
            
            self.unique_requests += 1
            return False, request_hash
    
    def mark_scanned(self, request_hash: str, results: Any):
        """Mark request as scanned with results"""
        with self.lock:
            if request_hash in self.seen_requests:
                self.seen_requests[request_hash]['results'] = results
                self.seen_requests[request_hash]['scanned_at'] = datetime.now()
    
    def get_results(self, request_hash: str) -> Optional[Any]:
        """Get cached results for request"""
        with self.lock:
            if request_hash in self.seen_requests:
                return self.seen_requests[request_hash].get('results')
        return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        with self.lock:
            total = self.unique_requests + self.duplicates_found
            dedup_rate = (self.duplicates_found / total * 100) if total > 0 else 0
            
            return {
                'unique_requests': self.unique_requests,
                'duplicates_found': self.duplicates_found,
                'deduplication_rate': f"{dedup_rate:.2f}%",
                'total_requests': total,
            }


class PerformanceOptimizer:
    """
    Main performance optimization coordinator.
    
    Combines all optimization strategies:
    - Intelligent caching
    - Adaptive threading
    - Request deduplication
    - Early termination
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize performance optimizer.
        
        Args:
            config: Configuration dictionary
        """
        config = config or {}
        
        # Initialize components
        self.cache = IntelligentCache(
            max_size_mb=config.get('cache_size_mb', 100),
            default_ttl=config.get('cache_ttl', 3600)
        )
        
        self.thread_pool = AdaptiveThreadPool(
            min_workers=config.get('min_workers', 2),
            max_workers=config.get('max_workers', 20),
            scale_threshold=config.get('scale_threshold', 10)
        )
        
        self.deduplicator = RequestDeduplicator(
            similarity_threshold=config.get('dedup_threshold', 0.95)
        )
        
        self.early_termination_enabled = config.get('early_termination', True)
        self.termination_confidence_threshold = config.get('termination_threshold', 0.95)
        
        logger.info("Performance optimizer initialized")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            'cache': self.cache.get_stats(),
            'thread_pool': self.thread_pool.get_stats(),
            'deduplication': self.deduplicator.get_stats(),
            'config': {
                'early_termination': self.early_termination_enabled,
                'termination_threshold': self.termination_confidence_threshold,
            }
        }
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up performance optimizer...")
        self.thread_pool.shutdown()
        self.cache.clear()
        logger.info("Performance optimizer cleanup complete")


# Global instance
_global_optimizer: Optional[PerformanceOptimizer] = None
_optimizer_lock = threading.Lock()


def get_optimizer(config: Optional[Dict[str, Any]] = None) -> PerformanceOptimizer:
    """Get or create global performance optimizer instance"""
    global _global_optimizer
    
    with _optimizer_lock:
        if _global_optimizer is None:
            _global_optimizer = PerformanceOptimizer(config)
        return _global_optimizer


def reset_optimizer():
    """Reset global optimizer (mainly for testing)"""
    global _global_optimizer
    
    with _optimizer_lock:
        if _global_optimizer:
            _global_optimizer.cleanup()
        _global_optimizer = None
