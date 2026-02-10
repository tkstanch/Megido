"""
Parallel Execution Engine for SQL Injection Testing

Provides concurrent testing capabilities to dramatically improve scan speed
while maintaining accuracy and respecting rate limits.
"""

import asyncio
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
import threading
import queue
import time
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    """Execution mode for parallel testing"""
    SEQUENTIAL = "sequential"  # One at a time
    THREADED = "threaded"      # Thread pool
    ASYNC = "async"            # Async/await
    HYBRID = "hybrid"          # Mix of threaded and async


@dataclass
class TestTask:
    """Represents a single test task"""
    task_id: str
    payload: str
    parameter: str
    param_type: str  # GET, POST, etc.
    priority: int = 5  # 1-10, higher = more important
    callback: Optional[Callable] = None
    context: Dict[str, Any] = None


@dataclass
class TestResult:
    """Result of a test task"""
    task_id: str
    success: bool
    vulnerable: bool = False
    response: Any = None
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = None


class ParallelExecutionEngine:
    """
    Advanced parallel execution engine for SQL injection testing.
    Supports multiple execution modes with intelligent task scheduling.
    """
    
    def __init__(self, max_workers: int = 5, mode: ExecutionMode = ExecutionMode.THREADED,
                 rate_limit: int = 20, respect_server: bool = True):
        """
        Initialize parallel execution engine.
        
        Args:
            max_workers: Maximum number of concurrent workers
            mode: Execution mode (threaded, async, hybrid)
            rate_limit: Maximum requests per minute
            respect_server: Whether to respect server resources
        """
        self.max_workers = max_workers
        self.mode = mode
        self.rate_limit = rate_limit
        self.respect_server = respect_server
        
        # Task management
        self.task_queue = queue.PriorityQueue()
        self.results = []
        self.active_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        
        # Rate limiting
        self.request_times = []
        self.rate_lock = threading.Lock()
        
        # Thread pool
        self.executor = None
        self.shutdown_event = threading.Event()
        
        logger.info(f"Parallel execution engine initialized: mode={mode.value}, workers={max_workers}")
    
    def submit_task(self, task: TestTask):
        """
        Submit a task for parallel execution.
        
        Args:
            task: TestTask to execute
        """
        # Priority queue uses (priority, item), lower priority number = higher priority
        # Invert priority so higher numbers run first
        self.task_queue.put((10 - task.priority, task))
        logger.debug(f"Task submitted: {task.task_id} (priority: {task.priority})")
    
    def submit_batch(self, tasks: List[TestTask]):
        """
        Submit multiple tasks at once.
        
        Args:
            tasks: List of TestTask objects
        """
        for task in tasks:
            self.submit_task(task)
        logger.info(f"Batch submitted: {len(tasks)} tasks")
    
    def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        if self.rate_limit <= 0:
            return  # No rate limiting
        
        with self.rate_lock:
            now = time.time()
            # Remove requests older than 60 seconds
            self.request_times = [t for t in self.request_times if now - t < 60]
            
            # Check if we've hit the limit
            if len(self.request_times) >= self.rate_limit:
                # Calculate wait time
                oldest = min(self.request_times)
                wait_time = 60 - (now - oldest)
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                    time.sleep(wait_time)
            
            # Record this request
            self.request_times.append(time.time())
    
    def _execute_task_sync(self, task: TestTask, test_func: Callable) -> TestResult:
        """
        Execute a single task synchronously.
        
        Args:
            task: TestTask to execute
            test_func: Function to execute (takes task, returns result)
        
        Returns:
            TestResult
        """
        start_time = time.time()
        
        try:
            # Check rate limit
            self._check_rate_limit()
            
            # Execute the test function
            result = test_func(task)
            
            execution_time = time.time() - start_time
            
            return TestResult(
                task_id=task.task_id,
                success=True,
                vulnerable=result.get('vulnerable', False) if isinstance(result, dict) else False,
                response=result.get('response') if isinstance(result, dict) else result,
                execution_time=execution_time,
                metadata=result.get('metadata', {}) if isinstance(result, dict) else {}
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Task {task.task_id} failed: {e}")
            
            return TestResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                execution_time=execution_time
            )
    
    def execute_parallel_threaded(self, test_func: Callable, timeout: int = 300) -> List[TestResult]:
        """
        Execute tasks in parallel using thread pool.
        
        Args:
            test_func: Function to execute for each task
            timeout: Maximum time to wait for all tasks
        
        Returns:
            List of TestResult objects
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            # Submit all tasks
            while not self.task_queue.empty():
                try:
                    _, task = self.task_queue.get_nowait()
                    future = executor.submit(self._execute_task_sync, task, test_func)
                    futures[future] = task
                    self.active_tasks += 1
                except queue.Empty:
                    break
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                task = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.completed_tasks += 1
                    
                    # Call callback if provided
                    if task.callback:
                        task.callback(result)
                    
                    logger.debug(f"Task completed: {task.task_id} ({self.completed_tasks} total)")
                
                except Exception as e:
                    logger.error(f"Task {task.task_id} failed with exception: {e}")
                    self.failed_tasks += 1
                    results.append(TestResult(
                        task_id=task.task_id,
                        success=False,
                        error=str(e)
                    ))
                
                finally:
                    self.active_tasks -= 1
        
        logger.info(f"Parallel execution complete: {self.completed_tasks} succeeded, {self.failed_tasks} failed")
        return results
    
    async def _execute_task_async(self, task: TestTask, test_func: Callable) -> TestResult:
        """
        Execute a single task asynchronously.
        
        Args:
            task: TestTask to execute
            test_func: Async function to execute
        
        Returns:
            TestResult
        """
        start_time = time.time()
        
        try:
            # Check rate limit (sync operation in async context)
            self._check_rate_limit()
            
            # Execute async function
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func(task)
            else:
                # Run sync function in executor
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, test_func, task)
            
            execution_time = time.time() - start_time
            
            return TestResult(
                task_id=task.task_id,
                success=True,
                vulnerable=result.get('vulnerable', False) if isinstance(result, dict) else False,
                response=result.get('response') if isinstance(result, dict) else result,
                execution_time=execution_time,
                metadata=result.get('metadata', {}) if isinstance(result, dict) else {}
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Async task {task.task_id} failed: {e}")
            
            return TestResult(
                task_id=task.task_id,
                success=False,
                error=str(e),
                execution_time=execution_time
            )
    
    async def execute_parallel_async(self, test_func: Callable) -> List[TestResult]:
        """
        Execute tasks in parallel using asyncio.
        
        Args:
            test_func: Async function to execute for each task
        
        Returns:
            List of TestResult objects
        """
        tasks = []
        
        # Extract all tasks from queue
        while not self.task_queue.empty():
            try:
                _, task = self.task_queue.get_nowait()
                tasks.append(task)
            except queue.Empty:
                break
        
        # Create coroutines
        coroutines = [self._execute_task_async(task, test_func) for task in tasks]
        
        # Execute with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def bounded_task(coro):
            async with semaphore:
                return await coro
        
        # Execute all tasks
        results = await asyncio.gather(*[bounded_task(coro) for coro in coroutines], return_exceptions=False)
        
        logger.info(f"Async execution complete: {len(results)} tasks")
        return results
    
    def execute_sequential(self, test_func: Callable) -> List[TestResult]:
        """
        Execute tasks sequentially (for comparison/debugging).
        
        Args:
            test_func: Function to execute for each task
        
        Returns:
            List of TestResult objects
        """
        results = []
        
        while not self.task_queue.empty():
            try:
                _, task = self.task_queue.get_nowait()
                result = self._execute_task_sync(task, test_func)
                results.append(result)
                
                if task.callback:
                    task.callback(result)
            
            except queue.Empty:
                break
        
        logger.info(f"Sequential execution complete: {len(results)} tasks")
        return results
    
    def execute(self, test_func: Callable) -> List[TestResult]:
        """
        Execute tasks based on configured mode.
        
        Args:
            test_func: Function to execute for each task
        
        Returns:
            List of TestResult objects
        """
        if self.mode == ExecutionMode.SEQUENTIAL:
            return self.execute_sequential(test_func)
        
        elif self.mode == ExecutionMode.THREADED:
            return self.execute_parallel_threaded(test_func)
        
        elif self.mode == ExecutionMode.ASYNC:
            # Run async in new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(self.execute_parallel_async(test_func))
                return results
            finally:
                loop.close()
        
        elif self.mode == ExecutionMode.HYBRID:
            # For hybrid mode, use threaded for now (can be enhanced)
            return self.execute_parallel_threaded(test_func)
        
        else:
            raise ValueError(f"Unknown execution mode: {self.mode}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        total = self.completed_tasks + self.failed_tasks
        success_rate = (self.completed_tasks / total * 100) if total > 0 else 0
        
        return {
            'total_tasks': total,
            'completed': self.completed_tasks,
            'failed': self.failed_tasks,
            'active': self.active_tasks,
            'queued': self.task_queue.qsize(),
            'success_rate': success_rate,
            'mode': self.mode.value,
            'max_workers': self.max_workers,
            'rate_limit': self.rate_limit,
        }
    
    def clear_queue(self):
        """Clear all pending tasks"""
        while not self.task_queue.empty():
            try:
                self.task_queue.get_nowait()
            except queue.Empty:
                break
        logger.info("Task queue cleared")
    
    def shutdown(self):
        """Shutdown the execution engine"""
        self.shutdown_event.set()
        self.clear_queue()
        if self.executor:
            self.executor.shutdown(wait=False)
        logger.info("Parallel execution engine shutdown")


class SmartTaskScheduler:
    """
    Intelligent task scheduler that prioritizes tests based on likelihood of success.
    """
    
    def __init__(self):
        self.success_patterns = {}  # Track which payloads/params work
        self.failure_patterns = {}  # Track which fail consistently
    
    def prioritize_tasks(self, tasks: List[TestTask]) -> List[TestTask]:
        """
        Prioritize tasks based on historical success patterns.
        
        Args:
            tasks: List of tasks to prioritize
        
        Returns:
            Sorted list with highest priority first
        """
        def get_priority_score(task: TestTask) -> float:
            """Calculate priority score for a task"""
            base_score = task.priority
            
            # Boost score if similar tasks succeeded before
            pattern_key = f"{task.parameter}:{task.param_type}"
            if pattern_key in self.success_patterns:
                base_score += 2
            
            # Reduce score if similar tasks failed consistently
            if pattern_key in self.failure_patterns:
                failures = self.failure_patterns[pattern_key]
                if failures > 5:
                    base_score -= 1
            
            return base_score
        
        # Sort by priority score (descending)
        sorted_tasks = sorted(tasks, key=get_priority_score, reverse=True)
        return sorted_tasks
    
    def record_result(self, task: TestTask, result: TestResult):
        """Record task result for future prioritization"""
        pattern_key = f"{task.parameter}:{task.param_type}"
        
        if result.success and result.vulnerable:
            # Record success
            if pattern_key not in self.success_patterns:
                self.success_patterns[pattern_key] = 0
            self.success_patterns[pattern_key] += 1
        
        elif not result.success or (result.success and not result.vulnerable):
            # Record failure
            if pattern_key not in self.failure_patterns:
                self.failure_patterns[pattern_key] = 0
            self.failure_patterns[pattern_key] += 1
