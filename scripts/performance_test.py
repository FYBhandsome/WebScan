"""
性能测试脚本

测试系统性能指标:
1. POC 执行性能 (单个和批量)
2. 缓存机制效果
3. 并发执行能力
"""

import asyncio
import json
import logging
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import statistics

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ai_agents.utils.cache import CacheManager
from backend.ai_agents.poc_system.poc_manager import POCManager, poc_manager
from backend.ai_agents.poc_system.verification_engine import VerificationEngine, ExecutionStats
from backend.config import settings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    name: str
    iterations: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    avg_time: float = 0.0
    std_dev: float = 0.0
    times: List[float] = field(default_factory=list)
    errors: int = 0
    success_rate: float = 0.0
    
    def add_result(self, execution_time: float, success: bool = True):
        self.iterations += 1
        if success:
            self.times.append(execution_time)
            self.total_time += execution_time
            self.min_time = min(self.min_time, execution_time)
            self.max_time = max(self.max_time, execution_time)
        else:
            self.errors += 1
    
    def calculate(self):
        if self.times:
            self.avg_time = self.total_time / len(self.times)
            if len(self.times) > 1:
                self.std_dev = statistics.stdev(self.times)
        if self.iterations > 0:
            self.success_rate = (self.iterations - self.errors) / self.iterations * 100
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "iterations": self.iterations,
            "total_time": round(self.total_time, 4),
            "min_time": round(self.min_time, 4) if self.min_time != float('inf') else 0,
            "max_time": round(self.max_time, 4),
            "avg_time": round(self.avg_time, 4),
            "std_dev": round(self.std_dev, 4),
            "errors": self.errors,
            "success_rate": round(self.success_rate, 2)
        }


@dataclass
class CacheMetrics:
    hits: int = 0
    misses: int = 0
    hit_rate: float = 0.0
    avg_hit_time: float = 0.0
    avg_miss_time: float = 0.0
    hit_times: List[float] = field(default_factory=list)
    miss_times: List[float] = field(default_factory=list)
    
    def add_hit(self, response_time: float):
        self.hits += 1
        self.hit_times.append(response_time)
    
    def add_miss(self, response_time: float):
        self.misses += 1
        self.miss_times.append(response_time)
    
    def calculate(self):
        total = self.hits + self.misses
        if total > 0:
            self.hit_rate = self.hits / total * 100
        if self.hit_times:
            self.avg_hit_time = statistics.mean(self.hit_times)
        if self.miss_times:
            self.avg_miss_time = statistics.mean(self.miss_times)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hit_rate, 2),
            "avg_hit_time": round(self.avg_hit_time, 4),
            "avg_miss_time": round(self.avg_miss_time, 4)
        }


@dataclass
class ConcurrencyMetrics:
    concurrent_tasks: int = 0
    total_time: float = 0.0
    throughput: float = 0.0
    avg_task_time: float = 0.0
    peak_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    task_times: List[float] = field(default_factory=list)
    
    def calculate(self):
        if self.total_time > 0 and self.concurrent_tasks > 0:
            self.throughput = self.concurrent_tasks / self.total_time
        if self.task_times:
            self.avg_task_time = statistics.mean(self.task_times)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "concurrent_tasks": self.concurrent_tasks,
            "total_time": round(self.total_time, 4),
            "throughput": round(self.throughput, 4),
            "avg_task_time": round(self.avg_task_time, 4),
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "avg_cpu_percent": round(self.avg_cpu_percent, 2)
        }


class PerformanceTestSuite:
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.cache_manager = CacheManager(ttl=3600)
        self.poc_manager = POCManager()
        
    async def run_all_tests(self):
        logger.info("=" * 60)
        logger.info("开始性能测试套件")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        await self.test_cache_performance()
        
        await self.test_poc_manager_performance()
        
        await self.test_concurrent_cache_access()
        
        await self.test_cache_memory_usage()
        
        total_time = time.time() - start_time
        
        self.results["summary"] = {
            "total_test_time": round(total_time, 4),
            "test_count": len(self.results) - 1,
            "timestamp": datetime.now().isoformat()
        }
        
        self._save_results()
        self._print_summary()
    
    async def test_cache_performance(self):
        logger.info("\n" + "=" * 60)
        logger.info("测试 1: 缓存性能测试")
        logger.info("=" * 60)
        
        metrics = CacheMetrics()
        
        test_data = {
            "poc_code_1": "print('test poc 1')",
            "poc_code_2": "print('test poc 2')",
            "poc_code_3": "print('test poc 3')",
            "search_result_1": [{"name": "CVE-2023-1234", "severity": "high"}],
            "search_result_2": [{"name": "CVE-2023-5678", "severity": "medium"}],
        }
        
        logger.info("阶段 1: 缓存写入测试 (冷启动)")
        for key, data in test_data.items():
            start = time.perf_counter()
            self.cache_manager.set(key, data)
            elapsed = time.perf_counter() - start
            metrics.add_miss(elapsed)
            logger.info(f"  写入 {key}: {elapsed*1000:.4f} ms")
        
        metrics.miss_times.clear()
        metrics.misses = 0
        
        logger.info("\n阶段 2: 缓存读取测试 (热缓存)")
        for _ in range(5):
            for key in test_data.keys():
                start = time.perf_counter()
                result = self.cache_manager.get(key)
                elapsed = time.perf_counter() - start
                
                if result is not None:
                    metrics.add_hit(elapsed)
                else:
                    metrics.add_miss(elapsed)
        
        logger.info("\n阶段 3: 缓存未命中测试")
        for i in range(20):
            key = f"nonexistent_key_{i}"
            start = time.perf_counter()
            result = self.cache_manager.get(key)
            elapsed = time.perf_counter() - start
            metrics.add_miss(elapsed)
        
        metrics.calculate()
        
        stats = self.cache_manager.get_stats()
        
        self.results["cache_performance"] = {
            "metrics": metrics.to_dict(),
            "cache_stats": stats
        }
        
        logger.info(f"\n缓存性能结果:")
        logger.info(f"  命中率: {metrics.hit_rate:.2f}%")
        logger.info(f"  平均命中时间: {metrics.avg_hit_time*1000:.4f} ms")
        logger.info(f"  平均未命中时间: {metrics.avg_miss_time*1000:.4f} ms")
        logger.info(f"  缓存条目数: {stats['cache_entries']}")
        
        return metrics
    
    async def test_poc_manager_performance(self):
        logger.info("\n" + "=" * 60)
        logger.info("测试 2: POC 管理器性能测试")
        logger.info("=" * 60)
        
        metrics = PerformanceMetrics(name="poc_manager_operations")
        
        logger.info("阶段 1: POC 元数据操作")
        
        poc_ids = []
        for i in range(100):
            start = time.perf_counter()
            poc_id = f"test_poc_{i}"
            self.poc_manager.register_dynamic_poc(poc_id, f"# Test POC {i}\nprint('test')")
            elapsed = time.perf_counter() - start
            metrics.add_result(elapsed)
            poc_ids.append(poc_id)
        
        logger.info(f"  注册 100 个动态 POC: {metrics.avg_time*1000:.4f} ms 平均")
        
        search_metrics = PerformanceMetrics(name="poc_search")
        for keyword in ["test", "poc", "web", "CVE", "sql"]:
            start = time.perf_counter()
            results = self.poc_manager.search_pocs(keyword)
            elapsed = time.perf_counter() - start
            search_metrics.add_result(elapsed)
            logger.info(f"  搜索 '{keyword}': {elapsed*1000:.4f} ms, 找到 {len(results)} 个结果")
        
        search_metrics.calculate()
        
        stats = self.poc_manager.get_poc_statistics()
        
        self.results["poc_manager_performance"] = {
            "registration_metrics": metrics.to_dict(),
            "search_metrics": search_metrics.to_dict(),
            "statistics": stats
        }
        
        logger.info(f"\nPOC 管理器性能结果:")
        logger.info(f"  注册平均时间: {metrics.avg_time*1000:.4f} ms")
        logger.info(f"  搜索平均时间: {search_metrics.avg_time*1000:.4f} ms")
        logger.info(f"  总 POC 数量: {stats['total_count']}")
        
        return metrics
    
    async def test_concurrent_cache_access(self):
        logger.info("\n" + "=" * 60)
        logger.info("测试 3: 并发缓存访问测试")
        logger.info("=" * 60)
        
        concurrency_levels = [5, 10, 20]
        results = {}
        
        for level in concurrency_levels:
            logger.info(f"\n测试并发级别: {level}")
            metrics = ConcurrencyMetrics(concurrent_tasks=level)
            
            async def cache_operation(task_id: int):
                start = time.perf_counter()
                key = f"concurrent_test_{task_id % 10}"
                
                if task_id % 3 == 0:
                    self.cache_manager.set(key, {"data": f"test_data_{task_id}"})
                else:
                    self.cache_manager.get(key)
                
                elapsed = time.perf_counter() - start
                metrics.task_times.append(elapsed)
                return elapsed
            
            start_time = time.time()
            tasks = [cache_operation(i) for i in range(level * 10)]
            await asyncio.gather(*tasks)
            metrics.total_time = time.time() - start_time
            
            metrics.calculate()
            results[f"concurrency_{level}"] = metrics.to_dict()
            
            logger.info(f"  总时间: {metrics.total_time:.4f} s")
            logger.info(f"  吞吐量: {metrics.throughput:.4f} tasks/s")
            logger.info(f"  平均任务时间: {metrics.avg_task_time*1000:.4f} ms")
        
        self.results["concurrent_cache_access"] = results
        
        return results
    
    async def test_cache_memory_usage(self):
        logger.info("\n" + "=" * 60)
        logger.info("测试 4: 缓存内存使用测试")
        logger.info("=" * 60)
        
        import sys
        
        test_sizes = [100, 500, 1000, 2000]
        results = {}
        
        for size in test_sizes:
            temp_cache = CacheManager(ttl=3600)
            
            for i in range(size):
                key = f"memory_test_key_{i}"
                data = {
                    "poc_code": f"# POC {i}\n" + "print('test')\n" * 10,
                    "metadata": {
                        "name": f"Test POC {i}",
                        "severity": "high",
                        "description": "A" * 100
                    }
                }
                temp_cache.set(key, data)
            
            stats = temp_cache.get_stats()
            
            results[f"size_{size}"] = {
                "entries": stats["cache_entries"],
                "size_bytes": stats["cache_size_bytes"],
                "size_mb": stats["cache_size_mb"],
                "avg_entry_size": stats["cache_size_bytes"] / size if size > 0 else 0
            }
            
            logger.info(f"\n缓存大小 {size}:")
            logger.info(f"  条目数: {stats['cache_entries']}")
            logger.info(f"  内存使用: {stats['cache_size_mb']:.4f} MB")
            logger.info(f"  平均条目大小: {stats['cache_size_bytes'] / size:.2f} bytes")
        
        self.results["cache_memory_usage"] = results
        
        return results
    
    def _save_results(self):
        output_dir = Path(__file__).parent.parent / "test_reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"performance_test_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"\n结果已保存到: {output_file}")
    
    def _print_summary(self):
        logger.info("\n" + "=" * 60)
        logger.info("性能测试总结")
        logger.info("=" * 60)
        
        if "cache_performance" in self.results:
            cp = self.results["cache_performance"]["metrics"]
            logger.info(f"\n缓存性能:")
            logger.info(f"  命中率: {cp['hit_rate']}%")
            logger.info(f"  平均命中响应时间: {cp['avg_hit_time']*1000:.4f} ms")
            logger.info(f"  平均未命中响应时间: {cp['avg_miss_time']*1000:.4f} ms")
        
        if "poc_manager_performance" in self.results:
            pm = self.results["poc_manager_performance"]["registration_metrics"]
            logger.info(f"\nPOC 管理器性能:")
            logger.info(f"  注册平均时间: {pm['avg_time']*1000:.4f} ms")
            logger.info(f"  成功率: {pm['success_rate']}%")
        
        if "concurrent_cache_access" in self.results:
            logger.info(f"\n并发性能:")
            for level, data in self.results["concurrent_cache_access"].items():
                logger.info(f"  {level}: 吞吐量 {data['throughput']:.2f} tasks/s, "
                          f"平均时间 {data['avg_task_time']*1000:.4f} ms")
        
        if "cache_memory_usage" in self.results:
            logger.info(f"\n内存使用:")
            for size, data in self.results["cache_memory_usage"].items():
                logger.info(f"  {size} 条目: {data['size_mb']:.4f} MB")
        
        logger.info(f"\n总测试时间: {self.results['summary']['total_test_time']:.4f} s")


async def test_verification_engine_mock():
    logger.info("\n" + "=" * 60)
    logger.info("测试 5: 验证引擎模拟测试")
    logger.info("=" * 60)
    
    engine = VerificationEngine(max_concurrent=5)
    
    stats = engine.get_execution_statistics()
    logger.info(f"引擎统计: {stats.to_dict()}")
    
    queue_status = engine.get_queue_status()
    logger.info(f"队列状态: {queue_status}")
    
    cache_stats = await engine.get_cache_stats()
    logger.info(f"缓存统计: {cache_stats}")
    
    engine_stats = await engine.get_engine_statistics()
    logger.info(f"引擎完整统计: {json.dumps(engine_stats, indent=2, default=str)}")
    
    return {
        "execution_stats": stats.to_dict(),
        "queue_status": queue_status,
        "cache_stats": cache_stats,
        "engine_stats": engine_stats
    }


async def main():
    test_suite = PerformanceTestSuite()
    await test_suite.run_all_tests()
    
    engine_results = await test_verification_engine_mock()
    test_suite.results["verification_engine"] = engine_results
    
    test_suite._save_results()


if __name__ == "__main__":
    asyncio.run(main())
