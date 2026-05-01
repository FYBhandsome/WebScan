import psutil
import platform
from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class ResourceUsage:
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    process_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResourceLimiter:
    def __init__(self):
        self._max_memory_percent = 90.0
        self._max_cpu_percent = 90.0
        self._max_concurrent = 5

    async def get_current_usage(self) -> ResourceUsage:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return ResourceUsage(
            cpu_percent=cpu,
            memory_percent=mem.percent,
            memory_used_gb=round(mem.used / (1024**3), 2),
            memory_total_gb=round(mem.total / (1024**3), 2),
            disk_percent=disk.percent,
            disk_used_gb=round(disk.used / (1024**3), 2),
            disk_total_gb=round(disk.total / (1024**3), 2),
            process_count=len(psutil.pids())
        )

    def get_statistics(self) -> Dict[str, Any]:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        return {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "platform": platform.platform(),
            "max_memory_percent": self._max_memory_percent,
            "max_cpu_percent": self._max_cpu_percent,
            "max_concurrent": self._max_concurrent,
        }

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent


_default_limiter: ResourceLimiter = None


def get_default_limiter() -> ResourceLimiter:
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = ResourceLimiter()
    return _default_limiter
