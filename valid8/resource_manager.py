"""
Smart Resource Management System
Adapts processing based on system resources and user preferences
"""

from __future__ import annotations

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class ProcessingMode(Enum):
    """Different processing modes based on system capabilities"""
    LIGHTWEIGHT = "lightweight"      # Low resource usage, slower processing
    BALANCED = "balanced"           # Moderate resource usage, good performance
    PERFORMANCE = "performance"     # High resource usage, maximum speed
    ADAPTIVE = "adaptive"          # Automatically adjust based on system load


@dataclass
class SystemResources:
    """Current system resource availability"""
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    disk_available_mb: float
    cpu_count: int
    load_average: Optional[List[float]] = None

    @property
    def resource_score(self) -> float:
        """Calculate overall resource availability score (0-1, higher is better)"""
        cpu_score = max(0, 1 - (self.cpu_percent / 100))
        memory_score = max(0, 1 - (self.memory_percent / 100))
        return (cpu_score + memory_score) / 2


@dataclass
class ProcessingConfiguration:
    """Dynamic processing configuration"""
    max_workers: int
    chunk_size_mb: int
    enable_streaming: bool
    enable_caching: bool
    ai_model_complexity: str  # "low", "medium", "high"
    file_size_limit_mb: int
    mode: ProcessingMode


class ResourceManager:
    """Smart resource management and adaptive processing"""

    def __init__(self):
        self._lock = threading.Lock()
        self._current_config = self._get_default_config()
        self._system_baseline = self._measure_system_resources()
        self._adaptive_enabled = True

    def _get_default_config(self) -> ProcessingConfiguration:
        """Get default processing configuration"""
        return ProcessingConfiguration(
            max_workers=2,
            chunk_size_mb=8,
            enable_streaming=True,
            enable_caching=True,
            ai_model_complexity="medium",
            file_size_limit_mb=50,
            mode=ProcessingMode.BALANCED
        )

    def _measure_system_resources(self) -> SystemResources:
        """Measure current system resource availability"""
        if not PSUTIL_AVAILABLE:
            # Fallback values when psutil is not available
            return SystemResources(
                cpu_percent=50.0,  # Assume moderate CPU usage
                memory_percent=60.0,  # Assume moderate memory usage
                memory_available_mb=2048,  # Assume 2GB available
                disk_available_mb=10240,  # Assume 10GB available
                cpu_count=4,  # Assume 4 CPU cores
                load_average=None
            )

        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return SystemResources(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_available_mb=memory.available / (1024 * 1024),
            disk_available_mb=disk.free / (1024 * 1024),
            cpu_count=psutil.cpu_count() or 1,
            load_average=self._get_load_average()
        )

    def _get_load_average(self) -> Optional[List[float]]:
        """Get system load average if available"""
        if not PSUTIL_AVAILABLE:
            return None

        try:
            return list(psutil.getloadavg())
        except (AttributeError, OSError):
            # Not available on Windows
            return None

    def get_optimal_configuration(self, user_mode: Optional[ProcessingMode] = None) -> ProcessingConfiguration:
        """Calculate optimal processing configuration based on system resources and user preferences"""

        with self._lock:
            resources = self._measure_system_resources()
            mode = user_mode or ProcessingMode.ADAPTIVE

            if mode == ProcessingMode.ADAPTIVE:
                mode = self._determine_adaptive_mode(resources)

            config = ProcessingConfiguration(
                mode=mode,
                **self._calculate_mode_settings(mode, resources)
            )

            self._current_config = config
            return config

    def _determine_adaptive_mode(self, resources: SystemResources) -> ProcessingMode:
        """Determine the best processing mode based on current resources"""

        resource_score = resources.resource_score

        # High resource availability → Performance mode
        if resource_score > 0.8 and resources.memory_available_mb > 4096:
            return ProcessingMode.PERFORMANCE

        # Moderate resources → Balanced mode
        elif resource_score > 0.5 and resources.memory_available_mb > 2048:
            return ProcessingMode.BALANCED

        # Limited resources → Lightweight mode
        else:
            return ProcessingMode.LIGHTWEIGHT

    def _calculate_mode_settings(self, mode: ProcessingMode, resources: SystemResources) -> Dict[str, Any]:
        """Calculate specific settings for each processing mode"""

        base_workers = min(resources.cpu_count, 8)  # Cap at 8 workers

        if mode == ProcessingMode.LIGHTWEIGHT:
            return {
                'max_workers': max(1, base_workers // 4),
                'chunk_size_mb': 4,
                'enable_streaming': True,
                'enable_caching': True,
                'ai_model_complexity': 'low',
                'file_size_limit_mb': 25
            }

        elif mode == ProcessingMode.BALANCED:
            return {
                'max_workers': max(1, base_workers // 2),
                'chunk_size_mb': 8,
                'enable_streaming': True,
                'enable_caching': True,
                'ai_model_complexity': 'medium',
                'file_size_limit_mb': 50
            }

        elif mode == ProcessingMode.PERFORMANCE:
            return {
                'max_workers': base_workers,
                'chunk_size_mb': 16,
                'enable_streaming': False,  # Process files in memory for speed
                'enable_caching': True,
                'ai_model_complexity': 'high',
                'file_size_limit_mb': 100
            }

        else:
            # Fallback to balanced
            return self._calculate_mode_settings(ProcessingMode.BALANCED, resources)

    def should_throttle(self) -> tuple[bool, str]:
        """Check if processing should be throttled due to resource constraints"""

        if not PSUTIL_AVAILABLE:
            # Without psutil, assume no throttling needed
            return False, ""

        resources = self._measure_system_resources()

        # Memory pressure
        if resources.memory_percent > 85:
            return True, f"High memory usage ({resources.memory_percent:.1f}%) - throttling processing"

        # CPU overload
        if resources.cpu_percent > 90:
            return True, f"High CPU usage ({resources.cpu_percent:.1f}%) - throttling processing"

        # Load average check (Unix systems)
        if resources.load_average and len(resources.load_average) >= 1:
            load_per_cpu = resources.load_average[0] / resources.cpu_count
            if load_per_cpu > 2.0:
                return True, f"High system load ({load_per_cpu:.1f} per CPU) - throttling processing"

        return False, ""

    def get_resource_report(self) -> Dict[str, Any]:
        """Generate detailed resource usage report"""

        resources = self._measure_system_resources()

        return {
            'current_resources': {
                'cpu_usage_percent': resources.cpu_percent,
                'memory_usage_percent': resources.memory_percent,
                'memory_available_mb': resources.memory_available_mb,
                'cpu_count': resources.cpu_count,
                'load_average': resources.load_average
            },
            'processing_config': {
                'mode': self._current_config.mode.value,
                'max_workers': self._current_config.max_workers,
                'ai_complexity': self._current_config.ai_model_complexity,
                'file_size_limit_mb': self._current_config.file_size_limit_mb
            },
            'recommendations': self._generate_recommendations(resources)
        }

    def _generate_recommendations(self, resources: SystemResources) -> List[str]:
        """Generate resource optimization recommendations"""

        recommendations = []

        if resources.memory_available_mb < 1024:
            recommendations.append("Consider upgrading RAM for better performance")

        if resources.cpu_count < 4:
            recommendations.append("Limited CPU cores - lightweight mode recommended")

        if resources.cpu_percent > 80:
            recommendations.append("High CPU usage - consider reducing concurrent processing")

        if resources.memory_percent > 80:
            recommendations.append("High memory usage - consider enabling more aggressive streaming")

        resource_score = resources.resource_score
        if resource_score < 0.3:
            recommendations.append("System resources limited - consider lightweight processing mode")
        elif resource_score > 0.8:
            recommendations.append("Excellent system resources - performance mode recommended")

        return recommendations

    def optimize_for_workload(self, file_count: int, avg_file_size_mb: float) -> ProcessingConfiguration:
        """Optimize configuration based on expected workload"""

        resources = self._measure_system_resources()

        # Large codebase optimization
        if file_count > 10000:
            # Reduce workers to prevent memory pressure
            optimal_workers = min(self._current_config.max_workers, max(1, resources.cpu_count // 2))
        else:
            optimal_workers = self._current_config.max_workers

        # Large file optimization
        if avg_file_size_mb > 10:
            # Enable streaming and reduce chunk size
            chunk_size = min(self._current_config.chunk_size_mb, 8)
            enable_streaming = True
        else:
            chunk_size = self._current_config.chunk_size_mb
            enable_streaming = self._current_config.enable_streaming

        return ProcessingConfiguration(
            max_workers=optimal_workers,
            chunk_size_mb=chunk_size,
            enable_streaming=enable_streaming,
            enable_caching=self._current_config.enable_caching,
            ai_model_complexity=self._current_config.ai_model_complexity,
            file_size_limit_mb=self._current_config.file_size_limit_mb,
            mode=self._current_config.mode
        )


# Global resource manager instance
resource_manager = ResourceManager()
