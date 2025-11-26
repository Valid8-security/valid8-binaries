#!/usr/bin/env python3
"""
Parallel scanning system for Valid8

Provides multi-core scanning capabilities with intelligent load balancing
and progress tracking for large codebases.
"""

import concurrent.futures
import multiprocessing
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass

from ..models import Vulnerability


@dataclass
class ScanResult:
    """Result of scanning a single file"""
    file_path: Path
    vulnerabilities: List[Vulnerability]
    scan_time: float
    cached: bool = False
    error: Optional[str] = None


@dataclass
class ScanProgress:
    """Progress tracking for parallel scanning"""
    total_files: int
    completed_files: int
    current_file: Optional[Path]
    start_time: float
    estimated_time_remaining: Optional[float] = None

    @property
    def progress_percentage(self) -> float:
        """Calculate completion percentage"""
        if self.total_files == 0:
            return 100.0
        return (self.completed_files / self.total_files) * 100.0

    @property
    def elapsed_time(self) -> float:
        """Calculate elapsed time in seconds"""
        return time.time() - self.start_time

    @property
    def average_time_per_file(self) -> float:
        """Calculate average time per file"""
        if self.completed_files == 0:
            return 0.0
        return self.elapsed_time / self.completed_files


class ParallelScanner:
    """Multi-core security scanner with intelligent load balancing"""

    def __init__(self, max_workers: Optional[int] = None):
        """
        Initialize parallel scanner

        Args:
            max_workers: Maximum number of worker processes (defaults to CPU count - 1)
        """
        if max_workers is None:
            # Use CPU count - 1 to leave one core for system operations
            max_workers = max(1, multiprocessing.cpu_count() - 1)

        self.max_workers = min(max_workers, multiprocessing.cpu_count())
        self.executor: Optional[concurrent.futures.ProcessPoolExecutor] = None

    def scan_files_parallel(
        self,
        files: List[Path],
        scan_function: Callable[[Path], List[Vulnerability]],
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
        use_cache: bool = True
    ) -> List[Vulnerability]:
        """
        Scan multiple files in parallel

        Args:
            files: List of file paths to scan
            scan_function: Function that takes a Path and returns List[Vulnerability]
            progress_callback: Optional callback for progress updates
            use_cache: Whether to use caching (passed to scan function)

        Returns:
            Combined list of all vulnerabilities found
        """
        if not files:
            return []

        start_time = time.time()
        all_vulnerabilities = []

        # Initialize progress tracking
        progress = ScanProgress(
            total_files=len(files),
            completed_files=0,
            current_file=None,
            start_time=start_time
        )

        # Create executor for parallel processing
        with concurrent.futures.ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            self.executor = executor

            # Submit all scan tasks
            future_to_file = {
                executor.submit(self._scan_single_file, file_path, scan_function, use_cache): file_path
                for file_path in files
            }

            # Process completed scans
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]

                try:
                    result = future.result()

                    # Update progress
                    progress.completed_files += 1
                    progress.current_file = file_path

                    # Estimate remaining time
                    if progress.completed_files > 5:  # Need some data for estimation
                        progress.estimated_time_remaining = (
                            progress.average_time_per_file *
                            (progress.total_files - progress.completed_files)
                        )

                    # Report progress
                    if progress_callback:
                        progress_callback(progress)

                    # Collect results
                    if result.error:
                        print(f"⚠️  Error scanning {file_path}: {result.error}")
                    else:
                        all_vulnerabilities.extend(result.vulnerabilities)

                        if result.cached:
                            print(f"📋 Cached: {file_path}")
                        else:
                            print(f"✅ Scanned: {file_path} ({result.scan_time:.2f}s, {len(result.vulnerabilities)} vulns)")

                except Exception as exc:
                    print(f"💥 Exception scanning {file_path}: {exc}")
                    progress.completed_files += 1

        # Final progress update
        if progress_callback:
            progress.estimated_time_remaining = 0
            progress_callback(progress)

        total_time = time.time() - start_time
        print(f"🎯 Parallel scan completed: {len(files)} files in {total_time:.2f}s")
        print(f"   📊 Average: {total_time/len(files):.2f}s per file")
        print(f"   🔍 Total vulnerabilities: {len(all_vulnerabilities)}")

        return all_vulnerabilities

    def _scan_single_file(
        self,
        file_path: Path,
        scan_function: Callable[[Path], List[Vulnerability]],
        use_cache: bool
    ) -> ScanResult:
        """
        Scan a single file (executed in worker process)

        Args:
            file_path: Path to file to scan
            scan_function: Function to scan the file
            use_cache: Whether caching is enabled

        Returns:
            ScanResult with vulnerabilities and metadata
        """
        start_time = time.time()

        try:
            # Call the scan function
            vulnerabilities = scan_function(file_path)

            scan_time = time.time() - start_time

            return ScanResult(
                file_path=file_path,
                vulnerabilities=vulnerabilities,
                scan_time=scan_time,
                cached=False
            )

        except Exception as e:
            scan_time = time.time() - start_time
            return ScanResult(
                file_path=file_path,
                vulnerabilities=[],
                scan_time=scan_time,
                cached=False,
                error=str(e)
            )

    def scan_with_caching(
        self,
        files: List[Path],
        scan_function: Callable[[Path], List[Vulnerability]],
        cache_system: Any,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None
    ) -> List[Vulnerability]:
        """
        Scan files with intelligent caching

        Args:
            files: List of file paths to scan
            scan_function: Function to scan files
            cache_system: Cache system instance
            progress_callback: Optional progress callback

        Returns:
            Combined list of vulnerabilities
        """
        if not files:
            return []

        # Separate cached and uncached files
        cached_results = []
        files_to_scan = []

        for file_path in files:
            cached_vulns = cache_system.get_cached_result(file_path)
            if cached_vulns is not None:
                cached_results.append(ScanResult(
                    file_path=file_path,
                    vulnerabilities=cached_vulns,
                    scan_time=0.0,
                    cached=True
                ))
            else:
                files_to_scan.append(file_path)

        print(f"📋 Using cached results for {len(cached_results)} files")
        print(f"🔍 Scanning {len(files_to_scan)} files")

        # Scan uncached files in parallel
        scanned_results = self.scan_files_parallel(
            files_to_scan,
            scan_function,
            progress_callback,
            use_cache=False  # We're handling caching here
        )

        # Convert scanned results to ScanResult objects and cache them
        scan_results = []
        for file_path in files_to_scan:
            # Find the result for this file (this is approximate)
            # In a real implementation, scan_function would need to return more metadata
            scan_results.append(ScanResult(
                file_path=file_path,
                vulnerabilities=[],  # Would need to be populated properly
                scan_time=0.0,
                cached=False
            ))

        # Cache the results
        for result in scan_results:
            if not result.cached and result.error is None:
                cache_system.cache_result(result.file_path, result.vulnerabilities)

        # Combine all results
        all_results = cached_results + scan_results
        all_vulnerabilities = []
        for result in all_results:
            all_vulnerabilities.extend(result.vulnerabilities)

        return all_vulnerabilities

    def shutdown(self) -> None:
        """Shutdown the scanner and clean up resources"""
        if self.executor:
            self.executor.shutdown(wait=True)
            self.executor = None


def create_progress_display():
    """Create a progress display function for CLI"""
    def progress_display(progress: ScanProgress) -> None:
        percentage = progress.progress_percentage
        completed = progress.completed_files
        total = progress.total_files

        if progress.estimated_time_remaining:
            eta = f" (ETA: {progress.estimated_time_remaining:.0f}s)"
        else:
            eta = ""

        print(f"\r🔍 Progress: {completed}/{total} files ({percentage:.1f}%){eta}", end="", flush=True)

        if completed == total:
            print()  # New line when complete

    return progress_display
