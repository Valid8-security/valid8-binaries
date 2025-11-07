"""
🚀 PERFORMANCE OPTIMIZATION: Streaming file processor
Memory-efficient file analysis with early termination and chunked processing
"""

import mmap
import os
from pathlib import Path
from typing import List, Callable, Any, Optional
from dataclasses import dataclass


@dataclass
class ProcessingResult:
    """Result of streaming file processing"""
    vulnerabilities: List[Any]
    processed_bytes: int
    early_termination: bool
    termination_reason: Optional[str] = None


class StreamingFileProcessor:
    """
    🚀 MEMORY OPTIMIZATION: Process files in streams/chunks
    Avoids loading entire files into memory for better performance
    """

    def __init__(self, chunk_size: int = 8192, max_file_size: int = 10*1024*1024):
        """
        Initialize streaming processor

        Args:
            chunk_size: Size of chunks to process (8KB default)
            max_file_size: Maximum file size to process (10MB default)
        """
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size

    def process_file_streaming(
        self,
        file_path: Path,
        analyzer_func: Callable[[str, Path, int], List[Any]],
        early_exit_threshold: int = 10
    ) -> ProcessingResult:
        """
        Process file in streaming chunks with early termination

        Args:
            file_path: Path to file to analyze
            analyzer_func: Function to analyze chunks (text, path, offset) -> vulnerabilities
            early_exit_threshold: Stop if this many vulnerabilities found

        Returns:
            ProcessingResult with vulnerabilities and metadata
        """
        vulnerabilities = []
        processed_bytes = 0
        early_termination = False
        termination_reason = None

        try:
            # Check file size first
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return ProcessingResult(
                    vulnerabilities=[],
                    processed_bytes=0,
                    early_termination=True,
                    termination_reason=f"File too large ({file_size} > {self.max_file_size})"
                )

            # Use memory mapping for efficient reading
            with open(file_path, 'r+b' if file_size > 0 else 'rb') as f:
                if file_size == 0:
                    return ProcessingResult([], 0, False)

                # Memory map the file for efficient access
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    offset = 0

                    while offset < file_size:
                        # Calculate chunk size
                        remaining = file_size - offset
                        chunk_bytes = min(self.chunk_size, remaining)

                        # Extract chunk as string
                        chunk_data = mm[offset:offset + chunk_bytes]
                        try:
                            chunk_text = chunk_data.decode('utf-8', errors='ignore')
                        except UnicodeDecodeError:
                            # Binary file or encoding issue
                            return ProcessingResult(
                                vulnerabilities=[],
                                processed_bytes=processed_bytes,
                                early_termination=True,
                                termination_reason="Binary file or encoding error"
                            )

                        # Analyze this chunk
                        chunk_vulns = analyzer_func(chunk_text, file_path, offset)
                        vulnerabilities.extend(chunk_vulns)

                        # Check for early termination
                        if len(vulnerabilities) >= early_exit_threshold:
                            early_termination = True
                            termination_reason = f"Early exit: {len(vulnerabilities)} vulnerabilities found"
                            break

                        offset += chunk_bytes
                        processed_bytes += chunk_bytes

        except (OSError, IOError) as e:
            return ProcessingResult(
                vulnerabilities=[],
                processed_bytes=processed_bytes,
                early_termination=True,
                termination_reason=f"File I/O error: {e}"
            )

        return ProcessingResult(
            vulnerabilities=vulnerabilities,
            processed_bytes=processed_bytes,
            early_termination=early_termination,
            termination_reason=termination_reason
        )

    def process_file_line_by_line(
        self,
        file_path: Path,
        line_analyzer_func: Callable[[str, int, Path], Optional[Any]],
        max_lines: int = 1000
    ) -> ProcessingResult:
        """
        Process file line by line for line-specific analysis

        Args:
            file_path: Path to file to analyze
            line_analyzer_func: Function to analyze each line (line_text, line_num, path) -> vuln or None
            max_lines: Maximum lines to process

        Returns:
            ProcessingResult with vulnerabilities
        """
        vulnerabilities = []
        processed_bytes = 0
        lines_processed = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if lines_processed >= max_lines:
                        return ProcessingResult(
                            vulnerabilities=vulnerabilities,
                            processed_bytes=processed_bytes,
                            early_termination=True,
                            termination_reason=f"Line limit reached ({max_lines})"
                        )

                    # Analyze this line
                    vuln = line_analyzer_func(line, line_num, file_path)
                    if vuln:
                        vulnerabilities.append(vuln)

                    processed_bytes += len(line.encode('utf-8'))
                    lines_processed += 1

        except (UnicodeDecodeError, IOError):
            return ProcessingResult(
                vulnerabilities=[],
                processed_bytes=0,
                early_termination=True,
                termination_reason="File encoding or I/O error"
            )

        return ProcessingResult(
            vulnerabilities=vulnerabilities,
            processed_bytes=processed_bytes,
            early_termination=False
        )


class SmartFilePreFilter:
    """
    🚀 PERFORMANCE OPTIMIZATION: Pre-filter files before analysis
    Skip obviously irrelevant files for massive speedup
    """

    def __init__(self):
        self.binary_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.exe', '.dll', '.so', '.dylib', '.class'
        }

        self.test_file_patterns = [
            'test_', '_test', 'spec.', '.test.', '__pycache__',
            'node_modules', 'vendor', 'dist', 'build'
        ]

    def should_analyze_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Quick pre-filtering to determine if file should be analyzed

        Returns:
            (should_analyze, reason)
        """
        # Size check (skip very large files)
        try:
            file_size = file_path.stat().st_size
            if file_size > 50 * 1024 * 1024:  # 50MB
                return False, f"File too large ({file_size} bytes)"

            if file_size == 0:
                return False, "Empty file"
        except OSError:
            return False, "Cannot access file"

        # Extension check (skip binary files)
        if file_path.suffix.lower() in self.binary_extensions:
            return False, f"Binary file extension: {file_path.suffix}"

        # Filename pattern check (skip test files)
        filename_lower = file_path.name.lower()
        for pattern in self.test_file_patterns:
            if pattern in filename_lower:
                return False, f"Test/build file pattern: {pattern}"

        # Path check (skip common directories)
        path_str = str(file_path).lower()
        if any(skip_dir in path_str for skip_dir in ['__pycache__', 'node_modules', '.git']):
            return False, "Excluded directory"

        return True, "File should be analyzed"

    def is_text_file(self, file_path: Path, sample_size: int = 1024) -> bool:
        """
        Check if file is likely text-based by sampling content
        """
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(sample_size)

            # Check for null bytes (binary file indicator)
            if b'\x00' in sample:
                return False

            # Try to decode as UTF-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                # Try other encodings
                try:
                    sample.decode('latin-1')
                    return True
                except UnicodeDecodeError:
                    return False

        except IOError:
            return False
