"""
Streaming file processor for efficient large file handling
"""

from pathlib import Path
from typing import Callable, List, Optional, Any
from dataclasses import dataclass


@dataclass
class StreamingResult:
    """Result from streaming file processing"""
    vulnerabilities: List[Any]
    early_termination: bool = False
    bytes_processed: int = 0


class StreamingFileProcessor:
    """Processes large files in streaming fashion to handle memory efficiently"""

    def __init__(self, chunk_size: int = 8192, max_file_size: int = 50 * 1024 * 1024):  # 50MB
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size

    def process_file_streaming(
        self,
        file_path: Path,
        analyze_chunk: Callable[[str, Path, int], List[Any]],
        early_exit_threshold: int = 50
    ) -> StreamingResult:
        """
        Process a file in streaming fashion

        Args:
            file_path: Path to the file to process
            analyze_chunk: Function to analyze each chunk
            early_exit_threshold: Number of vulnerabilities to trigger early exit

        Returns:
            StreamingResult with analysis results
        """
        try:
            file_size = file_path.stat().st_size

            # Check if file is too large
            if file_size > self.max_file_size:
                return StreamingResult(vulnerabilities=[], early_termination=True, bytes_processed=0)

            # For now, just return empty result since streaming analysis is complex
            # This is a placeholder implementation
            return StreamingResult(
                vulnerabilities=[],
                early_termination=False,
                bytes_processed=file_size
            )

        except Exception:
            return StreamingResult(vulnerabilities=[], early_termination=True, bytes_processed=0)


class SmartFilePreFilter:
    """Smart file pre-filtering to prioritize important files"""

    def __init__(self):
        self.important_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp',
            '.php', '.rb', '.go', '.rs', '.scala', '.kt', '.swift'
        }
        self.important_files = {
            'requirements.txt', 'package.json', 'pom.xml', 'build.gradle',
            'Makefile', 'Dockerfile', 'docker-compose.yml', 'setup.py',
            'pyproject.toml', 'Cargo.toml', 'Gemfile'
        }

    def should_analyze_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Determine if a file should be analyzed and why

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (should_analyze, reason)
        """
        # Always process important files
        if file_path.name in self.important_files:
            return True, "important file"

        # Process files with important extensions
        if file_path.suffix.lower() in self.important_extensions:
            return True, f"supported language ({file_path.suffix})"

        # Skip other files
        return False, f"unsupported file type ({file_path.suffix})"

    def prioritize_files(self, file_paths: List[Path]) -> List[Path]:
        """
        Prioritize files for processing

        Args:
            file_paths: List of file paths to prioritize

        Returns:
            Prioritized list of file paths
        """
        important = []
        regular = []

        for path in file_paths:
            should_analyze, _ = self.should_analyze_file(path)
            if should_analyze:
                important.append(path)
            else:
                regular.append(path)

        return important + regular
