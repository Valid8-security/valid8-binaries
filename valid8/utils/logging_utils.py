"""
Logging Utilities - Centralized logging configuration
"""
import logging
import sys
from pathlib import Path
from typing import Optional

from ..core.config_manager import config_manager


class Valid8Logger:
    """Centralized logging for Valid8"""

    def __init__(self):
        self._logger = None
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Setup logging configuration"""
        self._logger = logging.getLogger('valid8')
        self._logger.setLevel(getattr(logging, config_manager.get('log_level', 'INFO')))

        # Remove existing handlers
        self._logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self._logger.addHandler(console_handler)

        # File handler (if configured)
        log_file = config_manager.get('log_file')
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self._logger.addHandler(file_handler)

    def get_logger(self, name: str = 'valid8') -> logging.Logger:
        """Get logger instance"""
        if name == 'valid8':
            return self._logger
        else:
            return logging.getLogger(f'valid8.{name}')


# Global logger instance
logger = Valid8Logger().get_logger()


def log_scan_start(scan_id: str, target: str, mode: str) -> None:
    """Log scan start"""
    logger.info(f"Starting scan {scan_id} on {target} with mode {mode}")


def log_scan_complete(scan_id: str, files_scanned: int, vulnerabilities_found: int,
                     scan_time: float) -> None:
    """Log scan completion"""
    logger.info(
        f"Completed scan {scan_id}: {files_scanned} files, "
        f"{vulnerabilities_found} vulnerabilities, {scan_time:.2f}s"
    )


def log_error(message: str, exc: Optional[Exception] = None) -> None:
    """Log error with optional exception"""
    if exc:
        logger.error(f"{message}: {exc}", exc_info=True)
    else:
        logger.error(message)


def log_vulnerability_found(cwe: str, severity: str, file_path: str) -> None:
    """Log vulnerability detection"""
    logger.info(f"Found {severity} vulnerability {cwe} in {file_path}")


def setup_structured_logging() -> None:
    """Setup structured logging for production use"""
    # This could be extended to use structured logging libraries
    # like structlog or json logging for better observability
    pass
