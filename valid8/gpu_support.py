#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
GPU Support Detection and Configuration

Detects NVIDIA GPU availability and configures Ollama for GPU acceleration.
Provides 5-10x speedup for AI inference when GPU is available.
"""

import subprocess
import os
from typing import Dict, Optional


class GPUDetector:
    """Detect and configure GPU support for LLM inference"""
    
    @staticmethod
    def has_gpu() -> bool:
        """Check if NVIDIA GPU is available"""
        try:
            # Try to import torch and check CUDA
            import torch
            return torch.cuda.is_available() and torch.cuda.device_count() > 0
        except ImportError:
            # Torch not installed, try nvidia-smi
            try:
                result = subprocess.run(
                    ['nvidia-smi'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False
    
    @staticmethod
    def get_gpu_info() -> Dict[str, any]:
        """Get detailed GPU information"""
        if not GPUDetector.has_gpu():
            return {
                "available": False,
                "count": 0,
                "name": None,
                "memory_gb": 0
            }
        
        try:
            import torch
            if torch.cuda.is_available():
                return {
                    "available": True,
                    "count": torch.cuda.device_count(),
                    "name": torch.cuda.get_device_name(0),
                    "memory_gb": torch.cuda.get_device_properties(0).total_memory / 1e9
                }
        except ImportError:
            pass
        
        # Fallback: parse nvidia-smi
        try:
            result = subprocess.run(
                ['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                first_gpu = lines[0].split(',')
                name = first_gpu[0].strip()
                memory_str = first_gpu[1].strip().split()[0]  # "8192 MiB" -> "8192"
                memory_gb = float(memory_str) / 1024
                
                return {
                    "available": True,
                    "count": len(lines),
                    "name": name,
                    "memory_gb": memory_gb
                }
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        
        return {
            "available": False,
            "count": 0,
            "name": None,
            "memory_gb": 0
        }
    
    @staticmethod
    def configure_ollama_gpu() -> bool:
        """
        Configure Ollama to use GPU if available.
        Ollama automatically uses GPU when available, this just verifies.
        """
        try:
            # Check if Ollama is running
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    @staticmethod
    def get_recommended_model() -> str:
        """Get recommended model based on GPU availability"""
        gpu_info = GPUDetector.get_gpu_info()
        
        if not gpu_info["available"]:
            # CPU only: use smallest fast model
            return "qwen2.5-coder:1.5b"
        
        memory_gb = gpu_info["memory_gb"]
        
        if memory_gb >= 12:
            # High-end GPU: can use larger model
            return "qwen2.5-coder:7b"
        elif memory_gb >= 8:
            # Mid-range GPU: use medium model
            return "qwen2.5-coder:3b"
        else:
            # Low-end GPU: use small model
            return "qwen2.5-coder:1.5b"
    
    @staticmethod
    def estimate_speedup() -> float:
        """Estimate speedup factor with GPU vs CPU"""
        gpu_info = GPUDetector.get_gpu_info()
        
        if not gpu_info["available"]:
            return 1.0  # No speedup
        
        memory_gb = gpu_info["memory_gb"]
        
        # Speedup estimates based on GPU memory/power
        if memory_gb >= 16:
            return 10.0  # High-end GPU (RTX 4090, A100)
        elif memory_gb >= 8:
            return 7.0   # Mid-range GPU (RTX 4060, 3060)
        else:
            return 5.0   # Low-end GPU (GTX 1650)
    
    @staticmethod
    def print_gpu_status(console):
        """Print GPU status with rich console"""
        gpu_info = GPUDetector.get_gpu_info()
        
        if gpu_info["available"]:
            speedup = GPUDetector.estimate_speedup()
            console.print(
                f"[green]✓ GPU detected: {gpu_info['name']} "
                f"({gpu_info['memory_gb']:.1f}GB)[/green]"
            )
            console.print(
                f"[dim]AI inference will be ~{speedup:.0f}x faster than CPU[/dim]"
            )
        else:
            console.print(
                f"[yellow]⚠ No GPU detected. Using CPU (slower).[/yellow]"
            )
            console.print(
                f"[dim]Install NVIDIA GPU for 5-10x speedup. "
                f"See: parry doctor[/dim]"
            )

