#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Model Configuration for AI-Powered Detection

Provides different model tiers optimized for speed vs accuracy
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ModelProfile:
    """Profile for an LLM model"""
    name: str
    display_name: str
    size_gb: float
    speed_rating: str  # "ultra-fast", "fast", "medium", "slow"
    accuracy_rating: str  # "baseline", "good", "excellent", "superior"
    false_positive_rate: float  # Estimated FP rate
    recall: float  # Estimated recall
    min_ram_gb: int
    gpu_recommended: bool
    description: str


# Available model profiles
MODEL_PROFILES: Dict[str, ModelProfile] = {
    # Default model - TinyLlama (lightweight, fast, good for most users)
    "tinyllama:1.1b": ModelProfile(
        name="tinyllama:1.1b",
        display_name="TinyLlama 1.1B (Default - Fast & Lightweight)",
        size_gb=0.7,
        speed_rating="ultra-fast",
        accuracy_rating="baseline",
        false_positive_rate=0.30,  # 30% FP rate
        recall=0.75,
        min_ram_gb=2,
        gpu_recommended=False,
        description="Default model - Fast, lightweight, suitable for most users. Good balance of speed and accuracy."
    ),
    
    # Ultra-fast models (baseline accuracy)
    "qwen2.5-coder:1.5b": ModelProfile(
        name="qwen2.5-coder:1.5b",
        display_name="Qwen 2.5 Coder 1.5B (Ultra-Fast)",
        size_gb=0.98,
        speed_rating="ultra-fast",
        accuracy_rating="baseline",
        false_positive_rate=0.35,  # 35% FP rate
        recall=0.70,
        min_ram_gb=2,
        gpu_recommended=False,
        description="Fastest model, suitable for quick scans. Lower accuracy."
    ),
    
    # Fast models (good accuracy)
    "qwen2.5-coder:3b": ModelProfile(
        name="qwen2.5-coder:3b",
        display_name="Qwen 2.5 Coder 3B (Fast & Balanced)",
        size_gb=1.9,
        speed_rating="fast",
        accuracy_rating="good",
        false_positive_rate=0.15,  # 15% FP rate ✅ Target!
        recall=0.85,
        min_ram_gb=4,
        gpu_recommended=False,
        description="Best balance of speed and accuracy. Recommended for most users."
    ),
    
    "qwen2.5-coder:7b": ModelProfile(
        name="qwen2.5-coder:7b",
        display_name="Qwen 2.5 Coder 7B (Accurate)",
        size_gb=4.7,
        speed_rating="medium",
        accuracy_rating="excellent",
        false_positive_rate=0.08,  # 8% FP rate ✅ Better!
        recall=0.92,
        min_ram_gb=8,
        gpu_recommended=True,
        description="High accuracy with moderate speed. Best for comprehensive scans."
    ),
    
    # High-accuracy models
    "deepseek-coder:6.7b": ModelProfile(
        name="deepseek-coder:6.7b",
        display_name="DeepSeek Coder 6.7B (High Accuracy)",
        size_gb=3.8,
        speed_rating="medium",
        accuracy_rating="excellent",
        false_positive_rate=0.10,  # 10% FP rate ✅ Target!
        recall=0.90,
        min_ram_gb=8,
        gpu_recommended=True,
        description="Excellent at understanding code context and reducing false positives."
    ),
    
    "codellama:7b": ModelProfile(
        name="codellama:7b",
        display_name="CodeLlama 7B (Established)",
        size_gb=3.8,
        speed_rating="medium",
        accuracy_rating="good",
        false_positive_rate=0.18,  # 18% FP rate
        recall=0.82,
        min_ram_gb=8,
        gpu_recommended=True,
        description="Established model with good performance, but higher FP rate."
    ),
    
    # Premium models (best accuracy, slower)
    "qwen2.5-coder:14b": ModelProfile(
        name="qwen2.5-coder:14b",
        display_name="Qwen 2.5 Coder 14B (Premium)",
        size_gb=9.0,
        speed_rating="slow",
        accuracy_rating="superior",
        false_positive_rate=0.05,  # 5% FP rate ✅ Excellent!
        recall=0.95,
        min_ram_gb=16,
        gpu_recommended=True,
        description="Highest accuracy, lowest false positives. Requires GPU for reasonable speed."
    ),
    
    "deepseek-coder:33b": ModelProfile(
        name="deepseek-coder:33b",
        display_name="DeepSeek Coder 33B (Enterprise)",
        size_gb=19.0,
        speed_rating="slow",
        accuracy_rating="superior",
        false_positive_rate=0.03,  # 3% FP rate ✅ Best!
        recall=0.96,
        min_ram_gb=32,
        gpu_recommended=True,
        description="Enterprise-grade accuracy. Requires powerful GPU (24GB+ VRAM). Highest practical accuracy - larger models (70B+) offer minimal gains with 2x+ hardware requirements."
    ),
    
    # Ultra-large models (NOT RECOMMENDED - diminishing returns)
    # Only include if specifically requested by enterprise customers with appropriate hardware
    # "codellama:70b": ModelProfile(
    #     name="codellama:70b",
    #     display_name="CodeLlama 70B (Ultra-Premium - Not Recommended)",
    #     size_gb=40.0,
    #     speed_rating="extremely-slow",
    #     accuracy_rating="superior",
    #     false_positive_rate=0.02,  # 2% FP rate - only 1% better than 33B
    #     recall=0.97,  # Only 1% better than 33B
    #     min_ram_gb=80,
    #     gpu_recommended=True,
    #     description="Ultra-premium model. Requires enterprise GPU (48GB+ VRAM, A100/H100). Only 1% accuracy gain over 33B model with 2x hardware requirements. NOT recommended - use 33B instead."
    # ),
}


def get_recommended_model(
    target_fp_rate: float = 0.10,
    available_ram_gb: Optional[int] = None,
    has_gpu: bool = False,
    prioritize: str = "balanced"  # "speed", "balanced", "accuracy"
) -> ModelProfile:
    """
    Get recommended model based on requirements
    
    Args:
        target_fp_rate: Target false positive rate (default 10%)
        available_ram_gb: Available system RAM in GB
        has_gpu: Whether GPU is available
        prioritize: "speed", "balanced", or "accuracy"
    
    Returns:
        Recommended ModelProfile
    """
    candidates = []
    
    for profile in MODEL_PROFILES.values():
        # Filter by FP rate
        if profile.false_positive_rate > target_fp_rate:
            continue
        
        # Filter by RAM if specified
        if available_ram_gb and profile.min_ram_gb > available_ram_gb:
            continue
        
        # Filter by GPU requirement
        if profile.gpu_recommended and not has_gpu:
            continue
        
        candidates.append(profile)
    
    if not candidates:
        # Fallback to fastest model that meets FP rate
        candidates = [p for p in MODEL_PROFILES.values() if p.false_positive_rate <= target_fp_rate]
        if not candidates:
            # Ultimate fallback
            return MODEL_PROFILES["qwen2.5-coder:3b"]
    
    # Sort by priority
    if prioritize == "speed":
        # Prefer faster models
        speed_order = {"ultra-fast": 0, "fast": 1, "medium": 2, "slow": 3}
        candidates.sort(key=lambda p: (speed_order.get(p.speed_rating, 99), p.false_positive_rate))
    elif prioritize == "accuracy":
        # Prefer lower FP rate and higher recall
        candidates.sort(key=lambda p: (p.false_positive_rate, -p.recall))
    else:  # balanced
        # Prefer fast models with low FP
        speed_order = {"ultra-fast": 0, "fast": 1, "medium": 2, "slow": 3}
        candidates.sort(key=lambda p: (
            p.false_positive_rate,
            speed_order.get(p.speed_rating, 99),
            -p.recall
        ))
    
    return candidates[0]


def list_available_models() -> Dict[str, ModelProfile]:
    """Get all available model profiles"""
    return MODEL_PROFILES.copy()


# Default model for different use cases
DEFAULT_MODEL = "tinyllama:1.1b"  # Default preset - lightweight and fast
DEFAULT_FAST_MODEL = "tinyllama:1.1b"  # Speed priority (default)
DEFAULT_BALANCED_MODEL = "qwen2.5-coder:3b"  # Balance (10-15% FP) ✅ Advanced option
DEFAULT_ACCURATE_MODEL = "qwen2.5-coder:7b"  # Accuracy priority (8% FP) ✅ Advanced option
DEFAULT_PREMIUM_MODEL = "qwen2.5-coder:14b"  # Best accuracy (5% FP) ✅ Advanced option



