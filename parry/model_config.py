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
        description="Enterprise-grade accuracy. Requires powerful GPU (24GB+ VRAM)."
    ),
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
DEFAULT_FAST_MODEL = "qwen2.5-coder:1.5b"  # Speed priority
DEFAULT_BALANCED_MODEL = "qwen2.5-coder:3b"  # Balance (10-15% FP) ✅ NEW DEFAULT
DEFAULT_ACCURATE_MODEL = "qwen2.5-coder:7b"  # Accuracy priority (8% FP) ✅ RECOMMENDED
DEFAULT_PREMIUM_MODEL = "qwen2.5-coder:14b"  # Best accuracy (5% FP)



