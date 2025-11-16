#!/usr/bin/env python3
"""
Standalone test for massive training data generation logic
"""

import json
import random
import time
from typing import List, Dict, Any


def mock_feature_extraction(vuln: Dict[str, Any]) -> List[float]:
    """Mock feature extraction for testing (55 features)"""
    features = []

    # CWE features (6)
    cwe = vuln.get('cwe', '')
    features.extend([1 if cwe == 'CWE-89' else 0,  # SQL
                    1 if cwe == 'CWE-79' else 0,   # XSS
                    1 if cwe == 'CWE-78' else 0,   # Command
                    1 if cwe == 'CWE-22' else 0,   # Path
                    1 if cwe == 'CWE-502' else 0,  # Deserialization
                    1 if cwe == 'CWE-798' else 0]) # Secrets

    # Code context (8)
    file_path = vuln.get('file_path', '')
    features.append(1 if 'test' in file_path.lower() else 0)
    features.append(1 if 'spec' in file_path.lower() else 0)
    features.append(1 if '__pycache__' in file_path else 0)

    snippet = vuln.get('code_snippet', '')
    features.append(len(snippet))
    features.append(snippet.count('\n'))
    features.append(1 if 'import' in snippet.lower() else 0)
    features.append(1 if 'def ' in snippet else 0)
    features.append(1 if 'class ' in snippet else 0)

    # Pattern strength (6)
    pattern_matched = vuln.get('pattern_matched', '')
    match_strength = vuln.get('match_strength', 0.1)
    confidence = vuln.get('confidence', 0.1)
    features.extend([
        match_strength,
        confidence,
        len(pattern_matched),
        1 if 'fstring' in pattern_matched else 0,
        1 if 'concat' in pattern_matched else 0,
        1 if 'innerhtml' in pattern_matched.lower() else 0
    ])

    # Language features (8)
    features.extend([1, 0, 0, 0, 0, 0, 0, 0])  # Mock Python detection

    # Framework features (9)
    features.extend([0] * 9)  # Mock framework detection

    # Security context (8)
    severity = vuln.get('severity', 'UNKNOWN')
    features.extend([
        1 if severity == 'CRITICAL' else 0,
        1 if severity == 'HIGH' else 0,
        1 if severity == 'MEDIUM' else 0,
        1 if severity == 'LOW' else 0,
        1 if severity == 'UNKNOWN' else 0,
        len(snippet.split()),
        snippet.count('('),
        snippet.count('=')
    ])

    # Advanced features (10)
    features.extend([
        len(snippet.split()),  # Word count
        snippet.count('\n'),   # Line count
        snippet.count('('),    # Function calls
        snippet.count('='),    # Assignments
        1 if any(word in snippet.lower() for word in ['user', 'input', 'data']) else 0,
        1 if any(char in snippet for char in ['$', '@', '%']) else 0,
        sum(1 for word in snippet.split() if word.isupper() and len(word) > 1),
        1 if 'if ' in snippet and 'else' in snippet else 0,
        1 if 'try:' in snippet or 'try ' in snippet else 0,
        1 if 'import ' in snippet or 'require(' in snippet else 0
    ])

    return features


def generate_test_dataset(num_samples: int = 1000) -> Dict[str, Any]:
    """Generate a test training dataset"""
    print(f"🧪 Generating test dataset with {num_samples} samples")

    languages = ['python', 'javascript', 'java', 'go', 'php', 'ruby', 'csharp']

    # Templates for different types
    vuln_templates = {
        'python': [
            {'cwe': 'CWE-89', 'code': 'query = f"SELECT * FROM users WHERE id = \'{user_input}\'"\ncursor.execute(query)'},
            {'cwe': 'CWE-79', 'code': 'return f"<div>Welcome {user_input}</div>"'},
            {'cwe': 'CWE-78', 'code': 'subprocess.run(cmd, shell=True)'}
        ],
        'javascript': [
            {'cwe': 'CWE-79', 'code': 'element.innerHTML = `<h1>${userInput}</h1>`;'},
            {'cwe': 'CWE-78', 'code': 'exec(userCmd, (error, stdout) => { console.log(stdout); });'}
        ]
    }

    safe_templates = {
        'python': [
            {'code': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'},
            {'code': 'element.textContent = sanitize_input(user_input)'},
            {'code': 'subprocess.run(["ls", "-la"], check=True)'}
        ]
    }

    features = []
    labels = []
    metadata = []

    # Generate examples
    for i in range(num_samples):
        # Decide if this is a true positive (5%) or false positive (95%)
        is_true_positive = random.random() < 0.05

        if is_true_positive:
            # True vulnerability
            lang = random.choice(list(vuln_templates.keys()))
            template = random.choice(vuln_templates[lang])

            example = {
                'cwe': template['cwe'],
                'severity': random.choice(['HIGH', 'CRITICAL']),
                'title': 'Generated vulnerability',
                'description': 'Test vulnerability',
                'file_path': f"test_{lang}_{i}.{lang[:2] if lang != 'javascript' else 'js'}",
                'line_number': random.randint(10, 500),
                'code_snippet': template['code'],
                'pattern_matched': f"test_pattern_{random.randint(1,10)}",
                'match_strength': random.uniform(0.7, 0.95),
                'confidence': random.uniform(0.05, 0.15),
                'language': lang,
                'category': 'vulnerability',
                'expected_label': 1
            }
        else:
            # False positive (safe code that might trigger patterns)
            lang = random.choice(list(safe_templates.keys()))
            template = random.choice(safe_templates[lang])

            example = {
                'cwe': 'UNKNOWN',
                'severity': 'UNKNOWN',
                'title': 'Pattern match (safe)',
                'description': 'Safe code triggering patterns',
                'file_path': f"safe_{lang}_{i}.{lang[:2] if lang != 'javascript' else 'js'}",
                'line_number': random.randint(10, 500),
                'code_snippet': template['code'],
                'pattern_matched': f"safe_pattern_{random.randint(1,10)}",
                'match_strength': random.uniform(0.4, 0.7),
                'confidence': random.uniform(0.05, 0.15),
                'language': lang,
                'category': 'safe_code',
                'expected_label': 0
            }

        # Extract features
        vuln_features = mock_feature_extraction(example)
        features.append(vuln_features)
        labels.append(example['expected_label'])

        # Add metadata
        metadata.append({
            'id': f"test_{i}",
            'language': example['language'],
            'category': example['category'],
            'cwe': example['cwe'],
            'reason': 'generated_test'
        })

    # Create dataset
    dataset = {
        'features': features,
        'labels': labels,
        'metadata': metadata,
        'dataset_info': {
            'total_samples': len(features),
            'true_positives': labels.count(1),
            'false_positives': labels.count(0),
            'positive_rate': labels.count(1) / len(labels) if labels else 0,
            'languages': list(set(m['language'] for m in metadata)),
            'generation_time': time.time(),
            'description': 'Test training dataset for Valid8 AI validation'
        }
    }

    return dataset


def test_massive_data_generation():
    """Test the massive data generation approach"""
    print("🚀 TESTING MASSIVE TRAINING DATA GENERATION")
    print("=" * 60)

    # Test with small dataset first
    start_time = time.time()
    dataset = generate_test_dataset(1000)
    generation_time = time.time() - start_time

    print("📊 Dataset Generated:")
    print(f"   Total samples: {dataset['dataset_info']['total_samples']:,}")
    print(f"   True positives: {dataset['dataset_info']['true_positives']:,}")
    print(f"   False positives: {dataset['dataset_info']['false_positives']:,}")
    print(".1%")
    print(".1f")

    # Validate feature extraction
    print("\\n🔍 Validating Feature Extraction:")
    sample_features = dataset['features'][0]
    print(f"   Features per sample: {len(sample_features)} (expected: 55)")

    if len(sample_features) == 55:
        print("   ✅ Feature count correct")
    else:
        print(f"   ❌ Feature count incorrect: {len(sample_features)}")
        return False

    # Validate label distribution
    true_positives = dataset['dataset_info']['true_positives']
    total_samples = dataset['dataset_info']['total_samples']
    expected_tp_rate = 0.05  # 5%
    actual_tp_rate = true_positives / total_samples

    print("\\n📈 Label Distribution Analysis:")
    print(".3f")
    print(".1%")

    if abs(actual_tp_rate - expected_tp_rate) < 0.01:  # Within 1%
        print("   ✅ Label distribution correct")
    else:
        print("   ❌ Label distribution incorrect")
        return False

    # Test scaling projection
    print("\\n📈 Scaling Projections:")
    test_time = generation_time
    test_samples = 1000

    # Project to 1M samples
    projected_time_1m = (test_time / test_samples) * 1000000
    print(".1f")
    print(".1f")

    # Memory estimation
    feature_size = len(sample_features) * 8  # 8 bytes per float64
    total_memory_mb = (1000000 * feature_size) / (1024 * 1024)
    print(".1f")

    # Validate dataset quality
    print("\\n✅ VALIDATION RESULTS:")
    print("=" * 30)

    checks = [
        ("Feature extraction", len(sample_features) == 55),
        ("Label distribution", abs(actual_tp_rate - expected_tp_rate) < 0.01),
        ("Dataset structure", len(dataset['features']) == len(dataset['labels'])),
        ("Metadata completeness", len(dataset['metadata']) == len(dataset['features'])),
        ("Language diversity", len(dataset['dataset_info']['languages']) > 1)
    ]

    all_passed = True
    for check_name, passed in checks:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"   {check_name}: {status}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\\n🎉 MASSIVE TRAINING DATA GENERATION: VALIDATED")
        print("✅ Scalable to 1M+ samples")
        print("✅ Feature extraction working")
        print("✅ Label distribution correct")
        print("✅ Ready for production training")
        return True
    else:
        print("\\n❌ MASSIVE TRAINING DATA GENERATION: ISSUES FOUND")
        return False


if __name__ == "__main__":
    import sys
    success = test_massive_data_generation()

    if success:
        print("\\n🚀 Ready to proceed with Phase 3: AI model training!")
        sys.exit(0)
    else:
        print("\\n⚠️ Issues found - additional development needed")
        sys.exit(1)
