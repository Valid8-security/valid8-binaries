"""
Massive Training Data Generator for Valid8 AI Validation

Generates 1M+ labeled training examples across 7+ programming languages
to achieve 99.5% precision in vulnerability validation.

Strategy: Generate diverse, realistic examples covering:
- True vulnerabilities (label: 1)
- Pattern false positives (label: 0)
- Ambiguous cases (label: 0 - conservative approach)
"""

import json
import random
import uuid
from pathlib import Path
from typing import List, Dict, Any, Generator
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Reuse the AI validator feature extraction for consistency
from .ai_true_positive_validator import AITruePositiveValidator


@dataclass
class TrainingExample:
    """A single training example with features and label"""
    features: List[float]
    label: int  # 0 = false positive (filter out), 1 = true positive (keep)
    metadata: Dict[str, Any]


class MassiveTrainingGenerator:
    """
    Generates massive training datasets for ultra-precise AI validation.

    Target: 1M+ labeled examples across 7+ languages
    Goal: Enable 99.5% precision in vulnerability validation
    """

    def __init__(self):
        self.target_samples = 1000000  # 1M examples
        self.languages = ['python', 'javascript', 'java', 'go', 'php', 'ruby', 'csharp']
        self.validator = AITruePositiveValidator()

        # Distribution targets for balanced training
        self.distribution_targets = {
            'true_positives': 0.05,      # 5% true vulnerabilities (real challenges)
            'false_positives': 0.85,     # 85% pattern false positives (common case)
            'ambiguous': 0.10           # 10% ambiguous cases (edge cases)
        }

        # Progress tracking
        self.generated_count = 0
        self.start_time = time.time()

    def generate_massive_dataset(self, output_path: str = "training_data_massive.json") -> Dict[str, Any]:
        """
        Generate the complete massive training dataset.

        Args:
            output_path: Where to save the generated dataset

        Returns:
            Dataset metadata and statistics
        """
        print("🚀 GENERATING MASSIVE TRAINING DATASET (1M+ examples)")
        print("=" * 70)
        print(f"Target: {self.target_samples:,} training examples")
        print(f"Languages: {', '.join(self.languages)}")
        print(f"Distribution: {self.distribution_targets}")
        print()

        # Calculate samples per category
        true_positives_target = int(self.target_samples * self.distribution_targets['true_positives'])
        false_positives_target = int(self.target_samples * self.distribution_targets['false_positives'])
        ambiguous_target = int(self.target_samples * self.distribution_targets['ambiguous'])

        print("📊 Generation Targets:")
        print(f"   True Positives: {true_positives_target:,} (real vulnerabilities)")
        print(f"   False Positives: {false_positives_target:,} (pattern matches to filter)")
        print(f"   Ambiguous Cases: {ambiguous_target:,} (edge cases)")
        print()

        # Generate examples using parallel processing
        all_examples = []

        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit generation tasks
            futures = []

            # True positives (real vulnerabilities)
            futures.extend([
                executor.submit(self._generate_true_positives_batch,
                              true_positives_target // 8, lang)
                for lang in self.languages[:4]  # Distribute across languages
            ])

            # False positives (pattern matches to filter)
            futures.extend([
                executor.submit(self._generate_false_positives_batch,
                              false_positives_target // 4, lang)
                for lang in self.languages
            ])

        # Collect results
        for future in as_completed(futures):
            try:
                batch_examples = future.result()
                all_examples.extend(batch_examples)

                # Progress update
                self.generated_count += len(batch_examples)
                if self.generated_count % 10000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.generated_count / elapsed if elapsed > 0 else 0
                    print(".1f")

            except Exception as e:
                print(f"❌ Batch generation failed: {e}")

        # Generate ambiguous cases (sequential for consistency)
        print("\\n🔄 Generating ambiguous cases...")
        ambiguous_examples = self._generate_ambiguous_cases(ambiguous_target)
        all_examples.extend(ambiguous_examples)

        # Shuffle for better training
        random.shuffle(all_examples)

        # Extract features and labels
        features = []
        labels = []
        metadata = []

        print("\\n🔍 Extracting features from examples...")
        for example in all_examples:
            try:
                vuln_features = self.validator._extract_validation_features(example)
                features.append(vuln_features)
                labels.append(example.get('expected_label', 0))
                metadata.append({
                    'id': str(uuid.uuid4()),
                    'language': example.get('language', 'unknown'),
                    'category': example.get('category', 'unknown'),
                    'cwe': example.get('cwe', 'unknown'),
                    'reason': example.get('reason', 'generated')
                })
            except Exception as e:
                print(f"⚠️ Feature extraction failed for example: {e}")
                continue

        # Create final dataset
        dataset = {
            'features': features,
            'labels': labels,
            'metadata': metadata,
            'dataset_info': {
                'total_samples': len(features),
                'true_positives': labels.count(1),
                'false_positives': labels.count(0),
                'positive_rate': labels.count(1) / len(labels) if labels else 0,
                'languages': self.languages,
                'generation_time': time.time() - self.start_time,
                'target_precision': 0.995,
                'description': 'Massive training dataset for 99.5% precision AI validation'
            }
        }

        # Save dataset
        print(f"\\n💾 Saving dataset to {output_path}...")
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)

        # Final statistics
        final_stats = self._analyze_dataset_quality(dataset)

        print("\\n🎉 MASSIVE TRAINING DATASET GENERATED!")
        print("=" * 50)
        print(f"📊 Total Examples: {len(features):,}")
        print(f"🎯 True Positives: {labels.count(1):,}")
        print(f"🚫 False Positives: {labels.count(0):,}")
        print(".1%")
        print(".1f")
        print(f"🌍 Languages Covered: {len(set(m['language'] for m in metadata))}")

        return dataset

    def _generate_true_positives_batch(self, count: int, language: str) -> List[Dict[str, Any]]:
        """Generate true positive examples (real vulnerabilities)"""
        examples = []

        # Vulnerability templates by language
        templates = self._get_vulnerability_templates(language)

        for _ in range(count):
            # Select random template
            template = random.choice(templates)

            # Add variations
            example = self._create_vulnerability_example(template, language, is_true_positive=True)
            examples.append(example)

        return examples

    def _generate_false_positives_batch(self, count: int, language: str) -> List[Dict[str, Any]]:
        """Generate false positive examples (safe code that patterns match)"""
        examples = []

        # Safe code templates that might trigger patterns
        safe_templates = self._get_safe_code_templates(language)

        for _ in range(count):
            # Select random safe template
            template = random.choice(safe_templates)

            # Create example that patterns might flag but is actually safe
            example = self._create_safe_code_example(template, language)
            examples.append(example)

        return examples

    def _generate_ambiguous_cases(self, count: int) -> List[Dict[str, Any]]:
        """Generate ambiguous cases that require careful validation"""
        examples = []

        # Mix of borderline cases across all languages
        all_templates = []
        for lang in self.languages:
            all_templates.extend(self._get_ambiguous_templates(lang))

        for _ in range(count):
            template = random.choice(all_templates)
            lang = template.get('language', random.choice(self.languages))

            example = self._create_ambiguous_example(template, lang)
            examples.append(example)

        return examples

    def _get_vulnerability_templates(self, language: str) -> List[Dict[str, Any]]:
        """Get vulnerability templates for a specific language"""
        if language == 'python':
            return [
                {
                    'cwe': 'CWE-89', 'type': 'sql_injection',
                    'template': 'query = f"SELECT * FROM users WHERE id = \'{user_input}\'"\ncursor.execute(query)',
                    'pattern': 'fstring_sql'
                },
                {
                    'cwe': 'CWE-79', 'type': 'xss',
                    'template': 'return f"<div>Welcome {user_input}</div>"',
                    'pattern': 'template_literal'
                },
                {
                    'cwe': 'CWE-78', 'type': 'command_injection',
                    'template': 'subprocess.run(cmd, shell=True)',
                    'pattern': 'shell_true'
                }
            ]
        elif language == 'javascript':
            return [
                {
                    'cwe': 'CWE-79', 'type': 'xss',
                    'template': 'element.innerHTML = `<h1>${userInput}</h1>`;',
                    'pattern': 'innerhtml_assign'
                },
                {
                    'cwe': 'CWE-78', 'type': 'command_injection',
                    'template': 'exec(userCmd, (error, stdout) => { console.log(stdout); });',
                    'pattern': 'exec_call'
                }
            ]
        # Add more languages as needed
        return []

    def _get_safe_code_templates(self, language: str) -> List[Dict[str, Any]]:
        """Get safe code templates that might trigger false positives"""
        if language == 'python':
            return [
                {
                    'type': 'safe_sql',
                    'template': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                    'pattern_trigger': 'execute_call'
                },
                {
                    'type': 'safe_html',
                    'template': 'element.textContent = sanitize_input(user_input)',
                    'pattern_trigger': 'assignment'
                },
                {
                    'type': 'safe_command',
                    'template': 'subprocess.run(["ls", "-la"], check=True)',
                    'pattern_trigger': 'subprocess_call'
                }
            ]
        # Add more languages
        return []

    def _get_ambiguous_templates(self, language: str) -> List[Dict[str, Any]]:
        """Get ambiguous case templates"""
        return [
            {
                'type': 'framework_code',
                'template': 'Django ORM query patterns',
                'language': language
            },
            {
                'type': 'test_code',
                'template': 'Unit test with vulnerable patterns',
                'language': language
            },
            {
                'type': 'generated_code',
                'template': 'Auto-generated code with patterns',
                'language': language
            }
        ]

    def _create_vulnerability_example(self, template: Dict[str, Any], language: str, is_true_positive: bool = True) -> Dict[str, Any]:
        """Create a single vulnerability example"""
        # Add variations to make examples diverse
        variations = self._add_code_variations(template['template'])

        return {
            'cwe': template['cwe'],
            'severity': random.choice(['HIGH', 'CRITICAL']),
            'title': f"Generated {template['type'].replace('_', ' ')}",
            'description': f"Generated {template['type']} vulnerability",
            'file_path': f"generated_{language}_{random.randint(1, 1000)}.{'py' if language == 'python' else 'js'}",
            'line_number': random.randint(10, 500),
            'code_snippet': random.choice(variations),
            'pattern_matched': template['pattern'],
            'match_strength': random.uniform(0.7, 0.95),
            'confidence': random.uniform(0.05, 0.15),  # Low confidence as expected from patterns
            'language': language,
            'category': 'vulnerability',
            'expected_label': 1 if is_true_positive else 0,
            'reason': 'true_positive_vulnerability' if is_true_positive else 'false_positive_pattern'
        }

    def _create_safe_code_example(self, template: Dict[str, Any], language: str) -> Dict[str, Any]:
        """Create a safe code example that patterns might flag"""
        variations = self._add_code_variations(template['template'])

        return {
            'cwe': 'UNKNOWN',  # Not actually vulnerable
            'severity': 'UNKNOWN',
            'title': f"Pattern match: {template['type']}",
            'description': f"Pattern-triggered but safe: {template['type']}",
            'file_path': f"safe_{language}_{random.randint(1, 1000)}.{'py' if language == 'python' else 'js'}",
            'line_number': random.randint(10, 500),
            'code_snippet': random.choice(variations),
            'pattern_matched': template['pattern_trigger'],
            'match_strength': random.uniform(0.4, 0.7),  # Medium strength
            'confidence': random.uniform(0.05, 0.15),
            'language': language,
            'category': 'safe_code',
            'expected_label': 0,  # False positive to filter out
            'reason': 'safe_code_false_positive'
        }

    def _create_ambiguous_example(self, template: Dict[str, Any], language: str) -> Dict[str, Any]:
        """Create an ambiguous example"""
        # Create examples that are borderline
        if template['type'] == 'framework_code':
            code = f"# Django ORM\nUser.objects.filter(name__icontains=search_term)"
        elif template['type'] == 'test_code':
            code = f"def test_sql_injection():\n    query = f\"SELECT * FROM test_table WHERE id = {{user_id}}\""
        else:
            code = f"# Generated code\nresult = f\"Processed: {{input_data}}\""

        return {
            'cwe': 'UNKNOWN',
            'severity': 'UNKNOWN',
            'title': f"Ambiguous: {template['type']}",
            'description': f"Ambiguous {template['type']} case",
            'file_path': f"ambiguous_{language}_{random.randint(1, 1000)}.{'py' if language == 'python' else 'js'}",
            'line_number': random.randint(10, 500),
            'code_snippet': code,
            'pattern_matched': 'various',
            'match_strength': random.uniform(0.3, 0.6),  # Lower confidence
            'confidence': random.uniform(0.05, 0.15),
            'language': language,
            'category': 'ambiguous',
            'expected_label': 0,  # Conservative: filter out ambiguous cases
            'reason': 'ambiguous_conservative_filter'
        }

    def _add_code_variations(self, base_code: str) -> List[str]:
        """Add variations to base code to increase diversity"""
        variations = [base_code]

        # Add some common variations
        if 'f"' in base_code:
            variations.append(base_code.replace('f"', '"').replace('{', '').replace('}', ''))
        if 'user_input' in base_code:
            variations.extend([
                base_code.replace('user_input', 'user_data'),
                base_code.replace('user_input', 'request.args.get("q")'),
                base_code.replace('user_input', 'form_data')
            ])

        # Add indentation variations
        for var in variations[:]:
            variations.append('    ' + var.replace('\n', '\n    '))

        return variations[:10]  # Limit variations

    def _analyze_dataset_quality(self, dataset: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the quality of the generated dataset"""
        features = dataset['features']
        labels = dataset['labels']
        metadata = dataset['metadata']

        analysis = {
            'total_samples': len(features),
            'class_distribution': {
                'positive': labels.count(1),
                'negative': labels.count(0)
            },
            'language_distribution': {},
            'feature_statistics': {
                'avg_features_per_sample': sum(len(f) for f in features) / len(features) if features else 0,
                'min_features': min(len(f) for f in features) if features else 0,
                'max_features': max(len(f) for f in features) if features else 0
            }
        }

        # Language distribution
        for meta in metadata:
            lang = meta.get('language', 'unknown')
            analysis['language_distribution'][lang] = analysis['language_distribution'].get(lang, 0) + 1

        return analysis


def main():
    """Main execution for massive training data generation"""
    import argparse

    parser = argparse.ArgumentParser(description='Generate massive training dataset for Valid8')
    parser.add_argument('--samples', type=int, default=10000,
                       help='Number of training samples to generate (default: 10k for testing)')
    parser.add_argument('--output', type=str, default='massive_training_data.json',
                       help='Output file path')
    parser.add_argument('--languages', nargs='+',
                       help='Languages to include (default: all)')

    args = parser.parse_args()

    try:
        generator = MassiveTrainingGenerator()

        if args.languages:
            generator.languages = args.languages

        if args.samples != 1000000:  # If not default 1M, scale down for testing
            generator.target_samples = args.samples
            # Scale distribution targets proportionally
            scale_factor = args.samples / 1000000
            for key in generator.distribution_targets:
                generator.distribution_targets[key] *= scale_factor

        print(f"Generating {generator.target_samples:,} training examples...")

        dataset = generator.generate_massive_dataset(args.output)

        print("
✅ SUCCESS: Massive training dataset generated!"        print(f"📊 Samples: {dataset['dataset_info']['total_samples']:,}")
        print(".1%"
        return 0

    except Exception as e:
        print(f"❌ Dataset generation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

