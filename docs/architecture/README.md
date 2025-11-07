# Parry Architecture Documentation

This directory contains Mermaid diagram files that document the architecture and design of the Parry Security Scanner.

## 📊 Available Diagrams

### System Architecture
- **[System Overview](system-overview.mmd)** - High-level system architecture showing all components and their relationships

### AI & Validation Pipeline
- **[AI Validation Pipeline](ai-validation-pipeline.mmd)** - Detailed flow of AI-powered vulnerability validation and false positive reduction

### Data Flow & Processing
- **[Data Flow](data-flow.mmd)** - Complete data flow from input sources through processing to output formats

### Performance & Optimization
- **[Performance Optimization](performance-optimization.mmd)** - Two-phase optimization approach and performance gains

### Caching & Infrastructure
- **[Caching Hierarchy](caching-hierarchy.mmd)** - Multi-level caching system architecture

### Analysis & Comparison
- **[Competitive Analysis](competitive-analysis.mmd)** - Performance comparison with commercial competitors
- **[Scan Modes](scan-modes.mmd)** - Comparison of Fast, Hybrid, and Deep scanning modes

### Integration
- **[CI/CD Integration](ci-cd-integration.mmd)** - Integration with GitHub Actions, GitLab CI, and Jenkins

## 🔧 Viewing Mermaid Diagrams

### Online Tools
- **[Mermaid Live Editor](https://mermaid.live/)** - Paste diagram code to render
- **[GitHub Mermaid Support](https://github.blog/2022-02-14-include-diagrams-markdown-files-mermaid/)** - GitHub renders Mermaid in Markdown files

### VS Code Extensions
- **Mermaid Preview** - Real-time preview in VS Code
- **Markdown Preview Enhanced** - Includes Mermaid support

### Command Line
```bash
# Install mermaid CLI
npm install -g @mermaid-js/mermaid-cli

# Convert to PNG
mmdc -i system-overview.mmd -o system-overview.png

# Convert to SVG
mmdc -i system-overview.mmd -o system-overview.svg
```

## 📋 Diagram Categories

| Category | Purpose | Key Diagrams |
|----------|---------|--------------|
| **Architecture** | System design and components | System Overview, Data Flow |
| **AI/ML** | Machine learning and validation | AI Validation Pipeline |
| **Performance** | Optimization and efficiency | Performance Optimization, Caching |
| **Analysis** | Comparison and benchmarking | Competitive Analysis, Scan Modes |
| **Integration** | CI/CD and external systems | CI/CD Integration |

## 🎯 Key Architecture Insights

### System Design
- **Privacy-First**: All processing happens locally, no data leaves the machine
- **Modular Architecture**: Clean separation between scanning, AI, and output layers
- **Parallel Processing**: Thread pools and batching for optimal performance

### AI Integration
- **Multi-Stage Validation**: Rule-based → Cache → Ensemble → NL Filtering → Calibration
- **SLM Optimization**: Smaller models for speed, larger models for accuracy
- **Natural Language Filtering**: Unique capability to specify false positives in plain English

### Performance Optimizations
- **Phase 1**: Regex caching, streaming, pre-filtering (~5x speedup)
- **Phase 2**: Batched AI, progressive analysis, model caching (~3x additional speedup)
- **Total**: 4-7x faster than commercial competitors

### Scalability Features
- **Smart Prioritization**: Risk-based file selection for AI analysis
- **Multi-Level Caching**: L1 memory + L2 persistent cache
- **Streaming Processing**: Memory-efficient handling of large files

## 🔗 Related Documentation

- **[Main README](../../README.md)** - Product overview and quick start
- **[Setup Guide](../../SETUP_GUIDE.md)** - Installation and configuration
- **[API Reference](../../docs/api/API_REFERENCE.md)** - REST API documentation
- **[Contributing](../../CONTRIBUTING.md)** - Development guidelines

## 📞 Need Help?

- **Documentation Issues**: Open an issue on GitHub
- **Diagram Updates**: Edit the `.mmd` files and regenerate
- **New Diagrams**: Follow the existing naming and structure conventions

---

🛡️ **Parry Architecture**: Privacy-first, AI-powered, enterprise-grade security scanning
