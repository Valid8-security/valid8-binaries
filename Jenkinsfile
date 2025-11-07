// Jenkins Pipeline with Parry Security Scanning
// Requires Jenkins with Docker Pipeline plugin

pipeline {
    agent {
        docker {
            image 'python:3.9-slim'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    environment {
        PARRY_MODE = 'hybrid'  // Options: fast, hybrid, deep
        PARRY_SEVERITY = 'medium'
        FAIL_ON_HIGH_SEVERITY = true
        OLLAMA_MODEL = 'qwen2.5-coder:1.5b'
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    // Install system dependencies
                    sh '''
                        apt-get update && apt-get install -y \\
                            curl \\
                            jq \\
                            docker.io
                    '''

                    // Install Parry
                    sh 'pip install parry-security-scanner'

                    // Setup Ollama for AI scanning
                    sh '''
                        curl -fsSL https://ollama.ai/install.sh | sh
                        nohup ollama serve > /dev/null 2>&1 &
                        sleep 10
                        ollama pull ${OLLAMA_MODEL} || echo "AI model download failed"
                    '''
                }
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def scanCommand = "parry scan . --mode ${env.PARRY_MODE} --format json --output parry-results.json --severity ${env.PARRY_SEVERITY}"

                    def scanStatus = sh(
                        script: scanCommand,
                        returnStatus: true
                    )

                    // Publish scan results
                    if (fileExists('parry-results.json')) {
                        def results = readJSON file: 'parry-results.json'
                        def vulnCount = results.vulnerabilities?.size() ?: 0
                        def filesScanned = results.files_scanned ?: 0
                        def highSevCount = results.vulnerabilities?.findAll { it.severity in ['high', 'critical'] }?.size() ?: 0
                        def mediumSevCount = results.vulnerabilities?.findAll { it.severity == 'medium' }?.size() ?: 0

                        echo """
🔒 Parry Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Files Scanned: ${filesScanned}
Total Vulnerabilities: ${vulnCount}
High/Critical Severity: ${highSevCount}
Medium Severity: ${mediumSevCount}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        """

                        // Archive results
                        archiveArtifacts artifacts: 'parry-results.json', fingerprint: true

                        // Update build description
                        currentBuild.description = "Security: ${vulnCount} issues (${highSevCount} high)"

                        // Set build status based on findings
                        if (highSevCount > 0) {
                            currentBuild.result = 'UNSTABLE'
                            echo "⚠️ High-severity vulnerabilities detected!"
                        } else {
                            echo "✅ No high-severity vulnerabilities found!"
                        }
                    } else {
                        error("Security scan failed - no results file generated")
                    }
                }
            }
        }

        stage('Process Results') {
            steps {
                script {
                    if (fileExists('parry-results.json')) {
                        def results = readJSON file: 'parry-results.json'
                        def highSevCount = results.vulnerabilities?.findAll { it.severity in ['high', 'critical'] }?.size() ?: 0

                        // Fail build if configured and high-severity issues found
                        if (env.FAIL_ON_HIGH_SEVERITY == 'true' && highSevCount > 0) {
                            error("Build failed: ${highSevCount} high-severity security vulnerabilities found")
                        }
                    }
                }
            }
        }

        stage('Generate Report') {
            steps {
                script {
                    // Generate HTML report
                    sh '''
                        python3 -c "
import json
from pathlib import Path

# Load results
if Path('parry-results.json').exists():
    with open('parry-results.json') as f:
        data = json.load(f)
    
    # Generate HTML report
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Parry Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
            .vulnerability {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
            .high {{ border-left-color: #dc3545; background: #f8d7da; }}
            .medium {{ border-left-color: #ffc107; background: #fff3cd; }}
            .low {{ border-left-color: #28a745; background: #d4edda; }}
        </style>
    </head>
    <body>
        <h1>🔒 Parry Security Scan Report</h1>
        <div class=\"summary\">
            <h2>Summary</h2>
            <p><strong>Files Scanned:</strong> {data.get('files_scanned', 0)}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(data.get('vulnerabilities', []))}</p>
        </div>
        
        <h2>Vulnerabilities</h2>
    '''
    
    for vuln in data.get('vulnerabilities', []):
        severity_class = vuln.get('severity', 'low')
        html += f'''
        <div class=\"vulnerability {severity_class}\">
            <h3>{vuln.get('title', 'Unknown')}</h3>
            <p><strong>CWE:</strong> {vuln.get('cwe', 'Unknown')}</p>
            <p><strong>Severity:</strong> {severity_class.upper()}</p>
            <p><strong>File:</strong> {vuln.get('file_path', 'Unknown')}</p>
            <p><strong>Line:</strong> {vuln.get('line_number', 'Unknown')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
            <pre>{vuln.get('code_snippet', '')}</pre>
        </div>
        '''
    
    html += '''
    </body>
    </html>
    '''
    
    with open('parry-report.html', 'w') as f:
        f.write(html)
    
    print('HTML report generated: parry-report.html')
"
                    '''

                    // Publish HTML report
                    publishHTML([
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'parry-report.html',
                        reportName: 'Parry Security Report',
                        reportTitles: 'Parry Security Scan Results'
                    ])
                }
            }
        }
    }

    post {
        always {
            // Clean up workspace
            cleanWs()

            // Send notifications for failed builds
            script {
                if (currentBuild.result == 'FAILURE' || currentBuild.result == 'UNSTABLE') {
                    echo "Security scan found issues. Check the Parry Security Report for details."
                }
            }
        }

        success {
            echo "✅ Pipeline completed successfully with no blocking security issues!"
        }

        unstable {
            echo "⚠️ Pipeline completed with security findings. Review the Parry Security Report."
        }

        failure {
            echo "❌ Pipeline failed. Check security scan results and address critical issues."
        }
    }
}