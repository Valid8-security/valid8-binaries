pipeline {
    agent any
    
    environment {
        PARRY_CACHE_DIR = "${WORKSPACE}/.parry/cache"
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    // Install dependencies
                    sh '''
                        python3 -m pip install --upgrade pip
                        pip install parry-scanner
                        
                        # Install Ollama if not present
                        if ! command -v ollama &> /dev/null; then
                            curl -fsSL https://ollama.ai/install.sh | sh
                        fi
                        
                        # Start Ollama service
                        ollama serve &
                        sleep 5
                        
                        # Pull AI model
                        ollama pull codellama:7b-instruct-q4_K_M
                    '''
                }
            }
        }
        
        stage('Fast Security Scan') {
            steps {
                script {
                    // Run fast scan for quick feedback
                    sh '''
                        parry scan ${WORKSPACE} \
                            --mode fast \
                            --format json \
                            --output parry-fast-results.json
                    '''
                }
            }
        }
        
        stage('Dependency Scan (SCA)') {
            steps {
                script {
                    sh '''
                        parry scan ${WORKSPACE} \
                            --sca \
                            --format json \
                            --output parry-sca-results.json
                    '''
                }
            }
        }
        
        stage('Deep Scan (Main Branch)') {
            when {
                branch 'main'
            }
            steps {
                script {
                    sh '''
                        parry scan ${WORKSPACE} \
                            --mode deep \
                            --validate \
                            --format json \
                            --output parry-deep-results.json
                    '''
                }
            }
        }
        
        stage('Check Vulnerabilities') {
            steps {
                script {
                    def results = readJSON file: 'parry-fast-results.json'
                    def critical = results.vulnerabilities.findAll { it.severity == 'CRITICAL' }
                    def high = results.vulnerabilities.findAll { it.severity == 'HIGH' }
                    
                    echo "Security Scan Results:"
                    echo "  Critical: ${critical.size()}"
                    echo "  High: ${high.size()}"
                    echo "  Total: ${results.vulnerabilities.size()}"
                    
                    if (critical.size() > 0) {
                        error("Build failed: ${critical.size()} critical vulnerabilities found!")
                    }
                    
                    // Warning for high severity (don't fail build)
                    if (high.size() > 5) {
                        unstable("Warning: ${high.size()} high severity vulnerabilities found!")
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Archive scan results
            archiveArtifacts artifacts: 'parry-*-results.json', fingerprint: true
            
            // Publish to Jenkins dashboard
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'parry-report.html',
                reportName: 'Parry Security Report'
            ])
        }
        
        success {
            echo '✅ Security scan passed!'
        }
        
        failure {
            emailext(
                subject: "Security Scan Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                Security scan failed with critical vulnerabilities.
                
                Build: ${env.BUILD_URL}
                
                Please review the findings and remediate before merging.
                """,
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}


