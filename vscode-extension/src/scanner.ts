// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Scanner Module - Communicates with Parry backend
 */

import * as vscode from 'vscode';
import axios from 'axios';
import { LicenseManager } from './license';

export interface Vulnerability {
    cwe: string;
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    line: number;
    column: number;
    code: string;
    fix?: string;
    confidence: number;
}

export class ParryScanner {
    constructor(private licenseManager: LicenseManager) {}
    
    async scanDocument(document: vscode.TextDocument): Promise<Vulnerability[]> {
        const config = vscode.workspace.getConfiguration('parry');
        const mode = config.get<string>('mode', 'hybrid');
        const apiEndpoint = config.get<string>('apiEndpoint', 'https://api.parry.dev');
        
        // Get license info
        const licenseInfo = this.licenseManager.getLicenseInfo();
        
        // For free tier or local mode, use local scanning (not implemented yet)
        if (licenseInfo.tier === 'free' || licenseInfo.llm_mode === 'local') {
            return this.scanLocalPattern(document);
        }
        
        // For Pro/Enterprise, use hosted API
        try {
            const response = await axios.post(`${apiEndpoint}/scan`, {
                code: document.getText(),
                language: document.languageId,
                filepath: document.fileName,
                mode: mode
            }, {
                headers: {
                    'Authorization': `Bearer ${licenseInfo.license_key}`,
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            });
            
            return response.data.vulnerabilities || [];
        } catch (error) {
            console.error('API scan failed:', error);
            // Fallback to local scanning
            return this.scanLocalPattern(document);
        }
    }
    
    private async scanLocalPattern(document: vscode.TextDocument): Promise<Vulnerability[]> {
        // Simple pattern-based scanning (placeholder)
        // In production, this would call the local Parry CLI
        const vulnerabilities: Vulnerability[] = [];
        const text = document.getText();
        const lines = text.split('\n');
        
        // Example: Detect eval() usage
        for (let i = 0; i < lines.length; i++) {
            if (/\beval\s*\(/.test(lines[i])) {
                vulnerabilities.push({
                    cwe: 'CWE-94',
                    title: 'Code Injection via eval()',
                    description: 'Using eval() with user input can lead to arbitrary code execution',
                    severity: 'critical',
                    line: i,
                    column: lines[i].indexOf('eval'),
                    code: lines[i].trim(),
                    fix: 'Avoid eval(). Use safe alternatives like JSON.parse() or Function constructor with validation',
                    confidence: 0.9
                });
            }
            
            // Example: Detect SQL injection patterns
            if (/execute\s*\([^)]*[\+\$]/.test(lines[i]) || /query\s*\([^)]*[\+\$]/.test(lines[i])) {
                vulnerabilities.push({
                    cwe: 'CWE-89',
                    title: 'Potential SQL Injection',
                    description: 'String concatenation in SQL query can lead to injection attacks',
                    severity: 'critical',
                    line: i,
                    column: 0,
                    code: lines[i].trim(),
                    fix: 'Use parameterized queries or prepared statements',
                    confidence: 0.8
                });
            }
        }
        
        return vulnerabilities;
    }
    
    async generateFix(vulnerability: Vulnerability, document: vscode.TextDocument): Promise<string | null> {
        const config = vscode.workspace.getConfiguration('parry');
        const apiEndpoint = config.get<string>('apiEndpoint', 'https://api.parry.dev');
        const licenseInfo = this.licenseManager.getLicenseInfo();
        
        // AI fixes only available for Pro/Enterprise
        if (licenseInfo.tier === 'free') {
            return null;
        }
        
        try {
            const response = await axios.post(`${apiEndpoint}/fix`, {
                vulnerability: vulnerability,
                code: document.getText(),
                language: document.languageId
            }, {
                headers: {
                    'Authorization': `Bearer ${licenseInfo.license_key}`
                },
                timeout: 15000
            });
            
            return response.data.fixed_code || null;
        } catch (error) {
            console.error('Fix generation failed:', error);
            return null;
        }
    }
    
    async queryLLMForCode(
        code: string,
        language: string,
        filepath: string,
        startLine: number,
        endLine: number
    ): Promise<{ analysis: string; issues: any[] }> {
        /**
         * Direct LLM query for security analysis of specific code
         * Bypasses automated pattern detection
         */
        const config = vscode.workspace.getConfiguration('parry');
        const apiEndpoint = config.get<string>('apiEndpoint', 'https://api.parry.dev');
        const licenseInfo = this.licenseManager.getLicenseInfo();
        
        // Requires Pro/Enterprise
        if (licenseInfo.tier === 'free') {
            throw new Error('Direct LLM queries require Pro or Enterprise tier');
        }
        
        try {
            const response = await axios.post(`${apiEndpoint}/query-llm`, {
                code: code,
                language: language,
                filepath: filepath,
                start_line: startLine,
                end_line: endLine,
                prompt: 'Analyze this code for security vulnerabilities. Focus on: injection attacks, authentication issues, cryptographic problems, access control, data exposure, and any other security concerns.'
            }, {
                headers: {
                    'Authorization': `Bearer ${licenseInfo.license_key}`,
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            });
            
            return {
                analysis: response.data.analysis || 'No analysis available',
                issues: response.data.issues || []
            };
        } catch (error: any) {
            if (error.response?.status === 401) {
                throw new Error('License validation failed');
            } else if (error.response?.status === 429) {
                throw new Error('Rate limit exceeded. Try again later.');
            } else {
                throw new Error(`LLM query failed: ${error.message}`);
            }
        }
    }
}

