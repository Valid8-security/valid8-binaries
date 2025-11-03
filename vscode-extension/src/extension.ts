// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Parry VS Code Extension - Main Entry Point
 * 
 * Provides real-time security scanning with inline diagnostics and AI-powered fixes.
 * Requires Pro license for hosted LLM features.
 */

import * as vscode from 'vscode';
import { ParryScanner } from './scanner';
import { DiagnosticsManager } from './diagnostics';
import { SecurityPanelProvider } from './securityPanel';
import { LicenseManager } from './license';
import { QuickFixProvider } from './quickFix';

let scanner: ParryScanner;
let diagnosticsManager: DiagnosticsManager;
let licenseManager: LicenseManager;
let securityPanelProvider: SecurityPanelProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('Parry Security Scanner is activating...');
    
    // Initialize managers
    licenseManager = new LicenseManager(context);
    diagnosticsManager = new DiagnosticsManager();
    scanner = new ParryScanner(licenseManager);
    securityPanelProvider = new SecurityPanelProvider(context.extensionUri);
    
    // Register security panel
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            'parryVulnerabilities',
            securityPanelProvider
        )
    );
    
    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await scanDocument(editor.document);
            }
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.scanWorkspace', async () => {
            await scanWorkspace();
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.showSecurityPanel', () => {
            vscode.commands.executeCommand('workbench.view.extension.parry-security');
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.clearDiagnostics', () => {
            diagnosticsManager.clear();
            vscode.window.showInformationMessage('Parry: Diagnostics cleared');
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.activateLicense', async () => {
            const licenseKey = await vscode.window.showInputBox({
                prompt: 'Enter your Parry license key',
                placeHolder: 'License key from email',
                password: true
            });
            
            if (licenseKey) {
                const success = await licenseManager.activateLicense(licenseKey);
                if (success) {
                    vscode.window.showInformationMessage('License activated successfully!');
                } else {
                    vscode.window.showErrorMessage('License activation failed. Please check your key.');
                }
            }
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.showLicenseInfo', () => {
            const info = licenseManager.getLicenseInfo();
            const message = `Tier: ${info.tier}\nMode: ${info.llm_mode}\nFile Limit: ${info.file_limit || 'Unlimited'}`;
            vscode.window.showInformationMessage(message, { modal: true });
        })
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.subscribe', () => {
            vscode.env.openExternal(vscode.Uri.parse('https://parry.dev/pricing'));
        })
    );
    
    // NEW: Direct LLM query for specific code
    context.subscriptions.push(
        vscode.commands.registerCommand('parry.queryLLM', async () => {
            await queryLLMForSelection();
        })
    );
    
    // Register quick fix provider
    const quickFixProvider = new QuickFixProvider(scanner, licenseManager);
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            quickFixProvider,
            {
                providedCodeActionKinds: QuickFixProvider.providedCodeActionKinds
            }
        )
    );
    
    // Set up real-time scanning
    const config = vscode.workspace.getConfiguration('parry');
    if (config.get('enabled') && config.get('realtimeScan')) {
        setupRealtimeScanning(context);
    }
    
    // Scan open documents on startup
    vscode.window.visibleTextEditors.forEach(editor => {
        if (shouldScanDocument(editor.document)) {
            scanDocument(editor.document);
        }
    });
    
    // Show welcome message for free tier users
    if (licenseManager.getLicenseInfo().tier === 'free') {
        vscode.window.showInformationMessage(
            'Parry: Scanning with Free tier (100 file limit). Upgrade to Pro for unlimited files and hosted LLM.',
            'Upgrade'
        ).then(choice => {
            if (choice === 'Upgrade') {
                vscode.commands.executeCommand('parry.subscribe');
            }
        });
    }
    
    console.log('Parry Security Scanner activated successfully');
}

function setupRealtimeScanning(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('parry');
    const scanDelay = config.get<number>('scanDelay', 2000);
    
    let timeoutHandle: NodeJS.Timeout | undefined;
    
    // Scan on document change
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            if (!shouldScanDocument(event.document)) {
                return;
            }
            
            // Debounce scanning
            if (timeoutHandle) {
                clearTimeout(timeoutHandle);
            }
            
            timeoutHandle = setTimeout(() => {
                scanDocument(event.document);
            }, scanDelay);
        })
    );
    
    // Scan on document open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            if (shouldScanDocument(document)) {
                scanDocument(document);
            }
        })
    );
    
    // Clear diagnostics on document close
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(document => {
            diagnosticsManager.clearForDocument(document.uri);
        })
    );
}

function shouldScanDocument(document: vscode.TextDocument): boolean {
    // Don't scan untitled documents or output/debug consoles
    if (document.uri.scheme !== 'file') {
        return false;
    }
    
    // Check exclude patterns
    const config = vscode.workspace.getConfiguration('parry');
    const excludePatterns = config.get<string[]>('excludePatterns', []);
    const filePath = document.uri.fsPath;
    
    const minimatch = require('minimatch');
    for (const pattern of excludePatterns) {
        if (minimatch(filePath, pattern, { matchBase: true })) {
            return false;
        }
    }
    
    return true;
}

async function scanDocument(document: vscode.TextDocument) {
    const config = vscode.workspace.getConfiguration('parry');
    if (!config.get('enabled')) {
        return;
    }
    
    try {
        const vulnerabilities = await scanner.scanDocument(document);
        diagnosticsManager.updateDiagnostics(document.uri, vulnerabilities);
        
        // Update security panel
        securityPanelProvider.updateVulnerabilities(vulnerabilities);
        
        // Show status bar notification
        if (vulnerabilities.length > 0) {
            const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
            const high = vulnerabilities.filter(v => v.severity === 'high').length;
            
            if (critical > 0 || high > 0) {
                vscode.window.showWarningMessage(
                    `Parry found ${critical} critical and ${high} high severity vulnerabilities`
                );
            }
        }
    } catch (error) {
        console.error('Parry scan error:', error);
        vscode.window.showErrorMessage(`Parry scan failed: ${error}`);
    }
}

async function scanWorkspace() {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }
    
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Parry: Scanning workspace',
        cancellable: false
    }, async (progress) => {
        progress.report({ increment: 0, message: 'Finding files...' });
        
        const files = await vscode.workspace.findFiles('**/*', '**/node_modules/**');
        const total = files.length;
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const document = await vscode.workspace.openTextDocument(file);
            
            if (shouldScanDocument(document)) {
                await scanDocument(document);
            }
            
            progress.report({
                increment: (100 / total),
                message: `Scanning ${i + 1}/${total}`
            });
        }
        
        vscode.window.showInformationMessage(`Parry: Scanned ${total} files`);
    });
}

async function queryLLMForSelection() {
    /**
     * Direct LLM query for security analysis of specific code
     * Bypasses automated pattern detection and asks LLM directly
     */
    const editor = vscode.window.activeTextEditor;
    
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }
    
    // Check license tier (requires Pro/Enterprise for hosted LLM)
    const licenseInfo = licenseManager.getLicenseInfo();
    if (licenseInfo.tier === 'free') {
        const choice = await vscode.window.showWarningMessage(
            'Direct LLM queries require Pro or Enterprise tier (hosted LLM)',
            'Upgrade',
            'Cancel'
        );
        
        if (choice === 'Upgrade') {
            vscode.commands.executeCommand('parry.subscribe');
        }
        return;
    }
    
    // Get selection or current line
    const selection = editor.selection;
    let code: string;
    let startLine: number;
    let endLine: number;
    
    if (selection.isEmpty) {
        // Use current line
        startLine = selection.start.line;
        endLine = selection.start.line;
        code = editor.document.lineAt(startLine).text;
    } else {
        // Use selection
        startLine = selection.start.line;
        endLine = selection.end.line;
        code = editor.document.getText(selection);
    }
    
    // Show loading message
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Parry: Analyzing code with LLM...',
        cancellable: false
    }, async () => {
        try {
            // Query LLM via API
            const result = await scanner.queryLLMForCode(
                code,
                editor.document.languageId,
                editor.document.fileName,
                startLine,
                endLine
            );
            
            // Display results in output channel
            const outputChannel = vscode.window.createOutputChannel('Parry LLM Analysis');
            outputChannel.clear();
            outputChannel.appendLine('='.repeat(80));
            outputChannel.appendLine(`Parry LLM Security Analysis`);
            outputChannel.appendLine('='.repeat(80));
            outputChannel.appendLine('');
            outputChannel.appendLine(`File: ${editor.document.fileName}`);
            outputChannel.appendLine(`Lines: ${startLine + 1}-${endLine + 1}`);
            outputChannel.appendLine(`Language: ${editor.document.languageId}`);
            outputChannel.appendLine('');
            outputChannel.appendLine('CODE:');
            outputChannel.appendLine('-'.repeat(80));
            outputChannel.appendLine(code);
            outputChannel.appendLine('-'.repeat(80));
            outputChannel.appendLine('');
            outputChannel.appendLine('SECURITY ANALYSIS:');
            outputChannel.appendLine('-'.repeat(80));
            outputChannel.appendLine(result.analysis);
            
            if (result.issues && result.issues.length > 0) {
                outputChannel.appendLine('');
                outputChannel.appendLine('IDENTIFIED ISSUES:');
                result.issues.forEach((issue: any, idx: number) => {
                    outputChannel.appendLine(`\n${idx + 1}. ${issue.title} [${issue.severity}]`);
                    outputChannel.appendLine(`   ${issue.description}`);
                    if (issue.recommendation) {
                        outputChannel.appendLine(`   Fix: ${issue.recommendation}`);
                    }
                });
            }
            
            outputChannel.appendLine('');
            outputChannel.appendLine('='.repeat(80));
            outputChannel.show(true);
            
            // Show notification
            if (result.issues && result.issues.length > 0) {
                vscode.window.showWarningMessage(
                    `Parry LLM found ${result.issues.length} potential security issue(s)`,
                    'View Details'
                ).then(choice => {
                    if (choice === 'View Details') {
                        outputChannel.show();
                    }
                });
            } else {
                vscode.window.showInformationMessage('Parry LLM: No obvious security issues detected');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Parry LLM query failed: ${error}`);
        }
    });
}

export function deactivate() {
    diagnosticsManager.clear();
    console.log('Parry Security Scanner deactivated');
}
