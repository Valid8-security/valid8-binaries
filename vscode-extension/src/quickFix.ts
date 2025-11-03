// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Quick Fix Provider - Provides inline code actions for vulnerabilities
 */

import * as vscode from 'vscode';
import { ParryScanner, Vulnerability } from './scanner';
import { LicenseManager } from './license';

export class QuickFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];
    
    constructor(
        private scanner: ParryScanner,
        private licenseManager: LicenseManager
    ) {}
    
    async provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeAction[]> {
        const licenseInfo = this.licenseManager.getLicenseInfo();
        const actions: vscode.CodeAction[] = [];
        
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Parry') {
                continue;
            }
            
            // Add "Learn More" action
            const learnMoreAction = new vscode.CodeAction(
                'Learn More About This Vulnerability',
                vscode.CodeActionKind.QuickFix
            );
            learnMoreAction.command = {
                title: 'Learn More',
                command: 'vscode.open',
                arguments: [vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${diagnostic.code}.html`)]
            };
            actions.push(learnMoreAction);
            
            // Add "Suppress This Warning" action
            const suppressAction = new vscode.CodeAction(
                'Suppress This Warning',
                vscode.CodeActionKind.QuickFix
            );
            suppressAction.edit = new vscode.WorkspaceEdit();
            suppressAction.edit.insert(
                document.uri,
                new vscode.Position(range.start.line, 0),
                `// parry-ignore: ${diagnostic.code}\n`
            );
            actions.push(suppressAction);
            
            // Add AI-powered fix for Pro/Enterprise users
            if (licenseInfo.tier !== 'free') {
                const fixAction = new vscode.CodeAction(
                    '✨ AI-Powered Fix (Pro)',
                    vscode.CodeActionKind.QuickFix
                );
                fixAction.command = {
                    title: 'Apply AI Fix',
                    command: 'parry.applyAIFix',
                    arguments: [document, diagnostic, range]
                };
                fixAction.isPreferred = true;
                actions.push(fixAction);
            } else {
                // Show upgrade prompt for free users
                const upgradeAction = new vscode.CodeAction(
                    '⭐ Upgrade to Pro for AI-Powered Fixes',
                    vscode.CodeActionKind.QuickFix
                );
                upgradeAction.command = {
                    title: 'Upgrade',
                    command: 'parry.subscribe'
                };
                actions.push(upgradeAction);
            }
        }
        
        return actions;
    }
}
