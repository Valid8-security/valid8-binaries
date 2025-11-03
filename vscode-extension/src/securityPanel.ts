// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * Security Panel - Webview showing vulnerability summary
 */

import * as vscode from 'vscode';
import { Vulnerability } from './scanner';

export class SecurityPanelProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;
    private vulnerabilities: Vulnerability[] = [];
    
    constructor(private readonly _extensionUri: vscode.Uri) {}
    
    resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;
        
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };
        
        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);
        
        // Handle messages from webview
        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'openFile':
                    this._openFile(data.file, data.line);
                    break;
            }
        });
    }
    
    updateVulnerabilities(vulnerabilities: Vulnerability[]) {
        this.vulnerabilities = vulnerabilities;
        if (this._view) {
            this._view.webview.postMessage({
                type: 'update',
                vulnerabilities: vulnerabilities
            });
        }
    }
    
    private async _openFile(file: string, line: number) {
        const document = await vscode.workspace.openTextDocument(file);
        const editor = await vscode.window.showTextDocument(document);
        const position = new vscode.Position(line, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position));
    }
    
    private _getHtmlForWebview(webview: vscode.Webview): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Parry Security</title>
    <style>
        body {
            padding: 10px;
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
        }
        
        .vulnerability {
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid;
            background: var(--vscode-textBlockQuote-background);
            cursor: pointer;
        }
        
        .vulnerability:hover {
            opacity: 0.8;
        }
        
        .critical { border-color: #dc3545; }
        .high { border-color: #fd7e14; }
        .medium { border-color: #ffc107; }
        .low { border-color: #17a2b8; }
        
        .vulnerability-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .vulnerability-cwe {
            color: var(--vscode-descriptionForeground);
            font-size: 0.9em;
        }
        
        .vulnerability-description {
            margin-top: 5px;
            font-size: 0.9em;
        }
        
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 15px 0;
            padding: 10px;
            background: var(--vscode-editor-background);
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .stat-label {
            font-size: 0.8em;
            color: var(--vscode-descriptionForeground);
        }
        
        .empty {
            text-align: center;
            padding: 40px 20px;
            color: var(--vscode-descriptionForeground);
        }
    </style>
</head>
<body>
    <div id="stats" class="stats"></div>
    <div id="vulnerabilities"></div>
    
    <script>
        const vscode = acquireVsCodeApi();
        let vulnerabilities = [];
        
        window.addEventListener('message', event => {
            const message = event.data;
            if (message.type === 'update') {
                vulnerabilities = message.vulnerabilities;
                render();
            }
        });
        
        function render() {
            renderStats();
            renderVulnerabilities();
        }
        
        function renderStats() {
            const stats = document.getElementById('stats');
            const critical = vulnerabilities.filter(v => v.severity === 'critical').length;
            const high = vulnerabilities.filter(v => v.severity === 'high').length;
            const medium = vulnerabilities.filter(v => v.severity === 'medium').length;
            const low = vulnerabilities.filter(v => v.severity === 'low').length;
            
            stats.innerHTML = \`
                <div class="stat">
                    <div class="stat-value" style="color: #dc3545;">\${critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #fd7e14;">\${high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #ffc107;">\${medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #17a2b8;">\${low}</div>
                    <div class="stat-label">Low</div>
                </div>
            \`;
        }
        
        function renderVulnerabilities() {
            const container = document.getElementById('vulnerabilities');
            
            if (vulnerabilities.length === 0) {
                container.innerHTML = '<div class="empty">✅ No vulnerabilities found</div>';
                return;
            }
            
            container.innerHTML = vulnerabilities.map(v => \`
                <div class="vulnerability \${v.severity}" onclick="openVuln('\${v.file}', \${v.line})">
                    <div class="vulnerability-title">\${v.title}</div>
                    <div class="vulnerability-cwe">\${v.cwe} · Line \${v.line + 1}</div>
                    <div class="vulnerability-description">\${v.description}</div>
                </div>
            \`).join('');
        }
        
        function openVuln(file, line) {
            vscode.postMessage({
                type: 'openFile',
                file: file,
                line: line
            });
        }
        
        // Initial render
        render();
    </script>
</body>
</html>`;
    }
}
