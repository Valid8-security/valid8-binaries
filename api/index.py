#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Valid8 API - Vercel Serverless Function
Integrated with Valid8 Scanner
"""
import json
import sys
import tempfile
import os
from pathlib import Path
import time
import uuid

# Add parent directory to path to import valid8
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from valid8.scanner import Scanner
    SCANNER_AVAILABLE = True
    IMPORT_ERROR = None
except ImportError as e:
    SCANNER_AVAILABLE = False
    Scanner = None
    IMPORT_ERROR = str(e)

def handler(request):
    """
    Vercel serverless function handler
    
    Args:
        request: Vercel request object
    
    Returns:
        dict: Response with statusCode, headers, and body
    """
    # Handle CORS headers
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Max-Age': '86400',
    }
    
    # Get method safely
    method = 'GET'
    if hasattr(request, 'method'):
        method = request.method
    elif hasattr(request, 'get'):
        method = request.get('method', 'GET')
    
    # Handle OPTIONS for CORS preflight
    if method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'status': 'ok', 'message': 'CORS preflight'})
        }
    
    # Health check
    if method == 'GET':
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'status': 'ok',
                'service': 'Valid8 API',
                'version': '1.0.0',
                'scanner_available': SCANNER_AVAILABLE,
                'error': IMPORT_ERROR if not SCANNER_AVAILABLE else None
            })
        }
    
    # Handle scan requests
    if method == 'POST':
        if not SCANNER_AVAILABLE:
            return {
                'statusCode': 500,
                'headers': headers,
                'body': json.dumps({
                    'error': 'Scanner not available',
                    'message': 'Valid8 scanner could not be imported',
                    'import_error': IMPORT_ERROR
                })
            }
        
        try:
            # Parse request body
            data = {}
            if hasattr(request, 'json') and request.json:
                data = request.json
            elif hasattr(request, 'body'):
                body = request.body
                if isinstance(body, str):
                    data = json.loads(body)
                elif isinstance(body, bytes):
                    data = json.loads(body.decode('utf-8'))
                else:
                    data = body if body else {}
            
            action = data.get('action', 'scan')
            
            # Handle different actions
            if action == 'scan':
                return handle_scan(data, headers)
            elif action == 'get_scans':
                return handle_get_scans(data, headers)
            elif action == 'get_scan_result':
                return handle_get_scan_result(data, headers)
            else:
                return {
                    'statusCode': 400,
                    'headers': headers,
                    'body': json.dumps({'error': f'Unknown action: {action}'})
                }
                
        except json.JSONDecodeError as e:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({
                    'error': 'Invalid JSON in request body',
                    'message': str(e)
                })
            }
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': headers,
                'body': json.dumps({
                    'error': str(e),
                    'type': type(e).__name__
                })
            }
    
    # Method not allowed
    return {
        'statusCode': 405,
        'headers': headers,
        'body': json.dumps({'error': 'Method not allowed', 'method': method})
    }

def handle_scan(data, headers):
    """Handle scan request"""
    code = data.get('code', '')
    file_path = data.get('file_path', '')
    language = data.get('language', 'auto')
    scan_mode = data.get('mode', 'fast')
    
    if not code and not file_path:
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({
                'error': 'Missing code or file_path parameter'
            })
        }
    
    try:
        # Create scanner
        scanner = Scanner()
        
        # Create temporary file if code provided
        temp_file = None
        scan_path = file_path
        
        if code and not file_path:
            # Create temp file with code
            temp_dir = tempfile.mkdtemp()
            file_ext = {
                'python': '.py',
                'javascript': '.js',
                'java': '.java',
                'go': '.go',
                'ruby': '.rb',
                'php': '.php'
            }.get(language.lower(), '.txt')
            
            temp_file = os.path.join(temp_dir, f'scan{file_ext}')
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(code)
            scan_path = temp_file
        
        # Run scan
        start_time = time.time()
        results = scanner.scan(scan_path, mode=scan_mode)
        duration = time.time() - start_time
        
        # Format results
        vulnerabilities = []
        for vuln in results.get('vulnerabilities', []):
            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'cwe': vuln.get('cwe', 'Unknown'),
                'severity': vuln.get('severity', 'medium'),
                'message': vuln.get('message', ''),
                'file': vuln.get('file', scan_path),
                'line': vuln.get('line', 0),
                'description': vuln.get('description', '')
            })
        
        # Clean up temp file
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
            if os.path.exists(os.path.dirname(temp_file)):
                os.rmdir(os.path.dirname(temp_file))
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        scan_record = {
            'id': scan_id,
            'timestamp': time.time(),
            'date': time.strftime('%Y-%m-%d'),
            'target': scan_path,
            'vulnerabilities': len(vulnerabilities),
            'status': 'completed',
            'duration': f'{duration:.2f}s',
            'mode': scan_mode
        }
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'status': 'success',
                'scan': scan_record,
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v['severity'] == 'critical']),
                    'high': len([v for v in vulnerabilities if v['severity'] == 'high']),
                    'medium': len([v for v in vulnerabilities if v['severity'] == 'medium']),
                    'low': len([v for v in vulnerabilities if v['severity'] == 'low'])
                }
            })
        }
        
    except Exception as e:
        # Clean up temp file on error
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
                if os.path.exists(os.path.dirname(temp_file)):
                    os.rmdir(os.path.dirname(temp_file))
            except:
                pass
        
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': 'Scan failed',
                'message': str(e),
                'type': type(e).__name__
            })
        }

def handle_get_scans(data, headers):
    """Handle get scans request - return empty for now, can be extended with database"""
    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({
            'status': 'success',
            'scans': []  # Would come from database in production
        })
    }

def handle_get_scan_result(data, headers):
    """Handle get scan result request"""
    scan_id = data.get('scan_id')
    if not scan_id:
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({'error': 'Missing scan_id parameter'})
        }
    
    # Would fetch from database in production
    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({
            'status': 'success',
            'scan': None  # Would come from database
        })
    }
