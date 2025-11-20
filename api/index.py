"""
Valid8 API - Vercel Serverless Function
"""
import json
import sys
import tempfile
import os
from pathlib import Path

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
    # Handle CORS headers - MUST be present to avoid 401
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
    
    # Handle OPTIONS for CORS preflight - CRITICAL for avoiding 401
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
            # Parse request body - handle different request formats
            data = {}
            if hasattr(request, 'json') and request.json:
                data = request.json
            elif hasattr(request, 'body'):
                body = request.body
                if isinstance(body, str):
                    try:
                        data = json.loads(body)
                    except:
                        data = {}
                elif isinstance(body, bytes):
                    try:
                        data = json.loads(body.decode('utf-8'))
                    except:
                        data = {}
                else:
                    data = body if body else {}
            else:
                data = {}
            
            code = data.get('code', '')
            language = data.get('language', 'auto')
            file_path = data.get('file_path', '')
            
            if not code and not file_path:
                return {
                    'statusCode': 400,
                    'headers': headers,
                    'body': json.dumps({
                        'error': 'Missing code or file_path parameter',
                        'received_data': list(data.keys()) if data else []
                    })
                }
            
            # Create scanner
            scanner = Scanner()
            
            # For now, return a placeholder response
            # Full implementation would:
            # 1. Create temp file with code
            # 2. Run scanner on temp file
            # 3. Clean up temp file
            # 4. Return results
            
            results = {
                'status': 'success',
                'message': 'Valid8 API is ready. Full implementation needed.',
                'vulnerabilities': [],
                'scanned': bool(code or file_path),
                'language': language
            }
            
            return {
                'statusCode': 200,
                'headers': headers,
                'body': json.dumps(results)
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
