#!/usr/bin/env python3
"""
Copyright (c) 2025 Valid8 Security
All rights reserved.

This software is proprietary and confidential. Unauthorized copying,
modification, distribution, or use of this software, via any medium is
strictly prohibited without the express written permission of Valid8 Security.

"""

"""
Create Stripe Checkout Session for Valid8
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

def handler(request):
    """Create Stripe checkout session"""
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
    
    # Get method
    method = getattr(request, 'method', 'GET')
    
    # Handle CORS preflight
    if method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({'status': 'ok'})
        }
    
    if method != 'POST':
        return {
            'statusCode': 405,
            'headers': headers,
            'body': json.dumps({'error': 'Method not allowed', 'method': method})
        }
    
    if not STRIPE_AVAILABLE:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': 'Stripe not available'})
        }
    
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    if not stripe.api_key:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': 'Stripe secret key not configured'})
        }
    
    try:
        # Parse request body - handle different formats
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
        else:
            data = {}
        
        price_id = data.get('priceId')
        if not price_id:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'priceId required'})
            }
        
        # Create checkout session
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=data.get('successUrl', 'https://valid8code.ai/success?session_id={CHECKOUT_SESSION_ID}'),
            cancel_url=data.get('cancelUrl', 'https://valid8code.ai/pricing'),
            metadata={
                'user_id': data.get('userId', ''),
                'tier': data.get('tier', ''),
            },
            allow_promotion_codes=True,
        )
        
        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps({
                'sessionId': session.id,
                'url': session.url
            })
        }
    except json.JSONDecodeError as e:
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({'error': 'Invalid JSON', 'message': str(e)})
        }
    except stripe.error.StripeError as e:
        return {
            'statusCode': 400,
            'headers': headers,
            'body': json.dumps({'error': str(e.user_message) if hasattr(e, 'user_message') else str(e)})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': str(e), 'type': type(e).__name__})
        }
