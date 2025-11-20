"""
Stripe Webhook Handler for Valid8
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

def handler(request):
    """Handle Stripe webhook events"""
    headers = {
        'Content-Type': 'application/json',
    }
    
    if not STRIPE_AVAILABLE:
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({'error': 'Stripe not available'})
        }
    
    # Get webhook secret
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    if not webhook_secret:
        return {
            'statusCode': 200,  # Return 200 to prevent retries if secret not configured
            'headers': headers,
            'body': json.dumps({'error': 'Webhook secret not configured', 'received': True})
        }
    
    # Get method
    method = getattr(request, 'method', 'POST')
    if method != 'POST':
        return {
            'statusCode': 405,
            'headers': headers,
            'body': json.dumps({'error': 'Method not allowed'})
        }
    
    # Get signature from headers
    request_headers = getattr(request, 'headers', {})
    if isinstance(request_headers, dict):
        sig_header = request_headers.get('stripe-signature') or request_headers.get('Stripe-Signature')
    else:
        sig_header = getattr(request_headers, 'get', lambda x: None)('stripe-signature')
    
    if not sig_header:
        return {
            'statusCode': 200,  # Return 200 to acknowledge receipt
            'headers': headers,
            'body': json.dumps({'error': 'No signature', 'received': True})
        }
    
    # Get request body
    body = getattr(request, 'body', b'')
    if isinstance(body, str):
        body = body.encode('utf-8')
    elif body is None:
        body = b''
    
    # Verify webhook
    try:
        event = stripe.Webhook.construct_event(
            body,
            sig_header,
            webhook_secret
        )
    except ValueError as e:
        return {
            'statusCode': 200,  # Return 200 to acknowledge receipt
            'headers': headers,
            'body': json.dumps({'error': f'Invalid payload: {str(e)}', 'received': True})
        }
    except stripe.error.SignatureVerificationError as e:
        return {
            'statusCode': 200,  # Return 200 to acknowledge receipt
            'headers': headers,
            'body': json.dumps({'error': f'Invalid signature: {str(e)}', 'received': True})
        }
    
    # Handle event
    event_type = event['type']
    event_data = event['data']['object']
    
    # Log event (in production, use proper logging)
    print(f"Received Stripe event: {event_type}")
    
    # Handle different event types
    if event_type == 'checkout.session.completed':
        customer_id = event_data.get('customer')
        subscription_id = event_data.get('subscription')
        print(f"Checkout completed: customer={customer_id}, subscription={subscription_id}")
        
    elif event_type == 'customer.subscription.created':
        subscription_id = event_data.get('id')
        customer_id = event_data.get('customer')
        print(f"Subscription created: {subscription_id} for customer {customer_id}")
        
    elif event_type == 'customer.subscription.updated':
        subscription_id = event_data.get('id')
        print(f"Subscription updated: {subscription_id}")
        
    elif event_type == 'customer.subscription.deleted':
        subscription_id = event_data.get('id')
        print(f"Subscription deleted: {subscription_id}")
        
    elif event_type == 'invoice.payment_succeeded':
        subscription_id = event_data.get('subscription')
        print(f"Payment succeeded for subscription: {subscription_id}")
        
    elif event_type == 'invoice.payment_failed':
        subscription_id = event_data.get('subscription')
        print(f"Payment failed for subscription: {subscription_id}")
    
    return {
        'statusCode': 200,
        'headers': headers,
        'body': json.dumps({'received': True, 'event': event_type})
    }
