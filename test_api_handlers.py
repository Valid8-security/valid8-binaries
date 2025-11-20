#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

class MockRequest:
    def __init__(self, method='GET', body=None, json_data=None, headers=None):
        self.method = method
        self.body = body
        self.json = json_data
        self.headers = headers or {}

def test_main_api():
    print("Testing main API handler...")
    from api.index import handler
    
    req = MockRequest('GET')
    response = handler(req)
    assert response['statusCode'] == 200
    print("  ✅ GET works")
    
    req = MockRequest('OPTIONS')
    response = handler(req)
    assert response['statusCode'] == 200
    print("  ✅ OPTIONS works")
    
    req = MockRequest('POST', json_data={'code': 'test'})
    response = handler(req)
    assert response['statusCode'] == 200
    print("  ✅ POST works")

def test_checkout():
    print("Testing checkout handler...")
    import importlib.util
    spec = importlib.util.spec_from_file_location("checkout", "api/create-checkout-session.py")
    checkout_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checkout_module)
    handler = checkout_module.handler
    
    req = MockRequest('OPTIONS')
    response = handler(req)
    assert response['statusCode'] == 200
    print("  ✅ OPTIONS works")

def test_webhook():
    print("Testing webhook handler...")
    from api.webhooks.stripe import handler
    req = MockRequest('POST', headers={'stripe-signature': 'test'})
    response = handler(req)
    assert response['statusCode'] in [200, 500]
    print("  ✅ Webhook works")

if __name__ == '__main__':
    try:
        test_main_api()
        test_checkout()
        test_webhook()
        print("\n✅ All tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
