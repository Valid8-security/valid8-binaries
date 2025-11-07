"""
Complex vulnerable code with subtle issues that pattern matching might miss.
These require semantic understanding and data flow analysis.
"""

import os
import sqlite3
import pickle
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "dev"  # Weak secret in production

# Business Logic Vulnerabilities (hard to detect with patterns)

@app.route('/transfer', methods=['POST'])
def transfer_money():
    """Missing authorization check - IDOR vulnerability"""
    from_account = request.form.get('from')
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    
    # No check if current user owns from_account!
    # This is a classic IDOR (CWE-639)
    db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, from_account))
    db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, to_account))
    
    return "Transfer complete"


@app.route('/admin/users')
def admin_users():
    """Missing authentication - anyone can access admin panel"""
    # No @login_required or role check!
    # CWE-306: Missing Authentication
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template_string("<ul>{% for u in users %}<li>{{u.email}}</li>{% endfor %}</ul>", users=users)


@app.route('/update_price', methods=['POST'])
def update_price():
    """Mass assignment vulnerability"""
    product_id = request.form.get('id')
    
    # Dangerous: binding all form data to product
    # User could set 'is_admin=true' or change 'cost'
    # CWE-915: Mass Assignment
    product = Product.query.get(product_id)
    for key, value in request.form.items():
        setattr(product, key, value)  # Dangerous!
    product.save()
    
    return "Updated"


# Second-order vulnerabilities (stored XSS, delayed injection)

@app.route('/comment', methods=['POST'])
def save_comment():
    """Stored XSS - not immediate, requires data flow analysis"""
    comment = request.form.get('comment')
    user_id = session['user_id']
    
    # Stored without sanitization
    db.execute("INSERT INTO comments (user_id, text) VALUES (?, ?)", (user_id, comment))
    
    return redirect('/comments')


@app.route('/comments')
def show_comments():
    """This is where stored XSS triggers"""
    comments = db.execute("SELECT text, username FROM comments JOIN users").fetchall()
    
    # Rendering unsanitized stored data - Second-order XSS (CWE-79)
    html = "<div>"
    for comment in comments:
        html += f"<p>{comment['text']}</p>"  # XSS here!
    html += "</div>"
    
    return html


# Indirect injection (multi-hop data flow)

def get_user_file(username):
    """Helper function - seems safe"""
    return f"/var/data/{username}.dat"


@app.route('/download/<username>')
def download_user_file(username):
    """Path traversal through helper function
    Pattern matching won't catch this because the dangerous operation
    is separated from the user input by a function call.
    CWE-22: Path Traversal (indirect)
    """
    filepath = get_user_file(username)  # Looks safe...
    
    # But username could be '../../../etc/passwd'
    with open(filepath, 'rb') as f:
        return f.read()


# Race condition (TOCTOU)

@app.route('/withdraw', methods=['POST'])
def withdraw():
    """Race condition vulnerability
    CWE-362: Time-of-check Time-of-use
    """
    user_id = session['user_id']
    amount = float(request.form.get('amount'))
    
    # Check balance
    balance = db.execute("SELECT balance FROM accounts WHERE user_id = ?", (user_id,)).fetchone()[0]
    
    if balance >= amount:
        # RACE CONDITION: Balance could change between check and withdrawal
        # Two concurrent requests could overdraw the account
        time.sleep(0.1)  # Simulate processing delay
        
        new_balance = balance - amount
        db.execute("UPDATE accounts SET balance = ? WHERE user_id = ?", (new_balance, user_id))
        
        return "Withdrawal successful"
    
    return "Insufficient funds"


# Weak randomness in security context

import random

def generate_password_reset_token(user_id):
    """Predictable token generation
    CWE-330: Use of Insufficiently Random Values
    """
    # random.random() is NOT cryptographically secure!
    # Pattern matching might not flag this as it's not obvious
    token = str(random.randint(100000, 999999))
    
    db.execute("INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)", (user_id, token))
    
    return token


# Session fixation

@app.route('/login', methods=['POST'])
def login():
    """Session fixation vulnerability
    CWE-384: Session Fixation
    """
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = authenticate(username, password)
    
    if user:
        # Missing: session.regenerate()
        # Attacker can fixate the session ID before login
        # CWE-384: Session not regenerated after authentication
        session['user_id'] = user.id
        session['username'] = user.username
        
        return redirect('/dashboard')
    
    return "Login failed"


# Information disclosure through error messages

@app.route('/api/user/<user_id>')
def get_user_api(user_id):
    """Verbose error messages leak information
    CWE-209: Information Exposure Through Error Message
    """
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user:
            # Leaking information: tells attacker which IDs exist
            return {"error": f"User with ID {user_id} does not exist in database table 'users' (column 'id')"}
        
        # Also missing authorization check (CWE-639)
        return {"user": user}
        
    except Exception as e:
        # Leaking stack traces and database structure
        return {"error": str(e), "type": type(e).__name__}


# ORM injection (looks parameterized but isn't)

@app.route('/search')
def search():
    """ORM injection - looks safe but isn't
    CWE-89: SQL Injection (ORM variant)
    """
    search_term = request.args.get('q')
    sort_by = request.args.get('sort', 'name')
    
    # This LOOKS parameterized but sort_by is injected directly into SQL
    # Pattern matching might miss this
    query = f"SELECT * FROM products WHERE name LIKE ? ORDER BY {sort_by}"
    
    results = db.execute(query, (f"%{search_term}%",)).fetchall()
    
    return {"results": results}


# Integer overflow in price calculation

@app.route('/checkout', methods=['POST'])
def checkout():
    """Integer overflow vulnerability
    CWE-190: Integer Overflow
    """
    items = request.json.get('items', [])
    
    total = 0
    for item in items:
        quantity = int(item['quantity'])
        price = int(item['price'])
        
        # No overflow check! 
        # User could set quantity to 2^31 and get negative total
        total += quantity * price
    
    # If total overflowed to negative, user gets paid to buy!
    if total > 0:
        charge_customer(total)
        
    return {"total": total}


# Weak JWT implementation

import jwt

@app.route('/api/token')
def create_token():
    """Weak JWT implementation
    Multiple issues: CWE-327, CWE-347
    """
    user_id = session['user_id']
    
    # Issue 1: Using 'none' algorithm is dangerous
    # Issue 2: Weak secret
    # Issue 3: No expiration
    # Pattern matching won't catch the semantic issues
    token = jwt.encode(
        {'user_id': user_id},
        'secret123',  # Hardcoded weak secret
        algorithm='HS256'
    )
    
    return {"token": token}


# Template injection (context-dependent)

@app.route('/preview')
def preview_template():
    """Server-Side Template Injection
    CWE-94: Code Injection
    """
    template_string = request.args.get('template', 'Hello World')
    
    # Dangerous: rendering user-controlled template
    # In Jinja2 context, this allows code execution
    # Pattern matching might not understand the framework context
    return render_template_string(template_string)


# Missing rate limiting

failed_login_attempts = {}

@app.route('/api/login', methods=['POST'])
def api_login():
    """Missing rate limiting - brute force vulnerability
    CWE-307: Improper Restriction of Excessive Authentication Attempts
    """
    username = request.json.get('username')
    password = request.json.get('password')
    
    # No rate limiting! Attacker can brute force passwords
    # This is a business logic flaw that pattern matching won't catch
    user = authenticate(username, password)
    
    if user:
        return {"success": True, "token": generate_token(user)}
    
    return {"success": False}, 401


# Insecure direct object reference with partial validation

@app.route('/document/<doc_id>/delete', methods=['POST'])
def delete_document(doc_id):
    """IDOR with insufficient validation
    CWE-639: Authorization Bypass Through User-Controlled Key
    """
    current_user = get_current_user()
    
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    
    # Weak check: only verifies document exists, not ownership!
    if not doc:
        return "Document not found", 404
    
    # Missing: if doc.owner_id != current_user.id: return 403
    # User can delete ANY document by guessing IDs
    db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
    
    return "Deleted"


if __name__ == '__main__':
    # Debug mode in production - CWE-489
    app.run(debug=True, host='0.0.0.0')



