# Feedback System Implementation Guide

## Current State

**What exists:**
- ✅ `parry renew` command collects feedback
- ✅ Validates minimum 20 characters
- ✅ Shows email/URL for submission
- ✅ Debug logging if enabled

**What's missing:**
- ❌ No actual submission mechanism
- ❌ No tracking/storage
- ❌ No admin dashboard
- ❌ No automated processing
- ❌ No email automation

---

## Complete Feedback System Design

### Architecture Overview

```
User → CLI → Storage → Admin Dashboard → Action
  ↓       ↓        ↓           ↓              ↓
renew  Submit   Database    View         Approve/Deny
       button   or File     Metrics      Extend License
```

---

## Implementation Options

### Option 1: Simple File-Based (Recommended for Beta)

**Pros:**
- ✅ No infrastructure needed
- ✅ Privacy-preserving
- ✅ Fast to implement
- ✅ Works offline

**Cons:**
- ⚠️ Manual admin review
- ⚠️ No real-time tracking

**Implementation:**
```python
# parry/feedback.py
class FeedbackManager:
    def submit_renewal_request(email: str, feedback: str, metrics: dict):
        """Submit feedback to local file"""
        feedback_data = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'feedback': feedback,
            'metrics': metrics,
            'status': 'pending',
            'license_info': get_license_info()
        }
        
        # Save to file
        feedback_file = Path.home() / '.parry' / 'feedback_queue.jsonl'
        feedback_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(feedback_file, 'a') as f:
            f.write(json.dumps(feedback_data) + '\n')
```

**Admin Process:**
```bash
# Admin reviews feedback
cat ~/.parry/feedback_queue.jsonl | jq 'select(.status=="pending")'

# Admin approves
parry-admin approve-renewal --email X --days 90
```

---

### Option 2: Email-Based (Recommended for Start)

**Pros:**
- ✅ Simple, familiar
- ✅ No infrastructure
- ✅ Works immediately
- ✅ Easy to archive

**Cons:**
- ⚠️ Manual processing
- ⚠️ No automation

**Implementation:**
```python
def submit_renewal_request(email: str, feedback: str):
    """Submit feedback via email"""
    import smtplib
    from email.mime.text import MIMEText
    
    subject = f"Beta Renewal Request: {email}"
    body = f"""
    Email: {email}
    License Expires: {get_expiration_date(email)}
    Days Left: {get_days_left(email)}
    
    Feedback:
    {feedback}
    
    Usage Metrics:
    {json.dumps(get_usage_metrics(email), indent=2)}
    """
    
    # Send to admin email
    send_email('beta@parry.ai', subject, body)
```

---

### Option 3: GitHub Issues (Recommended for Public Beta)

**Pros:**
- ✅ Public/transparent
- ✅ Automatic tracking
- ✅ Discussion threads
- ✅ Searchable

**Cons:**
- ⚠️ Requires GitHub token
- ⚠️ Public exposure

**Implementation:**
```python
def submit_renewal_request(email: str, feedback: str):
    """Submit feedback via GitHub Issue"""
    import requests
    
    # Create issue on GitHub
    url = 'https://api.github.com/repos/Parry-AI/parry-scanner/issues'
    headers = {'Authorization': f'token {os.getenv("GITHUB_TOKEN")}'}
    
    issue = {
        'title': f'Beta Renewal Request: {email}',
        'body': f"""
        ## Renewal Request
        
        **Email:** {email}
        **Expires:** {get_expiration_date(email)}
        **Days Left:** {get_days_left(email)}
        
        ### Feedback
        {feedback}
        
        ### Usage Metrics
        ```json
        {json.dumps(get_usage_metrics(email), indent=2)}
        ```
        
        ---
        Status: Pending Review
        """,
        'labels': ['beta-renewal', 'pending']
    }
    
    response = requests.post(url, json=issue, headers=headers)
    issue_number = response.json()['number']
    
    console.print(f"\n[green]✓ Renewal request #{issue_number} created[/green]")
    console.print(f"   View: https://github.com/Parry-AI/parry-scanner/issues/{issue_number}")
```

---

### Option 4: Server API (Recommended for Paid Launch)

**Pros:**
- ✅ Automated processing
- ✅ Real-time tracking
- ✅ Dashboard analytics
- ✅ Email integration

**Cons:**
- ⚠️ Requires server infrastructure
- ⚠️ More complex
- ⚠️ Privacy concerns (if public API)

**Implementation:**
```python
def submit_renewal_request(email: str, feedback: str):
    """Submit feedback to backend API"""
    import requests
    
    url = 'https://api.parry.dev/beta/renewal'
    
    payload = {
        'email': email,
        'feedback': feedback,
        'metrics': get_usage_metrics(email),
        'license_info': get_license_info()
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('auto_approved'):
            console.print("[green]✓ Renewal approved! License extended.[/green]")
        else:
            console.print("[yellow]Renewal submitted for review[/yellow]")
```

---

## Recommended Implementation: Hybrid Approach

### Phase 1: Email + GitHub Issues (Beta)

**Implementation:**
```python
def submit_renewal_request(email: str, feedback: str):
    """Multi-channel submission"""
    
    # 1. Save locally (backup)
    save_local_feedback(email, feedback)
    
    # 2. Create GitHub Issue (public tracking)
    issue_url = create_github_issue(email, feedback)
    
    # 3. Send email (private notification)
    send_admin_email(email, feedback, issue_url)
    
    # 4. Log analytics
    log_renewal_request(email, feedback)
```

### Phase 2: Server API (Paid)

**Add server-side processing:**
- Auto-approval logic
- Email notifications
- Dashboard analytics
- Stripe integration

---

## Complete Implementation

Let me implement the recommended hybrid approach:

