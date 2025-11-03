# Beta Onboarding Process - Complete Guide

## Overview

**Complete virtual onboarding process** for beta testers, from initial interest to active usage.

---

## User Journey: From Interested to Active

### Phase 1: Discovery & Application

**How users find Parry:**

1. **Reddit Post** (r/Python, r/webdev, r/programming)
   - "90% recall security scanner with local AI"
   - Link to GitHub or landing page

2. **HackerNews Post**
   - "Show HN: Privacy-first security scanner with 90% recall"
   - Discussion thread

3. **Twitter/Thread**
   - Security tips thread
   - Demo video/GIF
   - Link to beta signup

4. **Product Hunt Launch**
   - Landing page
   - Beta signup form

5. **Word of Mouth**
   - Early testers share
   - Direct recommendations

---

### Phase 2: Beta Application

**User Action:**
1. Clicks "Request Beta Access" or "Apply for Beta"
2. Lands on signup page/email

**Signup Options:**

#### Option A: Email Signup (Recommended for Beta)
```
To: beta@parry.ai
Subject: Beta Access Request
Body:
  Hi! I'd like to join the Parry beta program.
  
  Name: John Doe
  Email: john@example.com
  Use Case: Scanning Python project for security issues
  Project Size: ~500 files
  
  Why I want to test: Interested in privacy-first security scanning
```

#### Option B: Web Form (Recommended for Scale)
```
https://parry.dev/beta or forms.google.com
[Form fields:]
- Name
- Email
- Company/Organization
- Use case
- Project size
- How did you hear about Parry?

Responses tracked in Google Sheet
```

#### Option C: Landing Page (Future)
```
https://parry.dev/beta
Professional signup form
Backend database tracking
Email automation
```

---

### Phase 3: Admin Approval

**Admin receives notification:**

#### Via Email:
- Direct email to beta@parry.ai
- Email inbox notification

#### Via Google Form (if using):
- Email notification when form submitted
- Check Google Sheet for new responses

**Admin review:**
```
# Check email inbox
# Subject: "Beta Access Request"

# Or check Google Sheet
# New row added with timestamp
```

**Approval criteria:**
- ✅ Looks like real user (not spam)
- ✅ Valid email
- ✅ Use case reasonable
- ✅ Not duplicate request

**Admin approves by generating token:**
```bash
parry admin generate-token --email john@example.com
```

**Token generated:**
```
✓ Beta token generated!

Token: eyJlbWFpbCI6ICJqb2huQGV4YW1wbGUuY29tIiwgImV4...

⚠️  SEND THIS TOKEN TO USER SECURELY
```

---

### Phase 4: Token Delivery

**Admin sends welcome email:**

```
Subject: Welcome to Parry Beta! 🎉

Hi John,

Thanks for your interest in testing Parry! We're excited to have you on board.

Your Beta Access:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Token: eyJlbWFpbCI6ICJqb2huQGV4YW1wbGUuY29tIiwgImV4...

✅ Duration: 90 days of full Pro features

✅ What You Get:
   • Deep mode (90% recall)
   • AI-powered validation (reduce false positives)
   • Compliance reports
   • SCA scanning
   • Secrets detection
   • Multi-language support

Quick Start:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Install Parry:
   pip install parry-scanner

2. Run setup:
   parry setup

3. Activate your beta license:
   parry license --install beta --token eyJlbWFpbCI6ICJqb2huQGV4YW1wbGUuY29tIiwgImV4...

4. Scan your code:
   parry scan . --mode hybrid

Documentation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📚 GitHub: https://github.com/Parry-AI/parry-scanner
📖 Docs: Coming soon!
💬 Feedback: parry feedback "your feedback here"
🆘 Help: Open GitHub issue or email beta@parry.ai

Beta Expectations:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

We're still improving Parry and would love your feedback!

What we need from you:
• Use it on real projects
• Report bugs via: parry feedback --type bug "description"
• Request features via: parry feedback --type feature "idea"
• Share what you love and what's confusing

Thank you for being an early adopter!

The Parry Team
```

**Alternative: Slack/Discord/DM**
```
Thanks for applying! Here's your Parry beta token:

Token: eyJ...

Install: parry license --install beta --token eyJ...

Get started: https://github.com/Parry-AI/parry-scanner
```

---

### Phase 5: User Onboarding

**User installs Parry:**

```bash
# 1. Install
pip install parry-scanner

# 2. Setup (install Ollama, models)
parry setup

# 3. Activate beta license
parry license --install beta --token eyJlbWFpbCI6ICJqb2huQGV4YW1wbGUuY29t...

# Output:
✓ Beta license installed successfully!
Beta access expires in 90 days

# 4. Verify installation
parry license

# Output:
License Tier: BETA
Features: 9 features unlocked
Expires: In 90 days
```

**First scan:**
```bash
# Try on a test project first
parry scan /path/to/test/project --mode fast

# See results
# [29 vulnerabilities found]

# Try hybrid mode for best results
parry scan . --mode hybrid
```

---

### Phase 6: Ongoing Engagement

**Welcome email follow-up (Day 1):**
```
Subject: Getting started with Parry?

Hi John,

Hoping you're finding Parry useful! A few tips:

🧭 Quick Tips:
• Fast Mode: Quick checks during development (222 files/sec)
• Deep Mode: Thorough security reviews (90% recall)
• Hybrid Mode: Best of both worlds

📝 First Scan Suggestions:
• Start with a small project
• Use hybrid mode for comprehensive results
• Review findings carefully

❓ Questions?
Reply to this email or open a GitHub issue

Happy scanning!
```

**Engagement check (Day 7):**
```
Subject: How's Parry working for you?

Hi John,

Quick check-in - how's your Parry experience going?

We'd love to hear:
• What vulnerabilities are you finding?
• Any bugs or issues?
• Feature requests?

Reply or use: parry feedback "your thoughts"

Thanks!
```

**Renewal reminder (Day 75):**
```
Subject: Your beta expires in 15 days

Hi John,

Your Parry beta expires in 15 days.

Want to continue? Request renewal:
parry renew

Feedback helps us improve! Share your experience to extend access.

Thanks for being part of the beta!
```

---

## Admin Workflow Summary

### Daily Routine (15-20 min)

**Morning:**
```bash
# Check for new beta requests
gh issue list --label beta-request --state open

# Review each application
# Approve if genuine
```

**Processing:**
```bash
# Generate token for approved user
parry admin generate-token --email user@example.com

# Copy token
# Send welcome email (template above)
```

**Evening:**
```bash
# Track issued tokens
parry admin list-tokens

# Monitor for issues
```

---

## Onboarding Automation Options

### Current (Manual): ✅ Working

**Process:**
1. Admin checks GitHub/Email
2. Admin reviews application
3. Admin generates token
4. Admin sends email
5. User installs

**Time:** ~5 min per user
**Scalable:** Up to 100 users

---

### Future (Semi-Automated)

**GitHub Actions Integration:**
```yaml
# .github/workflows/beta-approval.yml

on:
  issues:
    types: [opened]

jobs:
  auto-approve:
    runs-on: ubuntu-latest
    if: contains(github.event.issue.labels.*.name, 'beta-request')
    steps:
      - name: Check criteria
        # Check if user looks genuine
      
      - name: Generate token
        run: parry admin generate-token --email $EMAIL
      
      - name: Comment on issue
        run: |
          echo "✅ Approved! Token: $TOKEN"
          gh issue comment --body "..."
```

**Email Automation:**
```python
# Send welcome email automatically
# Parse GitHub issue → extract email
# Generate token → send email
```

---

## Onboarding Metrics to Track

**Phase 1: Discovery**
- Website visits
- Signup clicks
- Beta applications

**Phase 2: Application**
- Applications received
- Approval rate
- Time to approval

**Phase 3: Installation**
- Tokens delivered
- Installation rate
- Setup completion rate

**Phase 4: Activation**
- Users who run first scan
- Feature adoption
- Engagement rate

**Phase 5: Retention**
- Daily active users
- Weekly active users
- Feature usage

---

## User Support During Onboarding

### Common Issues

**1. Installation Problems**
```
Issue: pip install fails
Solution: Check Python version, upgrade pip

Issue: parry setup fails
Solution: Check Ollama installation, internet connection
```

**2. License Issues**
```
Issue: Token invalid
Solution: Check token format, ensure admin generated correctly

Issue: Beta expired
Solution: Request renewal with feedback
```

**3. Scanning Issues**
```
Issue: No vulnerabilities found
Solution: Check if code is clean, try different mode

Issue: Too many false positives
Solution: Use hybrid mode with validation
```

**Support Channels:**
- GitHub Issues
- Email: beta@parry.ai
- In-app help: `parry --help`

---

## Onboarding Templates

### Welcome Email Template

```
Subject: Welcome to Parry Beta! 🎉

[Personalized greeting]

Your Beta Access Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Token: {TOKEN}
Duration: 90 days
Features: All Pro features unlocked

Quick Start (5 minutes):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. pip install parry-scanner
2. parry setup
3. parry license --install beta --token {TOKEN}
4. parry scan . --mode hybrid

Resources:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📚 Docs: github.com/Parry-AI/parry-scanner
💬 Feedback: parry feedback "your thoughts"
🆘 Help: parry --help or open GitHub issue

Thank you for testing Parry!

The Parry Team
```

### Follow-up Email Template (Day 7)

```
Subject: How's Parry working for you?

Hi {NAME},

Quick check-in - how's your Parry experience going?

We'd love your feedback:
• What vulnerabilities are you finding?
• Any bugs or questions?
• What features would you like?

Share feedback:
parry feedback "your thoughts"

Or reply to this email.

Thanks!

Parry Team
```

### Renewal Reminder Template (Day 75)

```
Subject: Your beta expires in 15 days

Hi {NAME},

Your Parry beta expires in {DAYS} days.

Want to continue? Request renewal:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

parry renew

Just share your experience to extend your access!

Thanks for being part of the beta.

Parry Team
```

---

## Summary

**Complete Onboarding:**
1. ✅ Discovery (social media, HN, Reddit)
2. ✅ Application (GitHub Issues or email)
3. ✅ Admin approval (manual review)
4. ✅ Token generation (virtual command)
5. ✅ Token delivery (email)
6. ✅ User installation (one command)
7. ✅ Engagement (follow-ups, support)

**All Virtual, No Physical Access Needed!**

Time per user: ~5 minutes
Scales to: 100+ beta users
Ready for: Launch tomorrow! 🚀

