# Admin Access to Feedback from Multiple Machines

## Current Issue

**Problem:** Feedback is stored locally on each user's machine
```
User 1 Machine: ~/.parry/feedback/renewal_queue.jsonl
User 2 Machine: ~/.parry/feedback/renewal_queue.jsonl
User 3 Machine: ~/.parry/feedback/renewal_queue.jsonl
...
Admin Machine: ~/.parry/feedback/renewal_queue.jsonl (empty, only local)
```

**Result:** Admins can't see feedback from other users!

---

## Solution Options

### Option 1: GitHub Issues (Recommended for Beta)

**How it works:**
- When user submits feedback, automatically create GitHub Issue
- All issues visible in one place: `github.com/Parry-AI/parry-scanner/issues`
- Automatic tracking, labeling, searchable

**Implementation:** Already built! Just need GitHub token.

**Enable it:**
```bash
# User sets their GitHub token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx

# User submits feedback
parry renew --feedback "Found 50+ bugs!"
# → Automatically creates GitHub Issue
```

**Admin view:**
```bash
# Option 1: Visit GitHub
https://github.com/Parry-AI/parry-scanner/issues?q=is%3Aissue+is%3Aopen+label%3Abeta-renewal

# Option 2: Use GitHub CLI
gh issue list --label "beta-renewal,pending-review"
```

**Pros:**
- ✅ Centralized access
- ✅ Public/transparent
- ✅ Automatic tracking
- ✅ Discussion threads
- ✅ Searchable
- ✅ Already implemented

**Cons:**
- ⚠️ Requires GitHub token
- ⚠️ Public visibility
- ⚠️ Users opt-in

**Status:** ✅ Ready to use

---

### Option 2: Email Notifications

**How it works:**
- User submits feedback
- System sends email to admin
- Admin reviews in email inbox

**Implementation:** To be added

**Admin view:**
```
Inbox: beta@parry.ai
Subject: "Beta Renewal Request: user@example.com"
Body: Feedback + license details
```

**Pros:**
- ✅ Familiar workflow
- ✅ Push notifications
- ✅ No infrastructure
- ✅ Private

**Cons:**
- ⚠️ Manual review process
- ⚠️ Hard to track status
- ⚠️ Not searchable

**Status:** ⏸️ To implement

---

### Option 3: Server API (Paid Launch)

**How it works:**
- User submits feedback to `api.parry.dev/feedback/submit`
- All feedback stored in database
- Admin dashboard shows all submissions

**Implementation:** To be built

**Admin view:**
```
https://admin.parry.dev/feedback
  ├── Dashboard
  ├── Renewal Requests: 15 pending
  ├── Bug Reports: 23 new
  └── Feature Requests: 8
```

**Pros:**
- ✅ Centralized database
- ✅ Real-time updates
- ✅ Analytics dashboard
- ✅ Auto-approval logic
- ✅ Email notifications

**Cons:**
- ❌ Requires server infrastructure
- ❌ Privacy concerns
- ❌ Complex implementation
- ❌ Ongoing costs

**Status:** ⏸️ Future (Paid launch)

---

### Option 4: File Upload via S3/Dropbox

**How it works:**
- User submits feedback → automatically uploads to cloud storage
- Admin downloads aggregated file
- Review in bulk

**Implementation:** To be built

**Admin view:**
```bash
# Download all feedback
aws s3 cp s3://parry-feedback/renewal_queue.jsonl ./all_renewals.jsonl

# Review
parry list-feedback --file ./all_renewals.jsonl
```

**Pros:**
- ✅ Centralized storage
- ✅ Automatic upload
- ✅ Privacy-preserving
- ✅ Batch processing

**Cons:**
- ⚠️ Requires cloud storage
- ⚠️ Manual download
- ⚠️ Not real-time

**Status:** ⏸️ Future

---

## Recommended: Hybrid Approach

### Phase 1: GitHub Issues (Beta Launch)

**For Users:**
```bash
# Set GitHub token (optional)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx

# Submit feedback (creates GitHub Issue if token set)
parry renew --feedback "Great tool!"

# Still saves locally for backup
# → ~/.parry/feedback/renewal_queue.jsonl
```

**For Admins:**
```bash
# View all renewals
gh issue list --label "beta-renewal" --limit 100

# View specific renewal
gh issue view 123

# Close when approved
gh issue close 123
```

**Why This Works:**
- ✅ No server infrastructure needed
- ✅ Public transparency
- ✅ Automatic tracking
- ✅ Already implemented
- ✅ Works immediately

---

### Phase 2: Email + Dashboard (Month 2)

**Add email notifications:**
```python
# After GitHub issue created
send_email(
    to='admin@parry.dev',
    subject=f"New Renewal Request: {email}",
    body=f"View: {issue_url}"
)
```

**Add simple dashboard:**
```bash
# Aggregate GitHub issues
parry admin dashboard --from github
```

---

### Phase 3: Full API (Paid Launch)

**Build backend:**
- API endpoints
- Database storage
- Admin dashboard
- Auto-approval
- Analytics

---

## Immediate Solution: Enable GitHub Integration

### Step 1: Create GitHub Token

**For Admin:**
1. GitHub → Settings → Developer settings → Personal access tokens
2. Generate token with `repo` scope
3. Copy token

### Step 2: Share Token with Users (or not)

**Option A: Public Token (Recommended for Beta)**
```bash
# Users can use this token for issues
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
```

**Option B: No Token (Privacy Mode)**
```bash
# Users don't set token
# Feedback stays local only
# Admin can't see it
```

**Option C: Per-User Tokens**
- Each user generates own token
- Uses their own GitHub account
- Feedback created by them

### Step 3: Admin Reviews on GitHub

**View all feedback:**
```
https://github.com/Parry-AI/parry-scanner/issues
Filter by: label:beta-renewal AND label:pending-review
```

**Process feedback:**
1. Review issue
2. Approve or deny
3. Close issue
4. Extend license if approved

---

## Implementation Status

### Current (Local Only)

**What works:**
- ✅ Users can submit feedback
- ✅ Feedback saved locally
- ✅ `parry list-feedback` shows local only

**What doesn't:**
- ❌ Admin can't see other users' feedback
- ❌ No centralized access
- ❌ Manual collection needed

### With GitHub Integration (Recommended)

**What works:**
- ✅ Users can submit feedback
- ✅ Feedback saved locally + GitHub
- ✅ Admin sees all issues on GitHub
- ✅ Automatic tracking

**How to enable:**
```bash
# User (optional, for auto-GitHub issue)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
parry renew --feedback "..."

# Admin
gh issue list --label "beta-renewal"
# or visit: github.com/Parry-AI/parry-scanner/issues
```

---

## Recommended Workflow for Beta

### User Side

**Privacy-conscious users (no GitHub):**
```bash
# Just use local storage
parry renew --feedback "..."

# Manually email admin
Email: beta@parry.ai
Subject: Renewal Request
Body: [Feedback]
```

**GitHub-enabled users:**
```bash
# Set token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxx

# Submit (auto-creates issue)
parry renew --feedback "..."

# Done! Issue automatically visible
```

### Admin Side

**Daily routine:**
```bash
# Check for new issues
gh issue list --label "beta-renewal" --state open

# Review each issue
gh issue view <number>

# Process renewal
# ... decide approve/deny ...

# Close issue
gh issue close <number> --comment "License extended"
```

**Or via GitHub web:**
1. Visit: https://github.com/Parry-AI/parry-scanner/issues
2. Filter by: `label:beta-renewal label:pending-review`
3. Review submissions
4. Approve/deny
5. Close issue

---

## Migration Path

### Week 1: Launch (GitHub Optional)
- Users submit feedback locally
- Optional GitHub if token set
- Admin checks GitHub issues

### Week 2: Email Added
- Add email notifications
- Admin gets alerts
- Reply to approve/deny

### Month 2: Dashboard
- Build simple aggregator
- Parse GitHub issues
- Show statistics

### Month 4: Full API (Paid)
- Backend infrastructure
- Database storage
- Real-time updates

---

## Quick Start: Enable GitHub Now

### For Users (Optional)

**Option 1: Use Admin's Token (Simplest)**
```bash
# Admin shares token
export GITHUB_TOKEN=ghp_admin_token_here

# Submit feedback
parry renew --feedback "Found 50+ bugs!"
# → Creates issue as admin
```

**Option 2: Use Own Token**
```bash
# User creates own token
# Set it
export GITHUB_TOKEN=ghp_my_token_here

# Submit feedback
parry renew --feedback "Found 50+ bugs!"
# → Creates issue as user
```

**Option 3: No Token**
```bash
# Don't set token
# Feedback only local

# Manually email or post issue
```

### For Admin

**Review on GitHub:**
```bash
# Using GitHub CLI
gh issue list --label "beta-renewal" --limit 50

# Or visit website
open "https://github.com/Parry-AI/parry-scanner/issues?q=is%3Aissue+is%3Aopen+label%3Abeta-renewal"
```

**Auto-filter for pending:**
```
Add to browser bookmark:
https://github.com/Parry-AI/parry-scanner/issues?q=is%3Aissue+is%3Aopen+label%3Abeta-renewal+label%3Apending-review
```

---

## Summary

**Current State:**
- ✅ Feedback submission works locally
- ❌ Admin can't see feedback from other machines

**Immediate Solution:**
- ✅ GitHub Issues integration **already built**
- ⏸️ Just need GitHub token
- ⏸️ Users set token (optional)
- ⏸️ Admin reviews on GitHub

**Recommended:**
1. **Tell users about GitHub integration** (optional)
2. **Admin monitors GitHub issues** for feedback
3. **Alternative:** Users email admin if privacy desired
4. **Build API later** for paid launch

**For Beta Launch:**
- Use GitHub Issues (already implemented)
- Admin reviews on GitHub
- Manual approval process
- Simple and effective

---

The infrastructure is ready! Just need to share GitHub token with users or have them create their own.

