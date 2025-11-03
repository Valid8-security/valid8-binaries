# Feedback Options for Closed-Source Product

Since Parry is **not open source**, GitHub Issues won't work for public feedback/requests.

Here are your options:

---

## Option 1: Simple Email Workflow (Recommended for Beta)

**How it works:**
- Users email: beta@parry.ai
- Admin checks inbox
- Manual processing

**Pros:**
- ✅ Simple, no infrastructure
- ✅ Works immediately
- ✅ Private
- ✅ Professional

**Cons:**
- ⚠️ No automatic tracking
- ⚠️ Manual review process
- ⚠️ Harder to search

**Setup:**
```
1. Forward beta@parry.ai → your email
2. Check inbox daily
3. Reply to approvals with token
```

---

## Option 2: Web Form + Google Sheets

**How it works:**
- Google Form for beta requests
- Responses → Google Sheet
- Admin reviews sheet
- Email tokens to approved users

**Pros:**
- ✅ Free
- ✅ Automatic tracking
- ✅ Searchable
- ✅ Can add more fields

**Cons:**
- ⚠️ Requires Google account
- ⚠️ Not as professional
- ⚠️ Some users may not trust Google

**Setup:**
```
1. Create Google Form: forms.google.com
2. Add fields: Name, Email, Use Case, Project Size
3. Link form responses to Google Sheet
4. Check sheet daily
5. Send tokens via email
```

---

## Option 3: Custom Feedback System (API-Based)

**How it works:**
- User submits via CLI → posts to your API
- Admin views on simple dashboard
- Approve via web interface

**Implementation:**
```python
# parry/feedback.py update
def submit_renewal_request(email, feedback):
    # POST to api.parry.dev/feedback
    requests.post('https://api.parry.dev/feedback', json={...})
```

**Pros:**
- ✅ Professional
- ✅ Automatic tracking
- ✅ Real-time updates
- ✅ Integrated with CLI

**Cons:**
- ❌ Requires server infrastructure
- ❌ More complex
- ❌ Ongoing costs

---

## Option 4: Hybrid Approach (Email + Forms)

**Best of both worlds:**

**For beta applications:**
- Google Form (or Typeform/Zapier)
- Responses tracked automatically
- Admin reviews → approves

**For renewal requests:**
- Email only
- Admin checks inbox
- Manual approval

**Why this works:**
- Beta signups: More volume, needs tracking
- Renewals: Less volume, email is fine

---

## Recommended: Email + Google Form Hybrid

### Setup

**1. Google Form:**
```
https://forms.google.com/create

Fields:
- Name
- Email
- Company/Organization
- Use Case
- Project Size
- How did you hear about Parry?

Post to: Google Sheet
```

**2. Google Sheet Processing:**
```
Check sheet daily
Column: "Status" (Pending/Approved)
Admin marks "Approved" when token generated
```

**3. Email for Renewals:**
```
Users email: beta@parry.ai
Admin checks inbox
Reply with renewal confirmation
```

### Workflow

**New Beta Signup:**
1. User fills Google Form
2. Response in Google Sheet
3. Admin reviews → approves
4. Generate token: `parry admin generate-token --email X`
5. Email user with welcome + token
6. Mark "Approved" in sheet

**Renewal Request:**
1. User emails: beta@parry.ai
2. Admin checks inbox
3. Generate new token (90 more days)
4. Email user with token

---

## Updated Admin Workflow (Without GitHub)

**Daily Routine:**

**Morning (10 min):**
```
1. Check Google Sheet for new beta applications
2. Check email inbox for renewals
3. Review and filter applications
```

**Processing (5 min per user):**
```
1. If approved:
   parry admin generate-token --email user@example.com
   
2. Send welcome email (copy template)
   
3. Mark "Approved" in Google Sheet
```

**Evening (5 min):**
```
1. Review issued tokens:
   parry admin list-tokens
   
2. Follow up on pending applications if needed
```

---

## Alternative to Google: Other Tools

### Typeform
- More professional forms
- Paid ($25/mo)
- Better UX

### Airtable
- Database + forms
- $10/mo
- More structured data

### Notion Forms
- Simple integration
- If already using Notion
- Free tier available

### Zapier + Email
- Automated workflows
- Connect form → email → sheets
- $20/mo+

---

## Recommended Setup

**For Beta Launch (Starting Simple):**

**Phase 1: Email Only**
```
beta@parry.ai → Your email
Check daily
Manually track in spreadsheet or notes
```

**Phase 2: Add Google Form**
```
Google Form for signups
Email for renewals
Google Sheet for tracking
```

**Phase 3: Scale (If Needed)**
```
Custom dashboard
API integration
Advanced analytics
```

---

## Updated Marketing Materials

### Remove GitHub References

**Reddit Post:**
```
OLD: Request Beta: github.com/Parry-AI/parry-scanner/issues
NEW: Request Beta: parry.dev/beta or email beta@parry.ai
```

**HackerNews:**
```
OLD: Get Beta: Open GitHub issue
NEW: Get Beta: Email beta@parry.ai
```

**Landing Page:**
```
OLD: "Open GitHub Issue"
NEW: "Request Beta Access" (button → form/email)
```

---

## Quick Implementation

**Right Now:**
1. ✅ Use email for everything: beta@parry.ai
2. ✅ Check inbox daily
3. ✅ Track manually (Notes or spreadsheet)

**This Week:**
1. ⏸️ Set up Google Form
2. ⏸️ Create Google Sheet
3. ⏸️ Update marketing materials
4. ⏸️ Test signup flow

**Next Week:**
1. ⏸️ Launch with form
2. ⏸️ Monitor responses
3. ⏸️ Iterate based on volume

---

## Updated Workflow Summary

**Old (GitHub Issues - Won't Work):**
```
User → GitHub Issue → Admin sees → Approves → Token
```

**New (Email/Form - Will Work):**
```
User → Email/Form → Admin sees → Approves → Token
```

**Same process, different input!**

The admin workflow, token generation, and delivery remain the same.

---

**Bottom line:** Use email + Google Form instead of GitHub Issues. Same result, works with closed source.

