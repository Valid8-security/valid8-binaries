# Namecheap DNS Setup for valid8code.ai

## Quick Setup (A Records Method - Recommended)

Since Namecheap is asking for personal nameservers, use **A Records** instead. This is simpler and works immediately.

### Step-by-Step Instructions

#### 1. Login to Namecheap
- Go to: https://www.namecheap.com
- Login to your account

#### 2. Navigate to Domain
- Click: **Domain List** (top menu)
- Find: **valid8code.ai**
- Click: **Manage** button

#### 3. Go to Advanced DNS
- Click: **Advanced DNS** tab
- Scroll to: **Host Records** section

#### 4. Add A Record for Root Domain (@)

Click **Add New Record** button, then:

```
Type:        A Record
Host:        @
Value:       76.76.21.21
TTL:         Automatic (or 30 min)
```

Click the **checkmark (✓)** to save.

#### 5. Add CNAME for www (Optional but Recommended)

Click **Add New Record** again:

```
Type:        CNAME Record
Host:        www
Value:       cname.vercel-dns.com
TTL:         Automatic (or 30 min)
```

Click the **checkmark (✓)** to save.

#### 6. Remove Old Records (if any)
- Delete any existing A records pointing to other IPs
- Delete any existing CNAME records for www

#### 7. Save All Changes
- Make sure all records are saved (green checkmarks)
- Changes take effect immediately, but propagation takes 5-60 minutes

---

## What Happens Next

1. **DNS Propagation:** 5-60 minutes
   - You can check with: `nslookup valid8code.ai` or `dig valid8code.ai`

2. **Vercel Verification:** Automatic
   - Vercel will detect the DNS changes
   - Domain will show as "Valid" in Vercel dashboard

3. **SSL Certificate:** Automatic
   - Vercel provisions SSL automatically
   - Takes a few minutes after domain verification

4. **Site Goes Live:**
   - https://valid8code.ai will work
   - https://www.valid8code.ai will work (if CNAME added)

---

## Verify DNS is Working

After 5-60 minutes:

```bash
# Check DNS resolution
nslookup valid8code.ai

# Test API
curl https://valid8code.ai/api
```

Expected response:
```json
{"status": "ok", "service": "Valid8 API", "version": "1.0.0"}
```

---

## Troubleshooting

### If DNS doesn't resolve after 60 minutes:
1. Double-check A record value is: `76.76.21.21`
2. Verify record is saved (green checkmark)
3. Check Vercel dashboard for domain status
4. Try: `dig valid8code.ai` to see DNS propagation

### If Vercel shows domain as invalid:
1. Make sure A record is correct
2. Wait a bit longer (DNS can take up to 60 minutes)
3. Check Vercel dashboard for specific error messages

### Alternative IP (if 76.76.21.21 doesn't work):
- Check Vercel dashboard → Domains → valid8code.ai
- Vercel will show the correct IP address to use
- Update A record with that IP

---

## Summary

**What to do:**
1. Namecheap → Domain List → valid8code.ai → Manage
2. Advanced DNS → Host Records
3. Add A Record: `@` → `76.76.21.21`
4. Add CNAME: `www` → `cname.vercel-dns.com`
5. Save and wait 5-60 minutes

**That's it!** Vercel handles the rest automatically.
