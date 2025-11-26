# Namecheap DNS Setup - Step by Step

## ⚠️ Important: Use A Records, NOT Personal Nameservers

If Namecheap is asking for "personal nameserver", you're in the wrong section. 
Use **Host Records** instead (A Records and CNAME Records).

---

## Exact Steps for Namecheap

### Step 1: Login and Navigate
1. Go to: https://www.namecheap.com
2. Login to your account
3. Click: **Domain List** (top menu)
4. Find: **valid8code.ai** in the list
5. Click: **Manage** button (on the right)

### Step 2: Go to Advanced DNS
1. Click the **Advanced DNS** tab
2. Scroll down to find: **Host Records** section
   - This is where you add A and CNAME records
   - **NOT** the "Nameservers" section at the top

### Step 3: Add A Record for Root Domain

1. In the **Host Records** section, click: **Add New Record** button
2. A new row will appear
3. Fill in:
   - **Type:** Select `A Record` from dropdown
   - **Host:** Type `@` (just the @ symbol)
   - **Value:** Type `76.76.21.21`
   - **TTL:** Select `Automatic` (or 30 min)
4. Click the **green checkmark (✓)** to save

### Step 4: Add CNAME for www

1. Click **Add New Record** button again
2. Fill in:
   - **Type:** Select `CNAME Record` from dropdown
   - **Host:** Type `www`
   - **Value:** Type `cname.vercel-dns.com`
   - **TTL:** Select `Automatic` (or 30 min)
3. Click the **green checkmark (✓)** to save

### Step 5: Remove Old Records (if any)

- Look for any existing A records with Host = `@`
- If they point to a different IP, delete them (trash icon)
- Look for any existing CNAME records with Host = `www`
- If they point to something else, delete them

### Step 6: Verify Records

You should now have:
- ✅ One A Record: `@` → `76.76.21.21`
- ✅ One CNAME Record: `www` → `cname.vercel-dns.com`

Both should show green checkmarks.

---

## Visual Guide

**What you should see in Host Records:**

```
Type      Host    Value                  TTL
----      ----    -----                  ---
A Record  @       76.76.21.21            Automatic  ✓
CNAME     www     cname.vercel-dns.com   Automatic  ✓
```

---

## What NOT to Do

❌ **Don't use "Nameservers" section** (that's for personal nameservers)  
❌ **Don't use "Personal Nameserver"** option  
✅ **DO use "Host Records"** section with A and CNAME records

---

## After Saving

1. **Wait 5-60 minutes** for DNS propagation
2. **Check Vercel Dashboard:**
   - Go to: Settings → Domains
   - Domain should show as "Valid" when DNS propagates
3. **Test:**
   ```bash
   curl https://valid8code.ai/api
   ```

---

## If You Still See "Personal Nameserver" Prompt

You might be in the wrong section. Make sure you're in:
- ✅ **Advanced DNS** tab
- ✅ **Host Records** section (scroll down)
- ❌ NOT "Nameservers" section (at the top)

The "Host Records" section is where you add individual DNS records.
The "Nameservers" section is for changing your DNS provider entirely.

---

## Quick Reference

**Namecheap Location:**
Domain List → valid8code.ai → Manage → Advanced DNS → Host Records

**Records to Add:**
1. A Record: `@` → `76.76.21.21`
2. CNAME: `www` → `cname.vercel-dns.com`

**That's it!** No nameserver changes needed.
