# Quick Deployment Guide - valid8code.ai

## Prerequisites
- ✅ Domain: valid8code.ai (Namecheap)
- ✅ Vercel account (free tier)
- ✅ GitHub repository

## Deployment Steps

### 1. Install Vercel CLI
```bash
npm i -g vercel
```

### 2. Login to Vercel
```bash
vercel login
```

### 3. Deploy
```bash
cd /Users/sathvikkurapati/Downloads/valid8-local
vercel --prod
```

### 4. Configure Domain in Vercel
1. Go to Vercel Dashboard → Project → Settings → Domains
2. Add domain: `valid8code.ai`
3. Add domain: `www.valid8code.ai` (optional)

### 5. Configure DNS in Namecheap

**Option A: Vercel Nameservers (Recommended)**
1. Namecheap → Domain List → Manage → Advanced DNS
2. Change nameservers to:
   - `ns1.vercel-dns.com`
   - `ns2.vercel-dns.com`
3. Wait 5-60 minutes for propagation

**Option B: A Records (Alternative)**
1. Namecheap → Advanced DNS → Add New Record
2. A Record:
   - Host: `@`
   - Value: `76.76.21.21` (check Vercel docs for current IP)
3. CNAME Record:
   - Host: `www`
   - Value: `cname.vercel-dns.com`

### 6. Verify
```bash
curl https://valid8code.ai/api
# Should return: {"status": "ok", "service": "Valid8 API", ...}
```

## Quick Commands

```bash
# Deploy to production
vercel --prod

# Deploy preview
vercel

# View logs
vercel logs

# List deployments
vercel ls
```

## Cost
- **Free Tier:** $0/month (100GB bandwidth, sufficient for MVP)
- **Pro Tier:** $20/month (unlimited bandwidth, recommended for production)

## Support
- Vercel Docs: https://vercel.com/docs
- Vercel Dashboard: https://vercel.com/dashboard
