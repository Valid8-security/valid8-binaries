# How to Link GitHub Repo to Vercel

## Current Status
❓ **Unknown** - Need to check if repo is linked

## How Vercel Auto-Deployment Works

1. **Git Integration**: Vercel watches your GitHub repo
2. **Webhook**: GitHub sends webhook to Vercel on push
3. **Auto-Deploy**: Vercel automatically deploys changes
4. **Build**: Vercel runs build process
5. **Deploy**: New version goes live

## Check if Already Linked

### Option 1: Vercel Dashboard
1. Go to https://vercel.com/dashboard
2. Find your project (valid8code.ai or similar)
3. Go to **Settings** → **Git**
4. Check if "Valid8-security/parry-scanner" is connected

### Option 2: Check .vercel folder
```bash
cat .vercel/project.json
```

## Link GitHub Repo to Vercel

### Method 1: Via Vercel Dashboard (Recommended)

1. **Go to Vercel Dashboard**
   - https://vercel.com/dashboard

2. **Find or Create Project**
   - If project exists: Click on it → Settings
   - If new: Click "Add New" → Project

3. **Import Git Repository**
   - Click "Import Git Repository"
   - Search for: `Valid8-security/parry-scanner`
   - Click "Import"

4. **Configure Project**
   - Framework Preset: Other
   - Root Directory: `./` (or leave default)
   - Build Command: (leave empty for serverless functions)
   - Output Directory: (leave empty)

5. **Environment Variables** (if needed)
   - Add: `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, etc.

6. **Deploy**
   - Click "Deploy"
   - Vercel will deploy from GitHub

### Method 2: Via Vercel CLI

```bash
# Link existing project
vercel link

# Or create new project and link
vercel --prod
```

## After Linking

Once linked:
- ✅ Every `git push` triggers auto-deployment
- ✅ Vercel shows deployment status in dashboard
- ✅ You can see build logs
- ✅ Preview deployments for PRs

## Verify Auto-Deployment

1. Make a small change:
   ```bash
   echo "# Test" >> README.md
   git add README.md
   git commit -m "Test auto-deploy"
   git push
   ```

2. Check Vercel Dashboard:
   - Should see new deployment starting
   - Takes 1-2 minutes to complete

## Current Deployment Status

Since we just pushed to GitHub:
- If linked: Deployment should be starting now
- If not linked: Need to link first, then push again or trigger deploy

## Manual Deployment (If Not Linked)

If repo is not linked, you can still deploy manually:

```bash
# Deploy from current directory
vercel --prod --yes

# Or deploy specific files
vercel --prod --yes --archive=tgz
```

But GitHub linking is much better for:
- Automatic deployments
- Faster builds (only changed files)
- Preview deployments
- Better CI/CD integration
