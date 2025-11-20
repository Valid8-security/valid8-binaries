#!/bin/bash
echo "=== Checking Vercel-GitHub Link Status ==="
echo ""

# Check if .vercel folder exists
if [ -d ".vercel" ]; then
    echo "✅ .vercel folder exists"
    if [ -f ".vercel/project.json" ]; then
        echo "✅ Project configuration found"
        cat .vercel/project.json | python3 -m json.tool 2>/dev/null || cat .vercel/project.json
    else
        echo "⚠️  No project.json found"
    fi
else
    echo "❌ No .vercel folder - project not linked locally"
fi

echo ""
echo "=== To Check in Vercel Dashboard ==="
echo "1. Go to: https://vercel.com/dashboard"
echo "2. Find your project"
echo "3. Settings → Git"
echo "4. Check if 'Valid8-security/parry-scanner' is connected"
echo ""
echo "=== To Link GitHub Repo ==="
echo "1. Vercel Dashboard → Add New Project"
echo "2. Import: Valid8-security/parry-scanner"
echo "3. Configure and Deploy"
