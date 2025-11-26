# Vercel Deployment

This project is configured for deployment on Vercel.

## Setup

1. Install Vercel CLI:
   ```bash
   npm i -g vercel
   ```

2. Deploy:
   ```bash
   vercel
   ```

3. For production:
   ```bash
   vercel --prod
   ```

## API Endpoints

- `GET /api` - Health check
- `POST /api` - Scan code for vulnerabilities

## Configuration

- `vercel.json` - Vercel configuration
- `api/index.py` - Serverless function handler
- `api/requirements.txt` - Python dependencies
- `.vercelignore` - Files to exclude from deployment
