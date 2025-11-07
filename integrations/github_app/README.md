# Parry GitHub App Integration

🚀 **One-Click Security Scanning for GitHub Repositories**

Instant adoption with OAuth-based installation and automated security scanning for pull requests and pushes.

## ✨ Features

- **One-Click Installation** - OAuth flow for instant setup per repository
- **Automated PR Scanning** - Security scan on every pull request
- **Status Checks** - Block merges on critical security issues
- **PR Comments** - Detailed vulnerability reports in pull request discussions
- **Push Scanning** - Continuous monitoring of main/master branches
- **Caching** - Smart caching to avoid redundant scans

## 🚀 Quick Start

### 1. Create GitHub App

1. Go to [GitHub App Settings](https://github.com/settings/apps/new)
2. Upload the `github-app-manifest.yaml` file or configure manually:
   - **Name:** Parry Security Scanner
   - **Homepage URL:** https://parry.ai
   - **Webhook URL:** `https://your-domain.com/webhook`
   - **Permissions:**
     - Contents: Read
     - Pull requests: Write
     - Statuses: Write
     - Checks: Write
     - Metadata: Read
   - **Events:** Pull request, Push, Installation

### 2. Deploy the Service

#### Using Docker (Recommended)
```bash
# Build the image
docker build -t parry-github-app .

# Run with environment variables
docker run -p 5000:5000 \
  -e GITHUB_APP_ID=your-app-id \
  -e GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..." \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  parry-github-app
```

#### Using Python
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GITHUB_APP_ID=your-app-id
export GITHUB_PRIVATE_KEY="$(cat private-key.pem)"
export GITHUB_WEBHOOK_SECRET=your-webhook-secret

# Run the service
python app.py
```

### 3. Install on Repository

1. Go to your repository settings
2. Navigate to "Integrations" → "Applications"
3. Search for "Parry Security Scanner"
4. Click "Install" and select repositories
5. Done! Automatic scanning is now active

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_APP_ID` | GitHub App ID | ✅ |
| `GITHUB_PRIVATE_KEY` | App private key (PEM format) | ✅ |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for signature verification | ✅ |
| `GITHUB_CLIENT_ID` | OAuth client ID (optional) | ❌ |
| `GITHUB_CLIENT_SECRET` | OAuth client secret (optional) | ❌ |

### Webhook Security

The app verifies webhook signatures using HMAC-SHA256:

```python
expected_signature = hmac.new(
    webhook_secret.encode(),
    request_body,
    hashlib.sha256
).hexdigest()
```

## 🎯 Workflow Integration

### Pull Request Scanning

1. **Trigger:** PR opened, updated, or reopened
2. **Scan:** Repository scanned with hybrid mode
3. **Status:** Commit status updated (success/failure)
4. **Comment:** Detailed results posted to PR

### Push Scanning

1. **Trigger:** Push to main/master branch
2. **Scan:** Full repository security scan
3. **Status:** Commit status reflects security health

### Status Check Examples

```yaml
# Success (no critical issues)
✅ Security scan passed (3 issues found)

# Failure (critical issues found)
❌ 2 critical security issues found

# Warning (high severity issues)
⚠️ 3 high severity security issues
```

## 📊 API Endpoints

### Health Check
```http
GET /health
```

### Webhook Handler
```http
POST /webhook
Content-Type: application/json
X-GitHub-Event: pull_request|push|installation
X-Hub-Signature-256: sha256=...
```

### Installation Flow
- User clicks "Install" on GitHub
- OAuth redirect to your app
- Store installation ID for future API calls
- Generate installation access tokens

## 🔐 Security Features

- **Webhook Verification** - HMAC signature validation
- **JWT Authentication** - GitHub App authentication
- **Installation Tokens** - Scoped, time-limited access
- **Rate Limiting** - Built-in request throttling
- **Audit Logging** - Comprehensive event logging

## 📈 Performance Optimization

### Caching Strategy
- **Installation Tokens:** Cached with automatic refresh
- **Scan Results:** Cached for 1 hour to avoid redundant scans
- **Repository Metadata:** Cached to reduce API calls

### Scaling Considerations
- **Horizontal Scaling:** Stateless design supports multiple instances
- **Database:** Optional PostgreSQL for persistent caching
- **Queue System:** Redis/RabbitMQ for background processing

## 🧪 Testing

### Local Testing with ngrok
```bash
# Install ngrok
npm install -g ngrok

# Start local server
python app.py

# Expose to internet
ngrok http 5000

# Use ngrok URL as webhook URL in GitHub App
```

### Mock Webhook Testing
```bash
# Test PR webhook
curl -X POST http://localhost:5000/webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: pull_request" \
  -H "X-Hub-Signature-256: sha256=$(echo -n '{"action":"opened"}' | openssl dgst -sha256 -hmac 'your-secret' | cut -d' ' -f2)" \
  -d '{"action":"opened","pull_request":{"number":1},"repository":{"name":"test","owner":{"login":"user"}},"installation":{"id":123}}'
```

## 🔧 Troubleshooting

### Common Issues

**Webhook signature verification fails**
- Check `GITHUB_WEBHOOK_SECRET` is correct
- Ensure raw request body is used for HMAC calculation

**Installation token expired**
- Tokens auto-refresh, but check system clock sync
- Verify app has correct repository permissions

**Rate limiting**
- GitHub API has rate limits (5000/hour for apps)
- Implement exponential backoff for retries

### Logs and Debugging
```bash
# Enable debug logging
export FLASK_DEBUG=1
python app.py

# Check GitHub App logs in repository settings
# Navigate to App → Advanced → Delivery
```

## 🚀 Production Deployment

### Environment Setup
```bash
# Production environment variables
export GITHUB_APP_ID=12345
export GITHUB_WEBHOOK_SECRET=your-production-secret
export FLASK_ENV=production

# SSL certificate for HTTPS
# Configure reverse proxy (nginx/caddy)
```

### Monitoring
- **Health Checks:** `/health` endpoint
- **Metrics:** Request counts, success rates, latency
- **Alerts:** Failed webhook deliveries, authentication errors

## 📚 Related Documentation

- [GitHub Apps Documentation](https://docs.github.com/en/developers/apps)
- [Parry Security Scanner](../../README.md)
- [API Reference](../../docs/api/API_REFERENCE.md)

---

🛡️ **Instant security scanning for every GitHub repository**
