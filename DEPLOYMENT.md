# KATARAKT Deployment Guide

## Quick Start (Recommended)

The simplest deployment uses Terraform to handle everything automatically:

```bash
# 1. Configure your credentials
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform.tfvars with your values

# 2. Set environment variables
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"

# 3. Deploy everything
make deploy
```

That's it. Your shield is now live at `https://shield.idarti.com`

---

## Architecture Decision: Where to Deploy?

### Option A: shield.idarti.com (Recommended)

Deploy as a subdomain of your main domain:

``` txt
shield.idarti.com  →  Katarakt Security Dashboard
api.idarti.com     →  Backend API (optional)
www.idarti.com     →  Main Idarti website
```

**Pros:**

- Unified brand identity
- Single SSL certificate (wildcard)
- Users trust your domain
- SEO benefits from domain authority

### Option B: Separate Domain (e.g., katarakt.io)

**Pros:**

- Can be sold/spun-off independently
- Separate brand identity
- No risk to main domain reputation

**Recommendation:** Use `shield.idarti.com` - it builds your brand and shows Katarakt is part of your security ecosystem.

---

## Deployment Methods

### Method 1: Terraform (Fully Automated)

Terraform deploys both Cloudflare and GCP resources in one command.

#### Prerequisites

```bash
# Install Terraform
brew install terraform  # macOS
# or: https://terraform.io/downloads

# Install gcloud CLI
brew install google-cloud-sdk  # macOS
# or: https://cloud.google.com/sdk/docs/install

# Install wrangler (Cloudflare CLI)
npm install -g wrangler
```

#### Setup

1. **Google Cloud Setup:**

```bash
# Authenticate
gcloud auth login
gcloud auth application-default login

# Create project (if needed)
gcloud projects create idarti-katarakt --name="Katarakt Security"
gcloud config set project idarti-katarakt

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

2.**Cloudflare Setup:**

```bash
# Login to wrangler
wrangler login

# Get your credentials from Cloudflare Dashboard:
# - Zone ID: cloudflare.com/[account]/[domain] → Overview → Zone ID
# - Account ID: URL shows dash.cloudflare.com/[account-id]
# - API Token: My Profile → API Tokens → Create Token
#   (Use "Edit Cloudflare Workers" template)
```

3.**Configure terraform.tfvars:**

```hcl
project_id            = "idarti-katarakt"
region                = "us-central1"
domain                = "idarti.com"
subdomain             = "shield"
cloudflare_zone_id    = "abc123..."
cloudflare_account_id = "def456..."
```

4.**Deploy:**

```bash
make deploy
```

---

### Method 2: Cloudflare-Only (Simplest)

If you just want the edge security without GCP backend:

```bash
# Login
wrangler login

# Deploy
wrangler deploy

# Done! Available at: katarakt-security.<your-subdomain>.workers.dev
```

To use your own domain:

```bash
# Add route in wrangler.toml
# routes = [{ pattern = "shield.idarti.com/*", zone_name = "idarti.com" }]

wrangler deploy
```

---

### Method 3: Google Cloud Only

If you prefer pure GCP (using Cloud Run + Cloud Armor):

```bash
# Build and push container
docker build -t gcr.io/idarti-katarakt/katarakt-backend .
docker push gcr.io/idarti-katarakt/katarakt-backend

# Deploy to Cloud Run
gcloud run services replace google-cloud-run.yaml --region=us-central1

# Create Cloud Armor policy
gcloud compute security-policies create katarakt-armor \
  --description="Katarakt security policy"

# Add rate limiting rule
gcloud compute security-policies rules create 1000 \
  --security-policy=katarakt-armor \
  --action=rate-based-ban \
  --rate-limit-threshold-count=1000 \
  --rate-limit-threshold-interval-sec=60 \
  --ban-duration-sec=600 \
  --conform-action=allow \
  --exceed-action=deny-429

# Map domain
gcloud beta run domain-mappings create \
  --service=katarakt-backend \
  --domain=shield.idarti.com \
  --region=us-central1
```

---

## How Users Experience Katarakt

Once deployed, the user journey is:

1. **Visit:** `https://shield.idarti.com`
2. **Click:** "Activate Shield" button
3. **Automatic:** Service worker installs, browser is hardened
4. **Optional:** Enable "Persistent Mode" for continuous protection
5. **Optional:** Export `user.js` for Firefox or `policies.json` for Chrome

The Cloudflare Worker automatically:

- Injects fingerprint protection on every page load
- Adds security headers to all responses
- Blocks bot traffic and trackers
- Rate-limits suspicious requests

---

## Monitoring & Logs

### Cloudflare Analytics

```bash
# Tail real-time logs
make logs
# or: wrangler tail katarakt-security
```

Dashboard: `dash.cloudflare.com` → Workers → katarakt-security → Analytics

### Google Cloud Monitoring

```bash
# View Cloud Run logs
gcloud logging read "resource.type=cloud_run_revision" --limit=50

# View Cloud Armor logs
gcloud logging read "resource.type=security_policy" --limit=50
```

Dashboard: `console.cloud.google.com` → Cloud Run → katarakt-backend

---

## Costs

### Cloudflare Workers (Free Tier)

- 100,000 requests/day free
- After: $5/month for 10M requests

### Google Cloud Run (Scale-to-Zero)

- Free tier: 2M requests/month
- After: ~$0.00002400/request
- **When idle: $0**

### Estimated Monthly Cost

| Traffic | Cloudflare | GCP | Total |
|---------|------------|-----|-------|
| 10K/day | Free       |Free |   $0  |
| 100K/day| Free       |Free |   $0  |
| 1M/day  |  $5        |~$15 |  ~$20 |

---

## Updating

```bash
# Update Cloudflare Worker only
wrangler deploy

# Update everything
make deploy

# Update GCP only
make gcp-only
```

---

## Troubleshooting

### "Terraform provider not found"

```bash
cd terraform && terraform init
```

### "Cloudflare authentication failed"

```bash
export CLOUDFLARE_API_TOKEN="your-token"
# Or create: ~/.cloudflare/credentials
```

### "GCP permission denied"

```bash
gcloud auth application-default login
gcloud services enable run.googleapis.com
```

### "Domain not resolving"

Wait 5-10 minutes for DNS propagation, then:

```bash
dig shield.idarti.com
```

---

## Security Checklist

Before going live:

- [ ] Enable HTTPS-only in Cloudflare
- [ ] Set minimum TLS version to 1.2
- [ ] Enable Cloudflare Bot Fight Mode
- [ ] Configure Cloud Armor rate limiting
- [ ] Test fingerprint protection at browserleaks.com
- [ ] Test WebRTC leak protection at ipleak.net
- [ ] Verify headers at securityheaders.com

---

## Next Steps

1. Deploy: `make deploy`
2. Test: Visit `https://shield.idarti.com`
3. Verify: Check browserleaks.com with shield active
4. Monitor: Set up alerts in Cloudflare/GCP dashboards
5. Iterate: Collect user feedback, improve protection

Questions? The architecture is designed to be hands-free once deployed.
