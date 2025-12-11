# ============================================================================
# KATARAKT - Deployment Makefile
# Usage: make deploy
# ============================================================================

.PHONY: all init deploy destroy cloudflare-only gcp-only help

# Default target
all: help

# Initialize Terraform
init:
	@echo " Initializing Terraform..."
	cd terraform && terraform init

# Deploy everything (Cloudflare + GCP)
deploy: init
	@echo " Deploying Katarakt..."
	cd terraform && terraform apply -auto-approve
	@echo ""
	@echo " Deployment complete!"
	@echo " Your shield is now active at: https://$(SUBDOMAIN).$(DOMAIN)"

# Deploy only to Cloudflare Workers (faster, edge-only)
cloudflare-only:
	@echo " Deploying to Cloudflare Workers..."
	cd terraform && terraform apply -target=cloudflare_worker_script.katarakt \
		-target=cloudflare_worker_route.katarakt \
		-target=cloudflare_record.katarakt \
		-auto-approve

# Deploy only to Google Cloud
gcp-only:
	@echo " Deploying to Google Cloud..."
	cd terraform && terraform apply -target=google_cloud_run_v2_service.katarakt \
		-target=google_compute_security_policy.katarakt \
		-auto-approve

# Destroy all infrastructure
destroy:
	@echo " Destroying infrastructure..."
	cd terraform && terraform destroy -auto-approve

# Show deployment plan
plan:
	cd terraform && terraform plan

# Export browser configs
export-userjs:
	@echo " Exporting Firefox user.js..."
	curl -s https://$(SUBDOMAIN).$(DOMAIN)/api/export/userjs > katarakt-user.js
	@echo "Saved to katarakt-user.js"

export-policies:
	@echo " Exporting Chrome policies..."
	curl -s https://$(SUBDOMAIN).$(DOMAIN)/api/export/policies > policies.json
	@echo "Saved to policies.json"

# Development - run locally
dev:
	@echo " Starting local development..."
	wrangler dev cloudflare-worker.js

# Tail Cloudflare Worker logs
logs:
	wrangler tail katarakt-security

# Help
help:
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════╗"
	@echo "║              KATARAKT DEPLOYMENT COMMANDS                 ║"
	@echo "╠═══════════════════════════════════════════════════════════╣"
	@echo "║  make deploy         - Deploy everything                  ║"
	@echo "║  make cloudflare-only- Deploy only Cloudflare Worker      ║"
	@echo "║  make gcp-only       - Deploy only Google Cloud           ║"
	@echo "║  make destroy        - Tear down all infrastructure       ║"
	@echo "║  make plan           - Preview changes                    ║"
	@echo "║  make dev            - Run locally for development        ║"
	@echo "║  make logs           - Tail Cloudflare Worker logs        ║"
	@echo "║  make export-userjs  - Download Firefox hardening config  ║"
	@echo "║  make export-policies- Download Chrome policies           ║"
	@echo "╚═══════════════════════════════════════════════════════════╝"
	@echo ""

# Variables (override with: make deploy DOMAIN=example.com)
DOMAIN ?= idarti.com
SUBDOMAIN ?= shield
