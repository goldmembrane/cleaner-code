#!/bin/bash
set -e

# ===== Configuration =====
PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-asia-northeast3}"  # Seoul
SERVICE_NAME="cleaner-code-api"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "=== cleaner-code AI API — Cloud Run Deploy ==="
echo "Project:  ${PROJECT_ID}"
echo "Region:   ${REGION}"
echo "Service:  ${SERVICE_NAME}"
echo ""

# Move to project root
cd "$(dirname "$0")/../.."

# Build TypeScript
echo "[1/4] Building TypeScript..."
npm run build

# Build Docker image
echo "[2/4] Building Docker image..."
docker build -f deploy/gcp/Dockerfile -t "${IMAGE_NAME}:latest" .

# Push to GCR
echo "[3/4] Pushing to Container Registry..."
docker push "${IMAGE_NAME}:latest"

# Deploy to Cloud Run
echo "[4/4] Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE_NAME}:latest" \
  --platform managed \
  --region "${REGION}" \
  --memory 2Gi \
  --cpu 2 \
  --min-instances 0 \
  --max-instances 10 \
  --timeout 60 \
  --concurrency 20 \
  --port 8080 \
  --allow-unauthenticated \
  --set-env-vars "NODE_ENV=production,API_VALIDATE_URL=https://cleanercode.dev/api/validate-key,USAGE_URL=https://cleanercode.dev/api/usage"

# Get URL
URL=$(gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --format 'value(status.url)')
echo ""
echo "=== Deployed ==="
echo "URL: ${URL}"
echo "Health: ${URL}/health"
echo "Analyze: POST ${URL}/api/analyze"
