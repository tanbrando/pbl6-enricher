#!/bin/bash
# ============================================================
# Safe Deployment - Không động vào Loki/Grafana hiện có
# Author: tanbrando
# Date: 2025-01-08 03:08:52 UTC
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "============================================================"
echo "🔒 Safe Deployment - Log Parser API Only"
echo "============================================================"
echo "User: tanbrando"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
echo "⚠️  This will NOT touch existing Loki/Grafana containers"
echo "   Only deploy Log Parser API as new service"
echo ""

# Check existing containers
echo "📊 Current containers on this system:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | head -10
echo ""

read -p "Continue deployment? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Check .env.production
if [ ! -f ".env.production" ]; then
    echo -e "${RED}❌ .env.production not found!${NC}"
    echo ""
    echo "Please create it:"
    echo "  cp .env.example .env.production"
    echo "  nano .env.production"
    echo ""
    exit 1
fi

# Check for Azure OpenAI key
if ! grep -q "AZURE_OPENAI_API_KEY=sk-" .env.production && \
   ! grep -q "AZURE_OPENAI_API_KEY=.*[a-zA-Z0-9]" .env.production; then
    echo -e "${YELLOW}⚠️  Azure OpenAI API key looks empty${NC}"
    echo "   AI features will be disabled"
    echo ""
fi

# Detect network name
echo ""
echo -e "${BLUE}[INFO]${NC} Detecting Docker network..."
NETWORK_NAME=$(docker network ls --format '{{.Name}}' | grep -i monitoring | head -1)

if [ -z "$NETWORK_NAME" ]; then
    echo -e "${YELLOW}⚠️  No 'monitoring' network found${NC}"
    echo ""
    echo "Available networks:"
    docker network ls
    echo ""
    read -p "Enter the network name to use (or press Enter to create new): " CUSTOM_NETWORK
    
    if [ -z "$CUSTOM_NETWORK" ]; then
        echo "Creating new 'monitoring' network..."
        docker network create monitoring
        NETWORK_NAME="monitoring"
    else
        NETWORK_NAME="$CUSTOM_NETWORK"
    fi
fi

echo -e "${GREEN}✓${NC} Using network: $NETWORK_NAME"

# Update docker-compose.yml with correct network name
sed -i.bak "s/name: monitoring_default/name: $NETWORK_NAME/" docker-compose.yml

# Build image
echo ""
echo -e "${BLUE}[INFO]${NC} Building Docker image..."
docker build -t tanbrando/log-parser:1.0.0 .

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Docker build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Docker image built successfully"

# Start service
echo ""
echo -e "${BLUE}[INFO]${NC} Starting log-parser container..."
docker-compose --env-file .env.production up -d

# Wait for health check
echo ""
echo -e "${BLUE}[INFO]${NC} Waiting for service to be healthy..."
for i in {1..30}; do
    if curl -s http://localhost:5000/health > /dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

# Check status
if curl -s http://localhost:5000/health | grep -q "ok"; then
    AI_STATUS=$(curl -s http://localhost:5000/health | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    
    echo ""
    echo "============================================================"
    echo -e "${GREEN}✅ SUCCESS - Log Parser API is running!${NC}"
    echo "============================================================"
    echo ""
    echo "📊 All containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    echo "🔗 Access:"
    echo "   API:    http://localhost:5000"
    echo "   Health: http://localhost:5000/health"
    echo "   Docs:   http://localhost:5000/"
    echo ""
    
    if [ "$AI_STATUS" == "enabled" ]; then
        echo -e "🤖 AI Analysis: ${GREEN}✅ ENABLED${NC}"
    else
        echo -e "🤖 AI Analysis: ${YELLOW}⚠️  DISABLED${NC} (check .env.production)"
    fi
    
    echo ""
    echo "✅ Existing Loki/Grafana containers: UNCHANGED"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Test API: curl http://localhost:5000/health | jq"
    echo "   2. Add datasource to Grafana (see docs)"
    echo "   3. View logs: docker-compose logs -f log-parser"
    echo ""
    echo "============================================================"
else
    echo -e "${RED}❌ Failed to start!${NC}"
    echo ""
    echo "Check logs:"
    docker-compose logs log-parser
    exit 1
fi