#!/bin/bash
set -e

echo "Pulling latest docker image..."
docker pull ghcr.io/awaisch360/vibe:main

echo "Restarting container..."
docker kill local-armur || true
docker rm local-armur || true
docker run -d --name local-armur -p 4500:4500 ghcr.io/awaisch360/vibe:main

echo "Waiting for server to start..."
sleep 5

echo "Triggering scan on DVNA..."
RESPONSE=$(curl -s -X POST http://localhost:4500/api/v1/scan/repo -H "Content-Type: application/json" -d '{"repository_url": "https://github.com/appsecco/dvna"}')
echo "Response: $RESPONSE"

TASK_ID=$(echo $RESPONSE | grep -o '"task_id":"[^"]*' | cut -d'"' -f4)
if [ -z "$TASK_ID" ]; then
    echo "Failed to get task ID"
    exit 1
fi

echo "Task ID: $TASK_ID"
echo "Polling status..."
for i in {1..600}; do
    STATUS=$(curl -s "http://localhost:4500/api/v1/status/$TASK_ID" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    if [ "$STATUS" = "success" ]; then
        echo "Scan complete!"
        curl -s "http://localhost:4500/api/v1/status/$TASK_ID?format=sarif" > dvna_results.sarif
        echo "Saved to dvna_results.sarif"
        exit 0
    elif [ "$STATUS" = "failed" ]; then
        echo "Scan failed!"
        curl -s "http://localhost:4500/api/v1/status/$TASK_ID"
        exit 1
    fi
    echo "Scan status: $STATUS (poll $i/600)"
    sleep 30
done
echo "Timeout waiting for scan"
exit 1
