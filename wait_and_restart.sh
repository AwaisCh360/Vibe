#!/bin/bash
set -e

OLD_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/awaisch360/vibe:main 2>/dev/null || echo "none")

echo "Waiting for GitHub Actions to build the new image with user-about API..."
while true; do
    docker pull ghcr.io/awaisch360/vibe:main > /dev/null 2>&1 || true
    NEW_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/awaisch360/vibe:main 2>/dev/null || echo "none")
    
    if [ "$NEW_DIGEST" != "$OLD_DIGEST" ] && [ "$OLD_DIGEST" != "none" ]; then
        echo "New image detected!"
        break
    elif [ "$OLD_DIGEST" = "none" ] && [ "$NEW_DIGEST" != "none" ]; then
        echo "Image pulled!"
        break
    fi
    echo -n "."
    sleep 30
done

echo "Restarting container..."
docker kill local-armur || true
docker rm local-armur || true
docker run -d --name local-armur -p 4500:4500 ghcr.io/awaisch360/vibe:main

echo "Container restarted! Swagger is ready."
