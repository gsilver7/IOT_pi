#!/bin/bash

# Find the project root directory (2 levels up from deployments/front/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Project root: $PROJECT_ROOT"
cd "$PROJECT_ROOT" || exit 1

# Pull latest changes
echo "Pulling latest changes from git..."
git pull origin master

# Check if pull was successful
if [ $? -ne 0 ]; then
    echo "Error: Git pull failed"
    exit 1
fi

# Build Docker image
echo "Building Docker image..."
docker build -f deployments/front/Dockerfile -t iot-front:latest .

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "Error: Docker build failed"
    exit 1
fi

# Stop and remove existing container if it exists
echo "Stopping existing container..."
docker stop iot-front 2>/dev/null
docker rm iot-front 2>/dev/null

# Run new container
echo "Starting new container..."
docker run -d \
    --name iot-front \
    -p 8080:80 \
    --restart unless-stopped \
    iot-front:latest

# Check if container started successfully
if [ $? -eq 0 ]; then
    echo "Deployment successful!"
    echo "Container is running on port 80"
    docker ps | grep iot-front
else
    echo "Error: Failed to start container"
    exit 1
fi
