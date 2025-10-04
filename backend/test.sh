#!/bin/bash

# .env에서 값 읽기
source .env

echo "Testing Atlas API..."
echo "Project ID: $ATLAS_PROJECT_ID"

curl -i -u "$ATLAS_PUBLIC_KEY:$ATLAS_PRIVATE_KEY" \
  "https://cloud.mongodb.com/api/atlas/v1.0/groups/$ATLAS_PROJECT_ID"
