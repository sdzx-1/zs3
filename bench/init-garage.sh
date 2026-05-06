#!/usr/bin/env bash
# Bring Garage up, assign cluster layout, create a bucket+key for benchmarking.
# Prints exported AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY at the end.
set -euo pipefail

cd "$(dirname "$0")"

docker compose up -d

# Wait for the admin API to respond
echo "Waiting for Garage to start..."
for _ in $(seq 1 30); do
  if docker exec zs3-bench-garage /garage status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Assign layout if not already applied
if ! docker exec zs3-bench-garage /garage layout show 2>&1 | grep -q "^==== CURRENT CLUSTER LAYOUT ====" \
   || docker exec zs3-bench-garage /garage layout show 2>&1 | grep -q "No nodes currently have a role"; then
  NODE_ID=$(docker exec zs3-bench-garage /garage status | awk 'NR>2 && /NO ROLE ASSIGNED/ {print $1; exit}')
  if [ -z "${NODE_ID:-}" ]; then
    NODE_ID=$(docker exec zs3-bench-garage /garage node id -q 2>/dev/null | cut -d@ -f1)
  fi
  echo "Assigning layout to node: $NODE_ID"
  docker exec zs3-bench-garage /garage layout assign -z dc1 -c 1G "$NODE_ID"
  docker exec zs3-bench-garage /garage layout apply --version 1
fi

# Create benchmark bucket
docker exec zs3-bench-garage /garage bucket create benchbucket 2>/dev/null || true
docker exec zs3-bench-garage /garage bucket create concbench 2>/dev/null || true

# Create key (idempotent: ignore if it exists, then re-fetch info)
docker exec zs3-bench-garage /garage key create bench-key 2>/dev/null || true
KEY_INFO=$(docker exec zs3-bench-garage /garage key info bench-key --show-secret)
ACCESS_KEY=$(echo "$KEY_INFO" | awk '/Key ID:/ {print $3}')
SECRET_KEY=$(echo "$KEY_INFO" | awk '/Secret key:/ {print $3}')

# Grant key access on both buckets
docker exec zs3-bench-garage /garage bucket allow --read --write --owner benchbucket --key bench-key >/dev/null
docker exec zs3-bench-garage /garage bucket allow --read --write --owner concbench   --key bench-key >/dev/null

echo
echo "Garage ready at http://localhost:3900"
echo "  AWS_ACCESS_KEY_ID=$ACCESS_KEY"
echo "  AWS_SECRET_ACCESS_KEY=$SECRET_KEY"
