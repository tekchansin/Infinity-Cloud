#!/bin/sh
# Deploy, telling /v1/health the SHA-256 of the source that runs — the copy published at github.com/tekchansin/Infinity-Cloud
# hashes the same (shasum -a 256 src/index.js).
set -e
cd "$(dirname "$0")"
npx wrangler deploy --var SOURCE_SHA256:"$(shasum -a 256 src/index.js | cut -d" " -f1)"
