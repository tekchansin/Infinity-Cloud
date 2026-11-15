#!/bin/bash
# Local test: wrangler dev (local D1, real sources) + curl. Run: ./test.sh
set -u
cd "$(dirname "$0")"
rm -rf .wrangler/state
wrangler d1 execute infinity-meta --local --file=schema.sql >/dev/null || exit 1
wrangler dev --local --port 8798 >/tmp/meta-dev.log 2>&1 &
PID=$!; trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 60); do curl -s localhost:8798/v1/health | grep -q ok && break; sleep 1; done
B=http://localhost:8798
fail=0; check() { if echo "$2" | grep -q "$3"; then echo "PASS $1"; else echo "FAIL $1: ${2:0:300}"; fail=1; fi; }
t0=$(date +%s); R=$(curl -s "$B/v1/artist?name=Jennifer%20Warnes&lang=en"); t1=$(date +%s)
check artist-ok "$R" '"status":"ok"'
check artist-bio "$R" '"intro":'
check artist-links "$R" '⟦'
check artist-photo "$R" '"photoUrl":"https://'
echo "  cold: $((t1 - t0)) s"
t0=$(date +%s); R2=$(curl -s "$B/v1/artist?name=jennifer%20warnes&lang=en"); t1=$(date +%s)
check cached "$R2" '"mbid"'
echo "  cached: $((t1 - t0)) s"
check thai "$(curl -s "$B/v1/artist?name=Bodyslam&lang=th")" '"lang":"th"'
check unknown "$(curl -s "$B/v1/artist?name=zzqqxx%20nobody&lang=en")" '"status":"none"'
check no-name "$(curl -s "$B/v1/artist")" 'name required'
exit $fail
