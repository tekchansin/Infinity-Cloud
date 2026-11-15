#!/bin/bash
# Local smoke test: wrangler dev (local D1) + curl. Run: ./test.sh
set -u
cd "$(dirname "$0")"
rm -rf .wrangler/state  # fresh local D1 each run (rate-limit rows would carry over)
wrangler d1 execute infinity-share --local --file=schema.sql >/dev/null || exit 1
wrangler dev --local --port 8799 --var ADMIN_KEY:testadmin --var REVIEW_ADMIN_KEY:testreview >/tmp/share-dev.log 2>&1 &
PID=$!; trap 'kill $PID 2>/dev/null' EXIT
for i in $(seq 1 60); do curl -s localhost:8799/v1/list?type=harmonic >/dev/null && break; sleep 1; done
B=http://localhost:8799
fail=0; check() { if echo "$2" | grep -q "$3"; then echo "PASS $1"; else echo "FAIL $1: $2"; fail=1; fi; }

R=$(curl -s -X POST $B/v1/submit -H 'content-type: application/json' \
  -d '{"type":"listening","name":"  HD800S‮ warm ","author":"Tek","headphone":"HD800S","dap":"DX340MAX","amp":"Internal","payload":{"v":1}}')
check submit "$R" '"token"'
ID=$(echo "$R" | sed -E 's/.*"id":"([A-Z0-9]+)".*/\1/'); TOK=$(echo "$R" | sed -E 's/.*"token":"([a-f0-9]+)".*/\1/')
check list "$(curl -s "$B/v1/list?type=listening&dap=DX340MAX")" "\"id\":\"$ID\""
check clean-name "$(curl -s "$B/v1/list?type=listening")" '"name":"HD800S warm"'
check search "$(curl -s "$B/v1/list?type=listening&q=800")" "$ID"
check search-miss "$(curl -s "$B/v1/list?type=listening&q=zzz")" '"items":\[\]'
check cors "$(curl -si "$B/v1/list?type=listening" | tr A-Z a-z)" 'access-control-allow-origin: \*'
check item-no-count "$(curl -s $B/v1/item/$ID)" '"downloads":0'
check payload "$(curl -s $B/v1/item/$ID)" '"payload":{"v":1}'
check download "$(curl -s -X POST $B/v1/item/$ID/download)" '"downloads":1'
check download-404 "$(curl -s -X POST $B/v1/item/ZZZZZZZZ/download)" 'not found'
check dx320-list "$(curl -s "$B/v1/list?type=listening&dap=DX320")" '"items"'
check bad-dap "$(curl -s -X POST $B/v1/submit -d '{"type":"listening","name":"a","author":"b","headphone":"c","dap":"iPhone","payload":{}}')" 'bad dap'
check no-headphone "$(curl -s -X POST $B/v1/submit -d '{"type":"listening","name":"a","author":"b","dap":"DX340","payload":{}}')" 'headphone required'
check amp-unknown-dropped "$(curl -s -X POST $B/v1/submit -d '{"type":"harmonic","name":"u","author":"b","dap":"DX270","amp":"Unknown","payload":{"v":1}}' >/dev/null; curl -s "$B/v1/list?type=harmonic&dap=DX270")" '"amp":""'
check harmonic-no-hp "$(curl -s -X POST $B/v1/submit -d '{"type":"harmonic","name":"a","author":"b","dap":"DX340","payload":{"v":1}}')" '"token"'
check not-owner "$(curl -s -X DELETE $B/v1/item/$ID -H 'authorization: Bearer deadbeef')" 'not owner'
check owner-del "$(curl -s -X DELETE $B/v1/item/$ID -H "authorization: Bearer $TOK")" '"ok":true'
check gone "$(curl -s $B/v1/item/$ID)" 'not found'
H=$(curl -s "$B/v1/list?type=harmonic" | sed -E 's/.*"id":"([A-Z0-9]+)".*/\1/')
check admin-del "$(curl -s -X DELETE $B/v1/item/$H -H 'x-admin-key: testadmin')" '"ok":true'
# ── website reviews ──
J='content-type: application/json'
check rv-preflight "$(curl -si -X OPTIONS $B/v1/reviews | tr A-Z a-z)" 'access-control-allow-headers: content-type, x-admin-key'
check rv-submit "$(curl -s -X POST $B/v1/reviews -H "$J" -d '{"author":"Tek","dap":"DX340","headphone":"HD800S","text":"Great mod, sounds amazing on my DX340!\n\n\n\nSecond paragraph."}')" '"ok":true'
check rv-hidden-until-approved "$(curl -s $B/v1/reviews)" '"items":\[\]'
check rv-short "$(curl -s -X POST $B/v1/reviews -H "$J" -d '{"author":"a","text":"too short"}')" 'too short'
check rv-bad-dap "$(curl -s -X POST $B/v1/reviews -H "$J" -d '{"author":"a","dap":"iPhone","text":"long enough review text here"}')" 'bad dap'
check rv-honeypot "$(curl -s -X POST $B/v1/reviews -H "$J" -d '{"author":"bot","website":"x","text":"buy cheap watches buy cheap watches"}')" '"ok":true'
check rv-pending-noauth "$(curl -s $B/v1/reviews/pending)" 'admin only'
P=$(curl -s $B/v1/reviews/pending -H 'x-admin-key: testreview')
check rv-pending "$P" '"author":"Tek"'
check rv-honeypot-dropped "$(echo "$P" | grep -c '"author":"bot"')" '^0$'
check rv-paragraphs "$P" 'DX340!\\n\\nSecond'
RV=$(echo "$P" | sed -E 's/.*"id":"([A-Z0-9]+)".*/\1/')
SID=$(curl -s -X POST $B/v1/submit -d '{"type":"harmonic","name":"k","author":"b","dap":"DX340","payload":{"v":1}}' | sed -E 's/.*"id":"([A-Z0-9]+)".*/\1/')
check rv-key-cannot-delete-shares "$(curl -s -X DELETE $B/v1/item/$SID -H 'x-admin-key: testreview')" 'missing token'
check rv-approve "$(curl -s -X POST $B/v1/reviews/$RV/approve -H 'x-admin-key: testreview')" '"ok":true'
check rv-public "$(curl -s $B/v1/reviews)" '"author":"Tek"'
check rv-public-no-ip "$(curl -s $B/v1/reviews | grep -c ip_hash)" '^0$'
check rv-delete "$(curl -s -X DELETE $B/v1/reviews/$RV -H 'x-admin-key: testreview')" '"ok":true'
check rv-gone "$(curl -s $B/v1/reviews)" '"items":\[\]'
for i in 1 2 3 4; do RL=$(curl -s -X POST $B/v1/reviews -H "$J" -d '{"author":"r","text":"another long enough review"}'); done
check rv-rate-limit "$RL" 'too many'
for i in $(seq 1 12); do L=$(curl -s -X POST $B/v1/submit -d '{"type":"harmonic","name":"r","author":"b","dap":"DX340","payload":{"v":1}}'); done
check rate-limit "$L" 'too many'
# ── log reports ──
LR=$(curl -s -X POST $B/v1/logs -H "$J" -d '{"dap":"DX340","version":"12.1-abc-beta","note":"scan stuck","report":"THREADS\n\"main\" WAITING\nline2"}')
check log-submit "$LR" '"id"'
LID=$(echo "$LR" | sed -E 's/.*"id":"([A-Z0-9]+)".*/\1/')
check log-list-noauth "$(curl -s $B/v1/logs)" 'admin only'
check log-get-noauth "$(curl -s $B/v1/logs/$LID)" 'admin only'
check log-review-key-denied "$(curl -s $B/v1/logs -H 'x-admin-key: testreview')" 'admin only'
check log-list "$(curl -s $B/v1/logs -H 'x-admin-key: testadmin')" "\"id\":\"$LID\""
check log-get "$(curl -s $B/v1/logs/$LID -H 'x-admin-key: testadmin')" 'Note: scan stuck'
check log-get-body "$(curl -s $B/v1/logs/$LID -H 'x-admin-key: testadmin')" '"main" WAITING'
check log-bad-dap "$(curl -s -X POST $B/v1/logs -H "$J" -d '{"dap":"iPhone","version":"1","report":"x"}')" 'bad dap'
check log-no-report "$(curl -s -X POST $B/v1/logs -H "$J" -d '{"dap":"DX340","version":"1"}')" 'report required'
printf '{"dap":"DX340","version":"1","report":"%s"}' "$(head -c 800000 /dev/zero | tr '\0' a)" >/tmp/share-biglog.json
check log-too-large "$(curl -s -X POST $B/v1/logs -H "$J" --data-binary @/tmp/share-biglog.json)" 'report too large'
check log-delete "$(curl -s -X DELETE $B/v1/logs/$LID -H 'x-admin-key: testadmin')" '"ok":true'
check log-gone "$(curl -s $B/v1/logs/$LID -H 'x-admin-key: testadmin')" 'not found'
for i in $(seq 1 6); do LL=$(curl -s -X POST $B/v1/logs -H "$J" -d '{"dap":"DX340","version":"1","report":"x"}'); done
check log-rate-limit "$LL" 'too many'
exit $fail
