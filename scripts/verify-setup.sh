#!/usr/bin/env bash
# Verify the combined local DISPTCHR workspace after `npm run dev`.

set -e

echo "=== DISPTCHR workspace verification ==="

# 1. Backend health check
echo ""
echo "1. Workforce API through the gateway..."
HEALTH=$(curl -sf http://127.0.0.1:5050/api/health 2>/dev/null || echo '{"status":"error"}')
echo "   Response: $HEALTH"
if echo "$HEALTH" | grep -q '"status":"ok"'; then
  echo "   ✓ API, MongoDB, and file storage are connected"
else
  echo "   ✗ API is not healthy — check work/dev-logs/api.log"
  exit 1
fi

# 2. Guard web development surface / gateway check
echo ""
echo "2. Guard development surface through the gateway..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5050/ 2>/dev/null || echo "000")
echo "   HTTP status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
  echo "   ✓ Guard development surface is up"
else
  echo "   ✗ Guard development surface is not responding — check work/dev-logs/employee-app.log"
  exit 1
fi

echo ""
echo "3. Manager Portal..."
MANAGER_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5050/manager/ 2>/dev/null || echo "000")
if [ "$MANAGER_CODE" != "200" ]; then
  echo "   ✗ Manager Portal is not responding — check work/dev-logs/manager-portal.log"
  exit 1
fi
echo "   ✓ Manager Portal is up"

echo ""
echo "4. Disptchr Panel and control connection..."
PANEL_HEALTH=$(curl -sf http://127.0.0.1:3000/api/health 2>/dev/null || echo '{"status":"error"}')
if ! echo "$PANEL_HEALTH" | grep -q '"status":"ok"'; then
  echo "   ✗ Disptchr Panel is not healthy — check work/dev-logs/control-panel.log"
  exit 1
fi
echo "   ✓ Disptchr Panel, managed PostgreSQL, and the workforce control connection are healthy"

echo ""
echo "5. Notification worker..."
if ! pgrep -f "[j]ob_worker.py" >/dev/null 2>&1; then
  echo "   ✗ Notification worker is not running — check work/dev-logs/notification-worker.log"
  exit 1
fi
echo "   ✓ Notification worker is running"

echo ""
echo "=== All local runtime checks passed. ==="
