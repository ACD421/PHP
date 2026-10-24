#!/bin/bash
# (re)start the cloudflare quick tunnel (http2 — UDP/QUIC blocked on this net)
for pid in $(pgrep -f "cloudflared"); do
  [ "$pid" != "$$" ] && kill "$pid" 2>/dev/null
done
sleep 2
rm -f /tmp/cf_tunnel.log
nohup cloudflared tunnel --url http://127.0.0.1:8085 --protocol http2 --edge-ip-version 4 > /tmp/cf_tunnel.log 2>&1 &
sleep 12
URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /tmp/cf_tunnel.log | head -1)
echo "URL=$URL"
echo "registered=$(grep -cE 'Registered tunnel connection' /tmp/cf_tunnel.log)"
# pin the URL locally so the weapon (running in WSL) can resolve it
HOST=$(echo "$URL" | sed 's|https://||')
IP=$(getent hosts "$HOST" | awk '{print $1}' | head -1)
if [ -z "$IP" ]; then
  # WSL DNS is dead — resolve via the Windows host side is not scriptable here;
  # cloudflared edge anycast IPs also serve the hostname: use the pinned CF IP
  IP=104.16.230.132
fi
grep -q "$HOST" /etc/hosts || echo "$IP $HOST" | sudo -n tee -a /etc/hosts >/dev/null
echo "pinned $HOST -> $IP"
curl -s --max-time 25 "$URL/up.php"
