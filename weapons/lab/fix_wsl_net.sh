#!/bin/bash
# Pin DNS entries (WSL UDP/53 blocked; resolved on Windows side) + default route
sudo -n ip route replace default via 192.168.4.1 dev eth0 2>/dev/null
grep -q 'p2s-hosts' /etc/hosts || sudo -n tee -a /etc/hosts >/dev/null <<'EOF'
# p2s-hosts (WSL DNS workaround)
66.6.42.252 wordpress.org
54.39.182.210 getcomposer.org
143.244.60.196 repo.packagist.org
169.150.236.99 packagist.org
140.82.114.3 github.com
140.82.112.10 codeload.github.com
140.82.112.6 api.github.com
91.189.92.23 archive.ubuntu.com
91.189.90.11 security.ubuntu.com
98.91.159.177 registry-1.docker.io
104.16.100.215 production.cloudflare.docker.com
EOF
for u in https://wordpress.org/latest.tar.gz https://getcomposer.org/composer-stable.phar https://repo.packagist.org/packages.json; do
  code=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' "$u")
  echo "$code  $u"
done
