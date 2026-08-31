#!/bin/sh
# Akamai, formerly Linode, Marketplace StackScript.
# github.com/akamai-compute-marketplace/marketplace-apps.
#
# Marketplace apps there are a StackScript that hands off to an Ansible
# playbook. This is the StackScript half, and it is deliberately the same three
# steps as deploy/templates/cloud-init.yaml: install Docker, fetch the compose
# bundle, start it. Submitting to the catalogue means adding the playbook half in
# their repository; running this by hand needs nothing from anybody.
#
# <UDF name="relay_hostname" label="Relay hostname" example="relay.example.com" />
# <UDF name="relay_image" label="Relay image" default="ghcr.io/weald-protocol/wealdrelay:wealdrelay-v0.1.28" />
set -eu

# Only 22, 80 and 443. The observability listener on 9090 in particular must not
# be reachable (specs/backend/relay/server.md).
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

command -v docker >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

cd /opt
WEALD_RELAY_DIR=weald-relay curl -fsSL https://get.weald.team/relay | sh
cd /opt/weald-relay

sed -i "s|^WEALD_RELAY_HOSTNAME=.*|WEALD_RELAY_HOSTNAME=${RELAY_HOSTNAME}|" .env
printf 'WEALD_RELAY_IMAGE=%s\n' "${RELAY_IMAGE}" >> .env
docker compose up -d

# There is no provider log viewer on this path, so the one-time enrollment URL
# is written where the operator will find it. It expires in 24 hours or on first
# use, and the first device to open it becomes the workspace trust root.
sleep 20
docker compose logs relay > /root/weald-enrollment.txt 2>&1
chmod 600 /root/weald-enrollment.txt
