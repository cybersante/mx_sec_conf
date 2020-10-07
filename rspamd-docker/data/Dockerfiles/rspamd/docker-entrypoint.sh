#!/bin/bash

mkdir -p /etc/rspamd/plugins.d \
  /etc/rspamd/custom

touch /etc/rspamd/rspamd.conf.local \
  /etc/rspamd/rspamd.conf.override

chmod 755 /var/lib/rspamd


RSPAMD_V4=
RSPAMD_V6=
until [[ ! -z ${RSPAMD_V4} ]]; do
  RSPAMD_V4=$(dig a rspamd +short)
  RSPAMD_V6=$(dig aaaa rspamd +short)
  [[ ! -z ${RSPAMD_V4} ]] && break;
  echo "Waiting for Rspamd..."
  sleep 3
done
echo ${RSPAMD_V4}/32 > /etc/rspamd/custom/rspamd_trusted.map
if [[ ! -z ${RSPAMD_V6} ]]; then
  echo ${RSPAMD_V6}/128 >> /etc/rspamd/custom/rspamd_trusted.map
fi

if [[ ! -z ${REDIS_SLAVEOF_IP} ]]; then
  cat <<EOF > /etc/rspamd/local.d/redis.conf
read_servers = "redis:6379";
write_servers = "${REDIS_SLAVEOF_IP}:${REDIS_SLAVEOF_PORT}";
timeout = 10;
EOF
  until [[ $(redis-cli -h redis PING) == "PONG" ]]; do
    echo "Waiting for Redis @redis..."
    sleep 2
  done
  until [[ $(redis-cli -h ${REDIS_SLAVEOF_IP} -p ${REDIS_SLAVEOF_PORT} PING) == "PONG" ]]; do
    echo "Waiting for Redis @${REDIS_SLAVEOF_IP}..."
    sleep 2
  done
  redis-cli -h redis SLAVEOF ${REDIS_SLAVEOF_IP} ${REDIS_SLAVEOF_PORT}
else
  cat <<EOF > /etc/rspamd/local.d/redis.conf
servers = "redis:6379";
timeout = 10;
EOF
  until [[ $(redis-cli -h redis PING) == "PONG" ]]; do
    echo "Waiting for Redis slave..."
    sleep 2
  done
  redis-cli -h redis SLAVEOF NO ONE
fi

chown -R _rspamd:_rspamd /var/lib/rspamd \
  /etc/rspamd/local.d \
  /etc/rspamd/override.d \
  /etc/rspamd/rspamd.conf.local \
  /etc/rspamd/rspamd.conf.override \
  /etc/rspamd/plugins.d

# Fix missing default global maps, if any
# These exists in mailcow UI and should not be removed
touch /etc/rspamd/custom/global_mime_from_blacklist.map \
  /etc/rspamd/custom/global_rcpt_blacklist.map \
  /etc/rspamd/custom/global_smtp_from_blacklist.map \
  /etc/rspamd/custom/global_mime_from_whitelist.map \
  /etc/rspamd/custom/global_rcpt_whitelist.map \
  /etc/rspamd/custom/global_smtp_from_whitelist.map \
  /etc/rspamd/custom/bad_languages.map \
  /etc/rspamd/custom/sa-rules \
  /etc/rspamd/custom/rspamd_trusted.map \
  /etc/rspamd/custom/ip_wl.map \
  /etc/rspamd/custom/fishy_tlds.map \
  /etc/rspamd/custom/bad_words.map \
  /etc/rspamd/custom/bad_asn.map \
  /etc/rspamd/custom/bad_words_de.map \
  /etc/rspamd/custom/bulk_header.map

# www-data (82) group needs to write to these files
chown _rspamd:_rspamd /etc/rspamd/custom/
chmod 0755 /etc/rspamd/custom/.
chown -R 82:82 /etc/rspamd/custom/*
chmod 644 -R /etc/rspamd/custom/*

# Run hooks
for file in /hooks/*; do
  if [ -x "${file}" ]; then
    echo "Running hook ${file}"
    "${file}"
  fi
done

exec "$@"
