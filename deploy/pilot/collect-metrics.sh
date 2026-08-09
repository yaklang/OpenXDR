#!/bin/sh
set -eu

compose_dir=${OPENXDR_COMPOSE_DIR:-/opt/openxdr}
output=${OPENXDR_METRICS_FILE:-/var/log/openxdr-lab-metrics.csv}
lock=${OPENXDR_METRICS_LOCK:-/run/openxdr-lab-metrics.lock}

exec 9>"$lock"
flock -n 9 || exit 0

header='ts,events_total,events_1h,alerts_total,alert_hits_total,alerts_1h,incidents_total,active_assets_5m,database_bytes,events_bytes'
if [ ! -s "$output" ]; then
    printf '%s\n' "$header" >"$output"
fi

cd "$compose_dir"
docker compose exec -T postgres psql -U openxdr -d openxdr -At -F, -c "
select
  now(),
  (select count(*) from events),
  (select count(*) from events where ts >= now() - interval '1 hour'),
  (select count(*) from alerts),
  (select coalesce(sum(count), 0) from alerts),
  (select count(*) from alerts where ts >= now() - interval '1 hour'),
  (select count(*) from incidents),
  (select count(*) from assets where last_seen >= now() - interval '5 minutes'),
  pg_database_size(current_database()),
  pg_total_relation_size('events');
" >>"$output"
