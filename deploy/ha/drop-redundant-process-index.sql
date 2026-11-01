\set ON_ERROR_STOP on
-- 仅用于普通 events 表。分区父索引不支持并发删除，不能套用此脚本。
SET lock_timeout = '5s';
SET statement_timeout = '2min';
DO $$
DECLARE
 replacement pg_index%ROWTYPE;
 previous pg_index%ROWTYPE;
BEGIN
 IF (SELECT relkind FROM pg_class WHERE oid='public.events'::regclass) <> 'r' THEN
  RAISE EXCEPTION '仅支持普通 events 表，请另行规划分区索引维护';
 END IF;
 SELECT * INTO replacement FROM pg_index WHERE indexrelid=to_regclass('public.event_process_guid_ts');
 IF NOT FOUND OR NOT replacement.indisvalid OR NOT replacement.indisready
 OR replacement.indrelid <> 'public.events'::regclass OR replacement.indnkeyatts <> 2
 OR pg_get_indexdef(replacement.indexrelid,1,true) <> 'process_guid'
 OR pg_get_indexdef(replacement.indexrelid,2,true) <> 'ts'
 OR pg_get_expr(replacement.indpred,replacement.indrelid) IS DISTINCT FROM '(process_guid IS NOT NULL)' THEN
  RAISE EXCEPTION 'GUID/时间联合索引缺失、无效或定义不符，拒绝删除旧索引';
 END IF;
 SELECT * INTO previous FROM pg_index WHERE indexrelid=to_regclass('public.event_process_guid');
 IF FOUND AND (previous.indrelid <> 'public.events'::regclass OR previous.indnkeyatts <> 1
 OR previous.indisunique OR previous.indpred IS NOT NULL
 OR pg_get_indexdef(previous.indexrelid,1,true) <> 'process_guid') THEN
  RAISE EXCEPTION '旧索引定义不符，拒绝删除';
 END IF;
END $$;
DROP INDEX CONCURRENTLY IF EXISTS public.event_process_guid;
