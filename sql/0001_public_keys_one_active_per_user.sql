-- 0001: at most one active public key per user.
--
-- Needed only for databases created before this step (create_all does not add
-- indexes to existing tables). Fresh databases get it from `init-db`.
--
-- Safe to run more than once. It changes no rows and drops nothing. It fails
-- (and changes nothing) if a user already has 2+ active keys; check first with:
--   SELECT user_id, count(*) FROM public_keys WHERE is_active GROUP BY user_id HAVING count(*) > 1;
--
-- Apply:  psql "$DATABASE_URL_PSQL" -v ON_ERROR_STOP=1 -f sql/0001_public_keys_one_active_per_user.sql
-- (use a plain postgresql:// URL for psql, without the "+psycopg" suffix)
-- Rollback: DROP INDEX IF EXISTS uq_public_keys_one_active_per_user;

CREATE UNIQUE INDEX IF NOT EXISTS uq_public_keys_one_active_per_user
    ON public_keys (user_id)
    WHERE is_active;
