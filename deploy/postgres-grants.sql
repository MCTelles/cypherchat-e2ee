-- Execute as cypherchat_owner in the cypherchat database after init-db.
\set ON_ERROR_STOP on
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM cypherchat_app;
GRANT SELECT, INSERT, UPDATE ON TABLE users TO cypherchat_app;
GRANT SELECT, INSERT ON TABLE public_keys TO cypherchat_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE encrypted_messages TO cypherchat_app;
GRANT SELECT, INSERT ON TABLE audit_logs TO cypherchat_app;
-- Audit records are append-only for the application role.
