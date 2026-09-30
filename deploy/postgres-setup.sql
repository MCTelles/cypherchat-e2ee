-- Execute once as a local PostgreSQL superuser before init-db.
\set ON_ERROR_STOP on
SET password_encryption = 'scram-sha-256';
CREATE ROLE cypherchat_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE cypherchat_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password cypherchat_owner
\password cypherchat_app
CREATE DATABASE cypherchat OWNER cypherchat_owner;
REVOKE ALL ON DATABASE cypherchat FROM PUBLIC;
GRANT CONNECT ON DATABASE cypherchat TO cypherchat_app;
\connect cypherchat
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cypherchat_app;
-- No table privileges are granted here. Run postgres-grants.sql after init-db.
