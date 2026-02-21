-- ============================================================================
-- Auth System - PostgreSQL Prerequisite Setup Reference
-- ============================================================================
-- The best way to get the database schema initialized for the auth server
-- is by giving it an empty database with a sufficiently privileged user credential.
-- 
-- Run the following commands, as a PostgreSQL superuser,
-- before starting the auth server for the first time.
--
-- The server's db_init will create schemas and tables automatically on
-- first startup. These commands set up the database and roles it needs.
-- ============================================================================

-- ============================================================================
-- RECOMMENDED SETUP ROUTINE (run as superuser, e.g. psql -U postgres)
-- ============================================================================
-- 1. Non-login owner role (will own all schemas and tables)
--    This name must match db_owner_role in auth.conf (default fallback: db_user)

create role auth_dbo;

-- 2. Login role for the application (member of owner role, enabling SET ROLE)

create role auth_service login password 'CHANGE_ME' in role auth_dbo;

-- 3. Database owned by the non-login role

create database auth owner auth_dbo;

-- 4. Lock down the new database (connect to it first)

\c auth

revoke all on database auth from public;
drop schema if exists public restrict;

-- 5. Set default search path (makes manual queries easier)

set role auth_dbo;
alter database auth set search_path = security, session, lookup;

-- Start the server and let db_init handle the rest.

-- ============================================================================
-- OPTIONAL: Post-initialization hardening
-- ============================================================================
-- After db_init has created schemas and tables on first run, you can revoke
-- the owner role membership so auth_service can only do DML, not DDL.
--
-- Run these AFTER the server has started successfully at least once:
--
/*

\c auth

-- Remove DDL capability from service role
revoke auth_dbo from auth_service;

-- Grant runtime DML privileges explicitly
grant usage on schema security, session, lookup, logging, keys to auth_service;

grant select, insert, update, delete on all tables in schema security to auth_service;
grant select, insert, update, delete on all tables in schema session to auth_service;
grant select, insert, update, delete on all tables in schema logging to auth_service;
grant select, insert, update, delete on all tables in schema keys to auth_service;
grant select on all tables in schema lookup to auth_service;

-- Also grant on history schemas if history tables are enabled
grant usage on schema security_history, session_history, logging_history, lookup_history to auth_service;
grant select, insert, update, delete on all tables in schema security_history to auth_service;
grant select, insert, update, delete on all tables in schema session_history to auth_service;
grant select, insert, update, delete on all tables in schema logging_history to auth_service;
grant select, insert, update, delete on all tables in schema lookup_history to auth_service;

*/
-- !! IMPORTANT NOTE !! :: After revoking membership, auth_service cannot VACUUM tables owned
-- by auth_dbo. Set cleaner_postgres_vacuum_enabled = false in auth.conf
-- and rely on PostgreSQL's built-in autovacuum instead.

-- ============================================================================
-- OPTIONAL: Read-only role for reporting / analytics
-- ============================================================================
--
/*

create role auth_reader;

\c auth

grant connect on database auth to auth_reader;
grant usage on schema security, session, lookup, logging to auth_reader;
grant select on all tables in schema security to auth_reader;
grant select on all tables in schema session to auth_reader;
grant select on all tables in schema lookup to auth_reader;
grant select on all tables in schema logging to auth_reader;

*/
--
-- To use: create a login role that inherits auth_reader:
--   create role my_analyst login password '...' in role auth_reader;
