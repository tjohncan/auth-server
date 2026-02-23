-- ============================================================================
-- Auth System - Core Schema DDL (PostgreSQL)
-- ============================================================================
-- This file contains table definitions for the OAuth2 authentication system.
-- Designed for PostgreSQL 14+
--
-- Companion files:
--   - ../sqlite/schema.sql (SQLite version of this schema)
--   - ../README.md (schema documentation and design notes)
--   - ./setup_reference.sql (DB prereq. and optional hardening commands)
-- ============================================================================

begin;

set role $$$$$$$DB$$$$$$$OWNER$$$$$$$ROLE$$$$$$$;

-- ============================================================================
-- SCHEMAS
-- ============================================================================

create schema if not exists keys;

create schema if not exists security;
create schema if not exists security_history;

create schema if not exists session;
create schema if not exists session_history;

create schema if not exists logging;
create schema if not exists logging_history;

create schema if not exists lookup;
create schema if not exists lookup_history;

-- ============================================================================
-- KEYS - Cryptographic signing keys
-- ============================================================================
-- CRITICAL SECURITY: This schema contains signing key material.
-- Access should be restricted to auth server process only.
-- No other services, users, or applications should have read access.
-- ============================================================================

create table keys.auth_request_signing (
  singleton boolean not null default true
, current_secret text not null
, current_generated_at timestamp not null
, prior_secret text
, prior_generated_at timestamp

, constraint ck_auth_request_signing_singleton check(singleton = true)
, constraint uix_auth_request_signing_singleton unique(singleton)
);

create table keys.access_token_signing (
  singleton boolean not null default true
, current_private_key text not null
, current_public_key text not null
, current_generated_at timestamp not null
, prior_private_key text
, prior_public_key text
, prior_generated_at timestamp

, constraint ck_access_token_signing_singleton check(singleton = true)
, constraint uix_access_token_signing_singleton unique(singleton)
);

-- ============================================================================
-- SECURITY - Organizations, clients, resource servers, and users
-- ============================================================================

create table security.organization (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, code_name text not null
, display_name text not null
, note text

, constraint pk_organization primary key (pin)
, constraint uix_organization_id unique (id)
, constraint uix_organization_code_name unique (code_name)
);

create table security.organization_key (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, organization_pin bigint not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at timestamp not null default current_timestamp

, constraint pk_organization_key primary key (pin)
, constraint uix_organization_key_id unique (id)
, constraint fk_organization_key_organization foreign key (organization_pin) references security.organization(pin)
);

create table security.resource_server (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, organization_pin bigint not null
, code_name text not null
, display_name text not null
, address text not null
, note text

, constraint pk_resource_server primary key (pin)
, constraint uix_resource_server_id unique (id)
, constraint uix_resource_server_org_pin unique (organization_pin, pin)
, constraint fk_resource_server_organization foreign key (organization_pin) references security.organization(pin)
);

create unique index uix_resource_server_org_code
  on security.resource_server(organization_pin, code_name)
  where is_active = true;

create unique index uix_resource_server_org_address
  on security.resource_server(organization_pin, lower(address))
  where is_active = true;

create table security.resource_server_key (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, resource_server_pin bigint not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at timestamp not null default current_timestamp

, constraint pk_resource_server_key primary key (pin)
, constraint uix_resource_server_key_id unique (id)
, constraint fk_resource_server_key_resource_server foreign key (resource_server_pin) references security.resource_server(pin)
);

create table security.client (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, organization_pin bigint not null
, code_name text not null
, client_type text not null
, grant_type text not null
, display_name text not null
, note text
, require_mfa boolean not null default false
, access_token_ttl_seconds integer not null
, issue_refresh_tokens boolean not null default false
, refresh_token_ttl_seconds integer
, maximum_session_seconds integer
, secret_rotation_seconds integer
, is_universal boolean not null default false

, constraint pk_client primary key (pin)
, constraint uix_client_id unique (id)
, constraint uix_client_org_pin unique (organization_pin, pin)
, constraint fk_client_organization foreign key (organization_pin) references security.organization(pin)
, constraint ck_client_type check(client_type in ('public', 'confidential'))
, constraint ck_grant_type check(grant_type in ('authorization_code', 'client_credentials'))
, constraint ck_client_type_grant_type_pair check(
    (client_type = 'public' and grant_type = 'authorization_code') or
    (client_type = 'confidential' and grant_type = 'client_credentials')
  )
, constraint ck_access_token_ttl check(access_token_ttl_seconds >= 0)
, constraint ck_refresh_token_ttl check(refresh_token_ttl_seconds is null or refresh_token_ttl_seconds >= 0)
, constraint ck_maximum_session check(maximum_session_seconds is null or maximum_session_seconds >= 0)
, constraint ck_secret_rotation check(secret_rotation_seconds is null or secret_rotation_seconds >= 0)
, constraint ck_client_universal_must_be_public check(is_universal = false or (is_universal = true and client_type = 'public'))
);

create unique index uix_client_org_code
  on security.client(organization_pin, code_name)
  where is_active = true;

create table security.client_key (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, client_pin bigint not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at timestamp not null default current_timestamp

, constraint pk_client_key primary key (pin)
, constraint uix_client_key_id unique (id)
, constraint fk_client_key_client foreign key (client_pin) references security.client(pin)
);

create table security.client_redirect_uri (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, client_pin bigint not null
, redirect_uri text not null
, note text

, constraint pk_client_redirect_uri primary key (pin)
, constraint fk_client_redirect_uri_client foreign key (client_pin) references security.client(pin)
, constraint ck_redirect_uri_scheme check(lower(redirect_uri) like 'http://%' or lower(redirect_uri) like 'https://%')
);

create unique index uix_client_redirect_uri on security.client_redirect_uri (client_pin, redirect_uri);

create table security.client_resource_server (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, organization_pin bigint not null
, client_pin bigint not null
, resource_server_pin bigint not null

, constraint pk_client_resource_server primary key (pin)
, constraint uix_client_resource_server unique (client_pin, resource_server_pin)
, constraint fk_client_resource_server_organization foreign key (organization_pin) references security.organization(pin)
, constraint fk_client_resource_server_client foreign key (organization_pin, client_pin) references security.client(organization_pin, pin)
, constraint fk_client_resource_server_resource_server foreign key (organization_pin, resource_server_pin) references security.resource_server(organization_pin, pin)
);

create index idx_client_resource_server_resource_server_pin
  on security.client_resource_server(resource_server_pin);

create table security.user_account (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, is_active boolean not null default true
, username text
, username_hash text
, salt text
, hash_iterations integer
, secret_hash text
, force_password_reset boolean not null default false
, enable_passwordless_login boolean not null default false
, has_mfa boolean not null default false
, require_mfa boolean not null default false

, constraint pk_user_account primary key (pin)
, constraint uix_user_account_id unique (id)
, constraint ck_user_account_password_fields check(
    (salt is null and hash_iterations is null and secret_hash is null) or
    (salt is not null and hash_iterations is not null and secret_hash is not null)
  )
, constraint ck_user_account_mfa_flags check(
    (has_mfa = false and require_mfa = false) or
    (has_mfa = true and require_mfa in (false, true))
  )
);

create unique index uix_user_account_username_hash
  on security.user_account(username_hash)
  where username_hash is not null;

create table security.user_email (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, user_account_pin bigint not null
, email_address text not null
, email_hash text not null
, is_primary boolean not null default false
, is_verified boolean not null default false
, verified_at timestamp

, constraint pk_user_email primary key (pin)
, constraint fk_user_email_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create unique index uix_user_email_email_hash
  on security.user_email(email_hash);

create unique index uix_user_email_user_primary
  on security.user_email(user_account_pin)
  where is_primary = true;

create table security.user_mfa (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, user_account_pin bigint not null
, mfa_method text not null
, display_name text not null
, secret text not null
, is_confirmed boolean not null default false
, confirmed_at timestamp

, constraint pk_user_mfa primary key (pin)
, constraint uix_user_mfa_id unique (id)
, constraint fk_user_mfa_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create index idx_user_mfa_user_confirmed
  on security.user_mfa(user_account_pin, is_confirmed);

create table security.client_user (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, client_pin bigint not null
, user_account_pin bigint not null

, constraint pk_client_user primary key (pin)
, constraint uix_client_user_client_user unique (client_pin, user_account_pin)
, constraint fk_client_user_client foreign key (client_pin) references security.client(pin)
, constraint fk_client_user_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create table security.recovery_code_set (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, id uuid not null
, user_account_pin bigint not null
, generated_at timestamp not null
, salt text not null
, hash_iterations integer not null
, is_active boolean not null default true
, revoked_at timestamp

, constraint pk_recovery_code_set primary key (pin)
, constraint uix_recovery_code_set_id unique (id)
, constraint fk_recovery_code_set_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create unique index uix_recovery_code_set_user_active
  on security.recovery_code_set(user_account_pin)
  where is_active = true;

create table security.recovery_code (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, recovery_code_set_pin bigint not null
, secret_hash text not null
, plaintext_last4 text not null
, is_used boolean not null default false
, used_at timestamp
, used_from_ip text

, constraint pk_recovery_code primary key (pin)
, constraint fk_recovery_code_set foreign key (recovery_code_set_pin) references security.recovery_code_set(pin)
);

create table security.organization_admin (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, organization_pin bigint not null
, user_account_pin bigint not null

, constraint pk_organization_admin primary key (pin)
, constraint uix_organization_admin unique (organization_pin, user_account_pin)
, constraint fk_organization_admin_organization foreign key (organization_pin) references security.organization(pin)
, constraint fk_organization_admin_user_account foreign key (user_account_pin) references security.user_account(pin)
);

-- ============================================================================
-- SESSION - Browser sessions, authorization flows, and tokens
-- ============================================================================

create table session.browser (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, user_account_pin bigint not null
, session_token text not null
, started_at timestamp not null
, authenticated_at timestamp not null
, authentication_complete boolean not null default false
, authentication_method text
, mfa_completed boolean not null default false
, mfa_completed_at timestamp
, last_reauthentication_at timestamp
, last_used timestamp
, source_ip text
, user_agent text
, expected_expiry timestamp not null
, is_closed boolean not null default false
, closed_at timestamp

, constraint pk_browser primary key (id)
, constraint uix_browser_session_token unique (session_token)
, constraint fk_browser_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create table session.authorization_code (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, client_pin bigint not null
, user_account_pin bigint not null
, code text not null
, code_challenge text
, code_challenge_method text
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_exchanged boolean not null default false
, exchanged_at timestamp

, constraint pk_authorization_code primary key (id)
, constraint uix_authorization_code_code unique (code)
, constraint fk_authorization_code_client foreign key (client_pin) references security.client(pin)
, constraint fk_authorization_code_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create table session.refresh_token (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, client_pin bigint not null
, user_account_pin bigint not null
, authorization_code_id uuid
, origin_refresh_token_id uuid
, generation integer not null
, token text not null
, scopes text
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_exchanged boolean not null default false
, exchanged_at timestamp
, is_revoked boolean not null default false
, revoked_at timestamp

, constraint pk_refresh_token primary key (id)
, constraint uix_refresh_token_token unique (token)
, constraint ck_refresh_token_generation check(generation >= 1)
, constraint fk_refresh_token_client foreign key (client_pin) references security.client(pin)
, constraint fk_refresh_token_user_account foreign key (user_account_pin) references security.user_account(pin)
, constraint fk_refresh_token_authorization_code foreign key (authorization_code_id) references session.authorization_code(id)
, constraint fk_refresh_token_origin foreign key (origin_refresh_token_id) references session.refresh_token(id)
);

create table session.access_token (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, resource_server_pin bigint not null
, client_pin bigint not null
, user_account_pin bigint
, authorization_code_id uuid
, refresh_token_id uuid
, token text not null
, scopes text
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_revoked boolean not null default false
, revoked_at timestamp

, constraint pk_access_token primary key (id)
, constraint uix_access_token_token unique (token)
, constraint fk_access_token_resource_server foreign key (resource_server_pin) references security.resource_server(pin)
, constraint fk_access_token_client foreign key (client_pin) references security.client(pin)
, constraint fk_access_token_user_account foreign key (user_account_pin) references security.user_account(pin)
, constraint fk_access_token_authorization_code foreign key (authorization_code_id) references session.authorization_code(id)
, constraint fk_access_token_refresh_token foreign key (refresh_token_id) references session.refresh_token(id)
);

create unique index uix_refresh_token_auth_code
  on session.refresh_token(authorization_code_id)
  where authorization_code_id is not null;

create unique index uix_refresh_token_origin_generation
  on session.refresh_token(origin_refresh_token_id, generation)
  where origin_refresh_token_id is not null;

create unique index uix_access_token_auth_code
  on session.access_token(authorization_code_id)
  where authorization_code_id is not null;

create unique index uix_access_token_refresh_token
  on session.access_token(refresh_token_id)
  where refresh_token_id is not null;

create table session.passwordless_login_token (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, user_account_pin bigint not null
, email_address text not null
, token text not null
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_used boolean not null default false
, used_at timestamp
, source_ip text

, constraint pk_passwordless_login_token primary key (id)
, constraint uix_passwordless_login_token_token unique (token)
, constraint fk_passwordless_login_token_user_account foreign key (user_account_pin) references security.user_account(pin)
);

create table session.email_verification_token (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, user_email_pin bigint not null
, token text not null
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_used boolean not null default false
, used_at timestamp
, is_revoked boolean not null default false
, revoked_at timestamp
, source_ip text

, constraint pk_email_verification_token primary key (id)
, constraint uix_email_verification_token_token unique (token)
, constraint fk_email_verification_token_user_email foreign key (user_email_pin) references security.user_email(pin)
);

create table session.password_reset_token (
  id uuid not null
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, user_account_pin bigint not null
, token text not null
, issued_at timestamp not null
, expected_expiry timestamp not null
, is_used boolean not null default false
, used_at timestamp
, is_revoked boolean not null default false
, revoked_at timestamp
, source_ip text

, constraint pk_password_reset_token primary key (id)
, constraint uix_password_reset_token_token unique (token)
, constraint fk_password_reset_token_user_account foreign key (user_account_pin) references security.user_account(pin)
);

-- ============================================================================
-- LOOKUP - Reference/lookup tables
-- ============================================================================

create table lookup.grant_type (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, grant_type text not null
, description text not null

, constraint pk_grant_type primary key (pin)
, constraint uix_grant_type_grant_type unique (grant_type)
);

insert into lookup.grant_type (grant_type, description) values
  ('authorization_code', 'OAuth2 authorization code flow for public clients')
, ('client_credentials', 'OAuth2 client credentials flow for confidential clients');

create table lookup.client_type (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, client_type text not null
, allowed_grant_types text[] not null
, description text not null

, constraint pk_client_type primary key (pin)
, constraint uix_client_type_client_type unique (client_type)
);

insert into lookup.client_type (client_type, allowed_grant_types, description) values
  ('public', '{authorization_code}', 'Browser or mobile app - cannot keep secrets')
, ('confidential', '{client_credentials}', 'Server-side app - can securely store secrets');

create table lookup.mfa_method (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, mfa_method text not null
, description text not null

, constraint pk_mfa_method primary key (pin)
, constraint uix_mfa_method_mfa_method unique (mfa_method)
);

insert into lookup.mfa_method (mfa_method, description) values
  ('TOTP', 'Time-based one-time password (authenticator app)')
, ('SMS', 'SMS text message code (future support)');

create table lookup.code_challenge_method (
  pin bigint not null generated always as identity (start with 1 increment by 1)
, created_at timestamp not null default current_timestamp
, updated_at timestamp not null default current_timestamp

, code_challenge_method text not null
, description text not null

, constraint pk_code_challenge_method primary key (pin)
, constraint uix_code_challenge_method_method unique (code_challenge_method)
);

insert into lookup.code_challenge_method (code_challenge_method, description) values
  ('plain', 'PKCE plain method (code_verifier = code_challenge)')
, ('S256', 'PKCE S256 method (SHA256 hash of code_verifier)');

-- ============================================================================
-- LOG - Usage tracking and audit logs
-- ============================================================================

create table logging.client_key_usage (
  client_key_pin bigint not null
, authenticated_at timestamp not null
, source_ip text
, user_agent text

, constraint fk_client_key_usage_client_key foreign key (client_key_pin) references security.client_key(pin)
);

create table logging.organization_key_usage (
  organization_key_pin bigint not null
, authenticated_at timestamp not null
, source_ip text
, user_agent text
, operation text

, constraint fk_organization_key_usage_organization_key foreign key (organization_key_pin) references security.organization_key(pin)
);

create table logging.resource_server_key_usage (
  resource_server_key_pin bigint not null
, authenticated_at timestamp not null
, source_ip text
, user_agent text

, constraint fk_resource_server_key_usage_resource_server_key foreign key (resource_server_key_pin) references security.resource_server_key(pin)
);

create table logging.user_mfa_usage (
  user_mfa_pin bigint not null
, submitted_at timestamp not null
, success boolean not null
, source_ip text
, user_agent text

, constraint fk_user_mfa_usage_user_mfa foreign key (user_mfa_pin) references security.user_mfa(pin)
);

-- ============================================================================
-- INDEXES - Database cleaner performance
-- ============================================================================
-- These indexes support efficient cleanup queries that filter on timestamp columns
-- to purge old sessions, tokens, and usage logs

-- Session table cleanup indexes
create index idx_browser_expected_expiry
  on session.browser(expected_expiry);

create index idx_authorization_code_expected_expiry
  on session.authorization_code(expected_expiry);

create index idx_access_token_expected_expiry
  on session.access_token(expected_expiry);

create index idx_refresh_token_expected_expiry
  on session.refresh_token(expected_expiry);

create index idx_passwordless_login_token_expected_expiry
  on session.passwordless_login_token(expected_expiry);

create index idx_email_verification_token_expected_expiry
  on session.email_verification_token(expected_expiry);

create index idx_password_reset_token_expected_expiry
  on session.password_reset_token(expected_expiry);

-- Usage log cleanup indexes
create index idx_client_key_usage_authenticated_at
  on logging.client_key_usage(authenticated_at);

create index idx_resource_server_key_usage_authenticated_at
  on logging.resource_server_key_usage(authenticated_at);

create index idx_organization_key_usage_authenticated_at
  on logging.organization_key_usage(authenticated_at);

create index idx_user_mfa_usage_submitted_at
  on logging.user_mfa_usage(submitted_at);

-- Composite indexes for purging with business logic filters
-- (Leading with equality condition for better selectivity when deleting old rows)
create index idx_user_mfa_cleanup
  on security.user_mfa(is_confirmed, created_at);

create index idx_recovery_code_cleanup
  on security.recovery_code(is_used, used_at);

create index idx_recovery_code_set_cleanup
  on security.recovery_code_set(is_active, revoked_at);

reset role;

commit;
