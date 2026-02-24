-- ============================================================================
-- Auth System - Core Schema DDL (SQLite)
-- ============================================================================
-- This file contains table definitions for the OAuth2 authentication system.
-- Designed for SQLite 3.45+ (latest amalgamation)
--
-- Companion files:
--   - ../postgresql/schema.sql (PostgreSQL version of this schema)
--   - ../README.md (schema documentation and design notes)
-- ============================================================================

pragma foreign_keys = on;

-- ============================================================================
-- KEYS - Cryptographic signing keys
-- ============================================================================
-- CRITICAL SECURITY: This schema contains signing key material.
-- Access should be restricted to auth server process only.
-- No other services, users, or applications should have read access.
-- ============================================================================

create table auth_request_signing (
  singleton integer not null default 1
, current_secret text not null
, current_generated_at text not null
, prior_secret text
, prior_generated_at text

, constraint ck_auth_request_signing_singleton check(singleton = 1)
, constraint uix_auth_request_signing_singleton unique(singleton)
);

create table access_token_signing (
  singleton integer not null default 1
, current_private_key text not null
, current_public_key text not null
, current_generated_at text not null
, prior_private_key text
, prior_public_key text
, prior_generated_at text

, constraint ck_access_token_signing_singleton check(singleton = 1)
, constraint uix_access_token_signing_singleton unique(singleton)
);

-- ============================================================================
-- SECURITY - Organizations, clients, resource servers, and users
-- ============================================================================

create table organization (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, code_name text not null
, display_name text not null
, note text

, constraint uix_organization_id unique(id)
, constraint uix_organization_code_name unique(code_name)
, constraint ck_organization_is_active check(is_active in (0, 1))
);

create table organization_key (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, organization_pin integer not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at text not null default (datetime('now'))

, constraint uix_organization_key_id unique(id)
, constraint ck_organization_key_is_active check(is_active in (0, 1))
, constraint fk_organization_key_organization foreign key(organization_pin) references organization(pin)
);

create table resource_server (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, organization_pin integer not null
, code_name text not null
, display_name text not null
, address text not null
, note text

, constraint uix_resource_server_id unique(id)
, constraint uix_resource_server_org_pin unique(organization_pin, pin)
, constraint ck_resource_server_is_active check(is_active in (0, 1))
, constraint fk_resource_server_organization foreign key(organization_pin) references organization(pin)
);

create unique index uix_resource_server_org_code
  on resource_server(organization_pin, code_name)
  where is_active = 1;

create unique index uix_resource_server_org_address
  on resource_server(organization_pin, address)
  where is_active = 1;

create table resource_server_key (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, resource_server_pin integer not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at text not null default (datetime('now'))

, constraint uix_resource_server_key_id unique(id)
, constraint ck_resource_server_key_is_active check(is_active in (0, 1))
, constraint fk_resource_server_key_resource_server foreign key(resource_server_pin) references resource_server(pin)
);

create table client (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, organization_pin integer not null
, code_name text not null
, client_type text not null
, grant_type text not null
, display_name text not null
, note text
, require_mfa integer not null default 0
, access_token_ttl_seconds integer not null
, issue_refresh_tokens integer not null default 0
, refresh_token_ttl_seconds integer
, maximum_session_seconds integer
, secret_rotation_seconds integer
, is_universal integer not null default 0

, constraint uix_client_id unique(id)
, constraint uix_client_org_pin unique(organization_pin, pin)
, constraint ck_client_is_active check(is_active in (0, 1))
, constraint ck_client_type check(client_type in ('public', 'confidential'))
, constraint ck_client_grant_type check(grant_type in ('authorization_code', 'client_credentials'))
, constraint ck_client_type_grant_type_pair check(
    (client_type = 'public' and grant_type = 'authorization_code') or
    (client_type = 'confidential' and grant_type = 'client_credentials')
  )
, constraint ck_client_require_mfa check(require_mfa in (0, 1))
, constraint ck_client_access_token_ttl check(access_token_ttl_seconds >= 0)
, constraint ck_client_issue_refresh_tokens check(issue_refresh_tokens in (0, 1))
, constraint ck_client_refresh_token_ttl check(refresh_token_ttl_seconds is null or refresh_token_ttl_seconds >= 0)
, constraint ck_client_maximum_session check(maximum_session_seconds is null or maximum_session_seconds >= 0)
, constraint ck_client_secret_rotation check(secret_rotation_seconds is null or secret_rotation_seconds >= 0)
, constraint ck_client_is_universal check(is_universal in (0, 1))
, constraint ck_client_universal_must_be_public check(is_universal = 0 or (is_universal = 1 and client_type = 'public'))
, constraint fk_client_organization foreign key(organization_pin) references organization(pin)
);

create unique index uix_client_org_code
  on client(organization_pin, code_name)
  where is_active = 1;

create table grant_type (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, grant_type text not null
, description text not null

, constraint uix_grant_type_grant_type unique(grant_type)
);

insert into grant_type (grant_type, description) values
  ('authorization_code', 'OAuth2 authorization code flow for public clients')
, ('client_credentials', 'OAuth2 client credentials flow for confidential clients');

create table client_type (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, client_type text not null
, allowed_grant_types text not null
, description text not null

, constraint uix_client_type_client_type unique(client_type)
);

insert into client_type (client_type, allowed_grant_types, description) values
  ('public', '["authorization_code"]', 'Browser or mobile app - cannot keep secrets')
, ('confidential', '["client_credentials"]', 'Server-side app - can securely store secrets');

create table client_key (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, client_pin integer not null
, salt text not null
, hash_iterations integer not null
, secret_hash text not null
, note text
, generated_at text not null default (datetime('now'))

, constraint uix_client_key_id unique(id)
, constraint ck_client_key_is_active check(is_active in (0, 1))
, constraint fk_client_key_client foreign key(client_pin) references client(pin)
);

create table client_redirect_uri (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, client_pin integer not null
, redirect_uri text not null
, note text

, constraint uix_client_redirect_uri unique(client_pin, redirect_uri)
, constraint fk_client_redirect_uri_client foreign key(client_pin) references client(pin)
, constraint ck_redirect_uri_scheme check(lower(redirect_uri) like 'http://%' or lower(redirect_uri) like 'https://%')
);

create table client_resource_server (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, organization_pin integer not null
, client_pin integer not null
, resource_server_pin integer not null

, constraint uix_client_resource_server unique(client_pin, resource_server_pin)
, constraint fk_client_resource_server_organization foreign key(organization_pin) references organization(pin)
, constraint fk_client_resource_server_client foreign key(organization_pin, client_pin) references client(organization_pin, pin)
, constraint fk_client_resource_server_resource_server foreign key(organization_pin, resource_server_pin) references resource_server(organization_pin, pin)
);

create index idx_client_resource_server_resource_server_pin
  on client_resource_server(resource_server_pin);

create table user_account (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, is_active integer not null default 1
, username text
, username_hash text
, salt text
, hash_iterations integer
, secret_hash text
, force_password_reset integer not null default 0
, enable_passwordless_login integer not null default 0
, has_mfa integer not null default 0
, require_mfa integer not null default 0

, constraint uix_user_account_id unique(id)
, constraint ck_user_account_is_active check(is_active in (0, 1))
, constraint ck_user_account_force_password_reset check(force_password_reset in (0, 1))
, constraint ck_user_account_enable_passwordless check(enable_passwordless_login in (0, 1))
, constraint ck_user_account_mfa_flags check(
    (has_mfa = 0 and require_mfa = 0) or
    (has_mfa = 1 and require_mfa in (0, 1))
  )
, constraint ck_user_account_password_fields check(
    (salt is null and hash_iterations is null and secret_hash is null) or
    (salt is not null and hash_iterations is not null and secret_hash is not null)
  )
);

create unique index uix_user_account_username_hash
  on user_account(username_hash)
  where username_hash is not null;

create table user_email (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, user_account_pin integer not null
, email_address text not null
, email_hash text not null
, is_primary integer not null default 0
, is_verified integer not null default 0
, verified_at text

, constraint uix_user_email_email_hash unique(email_hash)
, constraint ck_user_email_is_primary check(is_primary in (0, 1))
, constraint ck_user_email_is_verified check(is_verified in (0, 1))
, constraint fk_user_email_user_account foreign key(user_account_pin) references user_account(pin)
);

create unique index uix_user_email_user_primary
  on user_email(user_account_pin)
  where is_primary = 1;


create table user_mfa (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, user_account_pin integer not null
, mfa_method text not null
, display_name text not null
, secret text not null
, is_confirmed integer not null default 0
, confirmed_at text

, constraint uix_user_mfa_id unique(id)
, constraint ck_user_mfa_is_confirmed check(is_confirmed in (0, 1))
, constraint fk_user_mfa_user_account foreign key(user_account_pin) references user_account(pin)
);

create index idx_user_mfa_user_confirmed
  on user_mfa(user_account_pin, is_confirmed);

create table mfa_method (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, mfa_method text not null
, description text not null

, constraint uix_mfa_method_mfa_method unique(mfa_method)
);

insert into mfa_method (mfa_method, description) values
  ('TOTP', 'Time-based one-time password (authenticator app)')
, ('SMS', 'SMS text message code (future support)');

create table client_user (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, client_pin integer not null
, user_account_pin integer not null

, constraint uix_client_user_client_user unique(client_pin, user_account_pin)
, constraint fk_client_user_client foreign key(client_pin) references client(pin)
, constraint fk_client_user_user_account foreign key(user_account_pin) references user_account(pin)
);

create table recovery_code_set (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, id blob not null
, user_account_pin integer not null
, generated_at text not null
, salt text not null
, hash_iterations integer not null
, is_active integer not null default 1
, revoked_at text

, constraint uix_recovery_code_set_id unique(id)
, constraint ck_recovery_code_set_is_active check(is_active in (0, 1))
, constraint fk_recovery_code_set_user_account foreign key(user_account_pin) references user_account(pin)
);

create unique index uix_recovery_code_set_user_active
  on recovery_code_set(user_account_pin)
  where is_active = 1;

create table recovery_code (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, recovery_code_set_pin integer not null
, secret_hash text not null
, plaintext_last4 text not null
, is_used integer not null default 0
, used_at text
, used_from_ip text

, constraint ck_recovery_code_is_used check(is_used in (0, 1))
, constraint fk_recovery_code_set foreign key(recovery_code_set_pin) references recovery_code_set(pin)
);

create table organization_admin (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, organization_pin integer not null
, user_account_pin integer not null

, constraint uix_organization_admin unique(organization_pin, user_account_pin)
, constraint fk_organization_admin_organization foreign key(organization_pin) references organization(pin)
, constraint fk_organization_admin_user_account foreign key(user_account_pin) references user_account(pin)
);

-- ============================================================================
-- SESSION - Browser sessions, authorization flows, and tokens
-- ============================================================================

create table browser (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, user_account_pin integer not null
, session_token text not null
, started_at text not null
, authenticated_at text not null
, authentication_complete integer not null default 0
, authentication_method text
, mfa_completed integer not null default 0
, mfa_completed_at text
, last_reauthentication_at text
, last_used text
, source_ip text
, user_agent text
, expected_expiry text not null
, is_closed integer not null default 0
, closed_at text

, constraint pk_browser primary key(id)
, constraint uix_browser_session_token unique(session_token)
, constraint ck_browser_authentication_complete check(authentication_complete in (0, 1))
, constraint ck_browser_mfa_completed check(mfa_completed in (0, 1))
, constraint ck_browser_is_closed check(is_closed in (0, 1))
, constraint fk_browser_user_account foreign key(user_account_pin) references user_account(pin)
);

create table authorization_code (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, client_pin integer not null
, user_account_pin integer not null
, code text not null
, code_challenge text
, code_challenge_method text
, issued_at text not null
, expected_expiry text not null
, is_exchanged integer not null default 0
, exchanged_at text

, constraint pk_authorization_code primary key(id)
, constraint uix_authorization_code_code unique(code)
, constraint ck_authorization_code_is_exchanged check(is_exchanged in (0, 1))
, constraint fk_authorization_code_client foreign key(client_pin) references client(pin)
, constraint fk_authorization_code_user_account foreign key(user_account_pin) references user_account(pin)
);

create table refresh_token (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, client_pin integer not null
, user_account_pin integer not null
, authorization_code_id blob
, origin_refresh_token_id blob
, generation integer not null
, token text not null
, scopes text
, issued_at text not null
, expected_expiry text not null
, is_exchanged integer not null default 0
, exchanged_at text
, is_revoked integer not null default 0
, revoked_at text

, constraint pk_refresh_token primary key(id)
, constraint uix_refresh_token_token unique(token)
, constraint ck_refresh_token_generation check(generation >= 1)
, constraint ck_refresh_token_is_exchanged check(is_exchanged in (0, 1))
, constraint ck_refresh_token_is_revoked check(is_revoked in (0, 1))
, constraint fk_refresh_token_client foreign key(client_pin) references client(pin)
, constraint fk_refresh_token_user_account foreign key(user_account_pin) references user_account(pin)
, constraint fk_refresh_token_authorization_code foreign key(authorization_code_id) references authorization_code(id)
, constraint fk_refresh_token_origin foreign key(origin_refresh_token_id) references refresh_token(id)
);

create table access_token (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, resource_server_pin integer not null
, client_pin integer not null
, user_account_pin integer
, authorization_code_id blob
, refresh_token_id blob
, token text not null
, scopes text
, issued_at text not null
, expected_expiry text not null
, is_revoked integer not null default 0
, revoked_at text

, constraint pk_access_token primary key(id)
, constraint uix_access_token_token unique(token)
, constraint ck_access_token_is_revoked check(is_revoked in (0, 1))
, constraint fk_access_token_resource_server foreign key(resource_server_pin) references resource_server(pin)
, constraint fk_access_token_client foreign key(client_pin) references client(pin)
, constraint fk_access_token_user_account foreign key(user_account_pin) references user_account(pin)
, constraint fk_access_token_authorization_code foreign key(authorization_code_id) references authorization_code(id)
, constraint fk_access_token_refresh_token foreign key(refresh_token_id) references refresh_token(id)
);

create unique index uix_refresh_token_auth_code
  on refresh_token(authorization_code_id)
  where authorization_code_id is not null;

create unique index uix_refresh_token_origin_generation
  on refresh_token(origin_refresh_token_id, generation)
  where origin_refresh_token_id is not null;

create unique index uix_access_token_auth_code
  on access_token(authorization_code_id)
  where authorization_code_id is not null;

create unique index uix_access_token_refresh_token
  on access_token(refresh_token_id)
  where refresh_token_id is not null;

create table passwordless_login_token (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, user_account_pin integer not null
, email_address text not null
, token text not null
, issued_at text not null
, expected_expiry text not null
, is_used integer not null default 0
, used_at text
, source_ip text

, constraint pk_passwordless_login_token primary key(id)
, constraint uix_passwordless_login_token_token unique(token)
, constraint ck_passwordless_login_token_is_used check(is_used in (0, 1))
, constraint fk_passwordless_login_token_user_account foreign key(user_account_pin) references user_account(pin)
);

create table email_verification_token (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, user_email_pin integer not null
, token text not null
, issued_at text not null
, expected_expiry text not null
, is_used integer not null default 0
, used_at text
, is_revoked integer not null default 0
, revoked_at text
, source_ip text

, constraint pk_email_verification_token primary key(id)
, constraint uix_email_verification_token_token unique(token)
, constraint ck_email_verification_token_is_used check(is_used in (0, 1))
, constraint ck_email_verification_token_is_revoked check(is_revoked in (0, 1))
, constraint fk_email_verification_token_user_email foreign key(user_email_pin) references user_email(pin)
);

create table password_reset_token (
  id blob not null
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, user_account_pin integer not null
, token text not null
, issued_at text not null
, expected_expiry text not null
, is_used integer not null default 0
, used_at text
, is_revoked integer not null default 0
, revoked_at text
, source_ip text

, constraint pk_password_reset_token primary key(id)
, constraint uix_password_reset_token_token unique(token)
, constraint ck_password_reset_token_is_used check(is_used in (0, 1))
, constraint ck_password_reset_token_is_revoked check(is_revoked in (0, 1))
, constraint fk_password_reset_token_user_account foreign key(user_account_pin) references user_account(pin)
);

-- ============================================================================
-- REFERENCE/LOOKUP - Lookup tables for valid values
-- ============================================================================

create table code_challenge_method (
  pin integer primary key autoincrement
, created_at text not null default (datetime('now'))
, updated_at text not null default (datetime('now'))

, code_challenge_method text not null
, description text not null

, constraint uix_code_challenge_method_method unique(code_challenge_method)
);

insert into code_challenge_method (code_challenge_method, description) values
  ('plain', 'PKCE plain method (code_verifier = code_challenge)')
, ('S256', 'PKCE S256 method (SHA256 hash of code_verifier)');

-- ============================================================================
-- LOGGING - Usage tracking and audit logs
-- ============================================================================

create table client_key_usage (
  client_key_pin integer not null
, authenticated_at text not null
, source_ip text
, user_agent text

, constraint fk_client_key_usage_client_key foreign key(client_key_pin) references client_key(pin)
);

create table resource_server_key_usage (
  resource_server_key_pin integer not null
, authenticated_at text not null
, source_ip text
, user_agent text

, constraint fk_resource_server_key_usage_resource_server_key foreign key(resource_server_key_pin) references resource_server_key(pin)
);

create table organization_key_usage (
  organization_key_pin integer not null
, authenticated_at text not null
, source_ip text
, user_agent text
, operation text

, constraint fk_organization_key_usage_organization_key foreign key(organization_key_pin) references organization_key(pin)
);

create table user_mfa_usage (
  user_mfa_pin integer not null
, submitted_at text not null
, success integer not null
, source_ip text
, user_agent text

, constraint ck_user_mfa_usage_success check(success in (0, 1))
, constraint fk_user_mfa_usage_user_mfa foreign key(user_mfa_pin) references user_mfa(pin)
);

-- ============================================================================
-- INDEXES - Database cleaner performance
-- ============================================================================
-- These indexes support efficient cleanup queries that filter on timestamp columns
-- to purge old sessions, tokens, and usage logs

-- Session table cleanup indexes
create index idx_browser_expected_expiry
  on browser(expected_expiry);

create index idx_authorization_code_expected_expiry
  on authorization_code(expected_expiry);

create index idx_access_token_expected_expiry
  on access_token(expected_expiry);

create index idx_refresh_token_expected_expiry
  on refresh_token(expected_expiry);

create index idx_passwordless_login_token_expected_expiry
  on passwordless_login_token(expected_expiry);

create index idx_email_verification_token_expected_expiry
  on email_verification_token(expected_expiry);

create index idx_password_reset_token_expected_expiry
  on password_reset_token(expected_expiry);

-- Usage log cleanup indexes
create index idx_client_key_usage_authenticated_at
  on client_key_usage(authenticated_at);

create index idx_resource_server_key_usage_authenticated_at
  on resource_server_key_usage(authenticated_at);

create index idx_organization_key_usage_authenticated_at
  on organization_key_usage(authenticated_at);

create index idx_user_mfa_usage_submitted_at
  on user_mfa_usage(submitted_at);

-- Composite indexes for purging with business logic filters
-- (Leading with equality condition for better selectivity when deleting old rows)
create index idx_user_mfa_cleanup
  on user_mfa(is_confirmed, created_at);

create index idx_recovery_code_cleanup
  on recovery_code(is_used, used_at);

create index idx_recovery_code_set_cleanup
  on recovery_code_set(is_active, revoked_at);
