--
-- PostgreSQL database dump
--

-- Dumped from database version 14.17 (Homebrew)
-- Dumped by pg_dump version 14.17 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: backup_codes; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.backup_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    code text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    used_at timestamp with time zone,
    deleted_at timestamp with time zone
);


ALTER TABLE public.backup_codes OWNER TO idm;

--
-- Name: device; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.device (
    fingerprint character varying(255) NOT NULL,
    user_agent text,
    accept_headers text,
    timezone character varying(100),
    screen_resolution character varying(50),
    last_login_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    device_name character varying(255),
    device_type character varying(50),
    device_id character varying(255)
);


ALTER TABLE public.device OWNER TO idm;

--
-- Name: goose_db_version; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.goose_db_version (
    id integer NOT NULL,
    version_id bigint NOT NULL,
    is_applied boolean NOT NULL,
    tstamp timestamp without time zone DEFAULT now()
);


ALTER TABLE public.goose_db_version OWNER TO idm;

--
-- Name: goose_db_version_id_seq; Type: SEQUENCE; Schema: public; Owner: idm
--

CREATE SEQUENCE public.goose_db_version_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.goose_db_version_id_seq OWNER TO idm;

--
-- Name: goose_db_version_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: idm
--

ALTER SEQUENCE public.goose_db_version_id_seq OWNED BY public.goose_db_version.id;


--
-- Name: groups; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    deleted_at timestamp without time zone
);


ALTER TABLE public.groups OWNER TO idm;

--
-- Name: login; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    created_by character varying(255),
    password bytea,
    username character varying(255),
    password_version integer DEFAULT 1,
    password_reset_required boolean,
    password_updated_at timestamp without time zone,
    password_expires_at timestamp without time zone,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp without time zone,
    last_failed_attempt_at timestamp without time zone,
    is_passwordless boolean DEFAULT false
);


ALTER TABLE public.login OWNER TO idm;

--
-- Name: login_2fa; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_2fa (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    login_id uuid NOT NULL,
    two_factor_secret text,
    two_factor_enabled boolean DEFAULT false,
    two_factor_type character varying(48),
    two_factor_backup_codes text[],
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    updated_at timestamp without time zone,
    deleted_at timestamp without time zone
);


ALTER TABLE public.login_2fa OWNER TO idm;

--
-- Name: login_attempt; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_attempt (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    login_id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    ip_address character varying(45),
    user_agent text,
    success boolean NOT NULL,
    failure_reason character varying(255),
    device_fingerprint character varying(255)
);


ALTER TABLE public.login_attempt OWNER TO idm;

--
-- Name: login_device; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_device (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    login_id uuid NOT NULL,
    fingerprint character varying(255) NOT NULL,
    linked_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    deleted_at timestamp without time zone,
    display_name character varying(255),
    updated_at timestamp without time zone,
    created_at timestamp without time zone
);


ALTER TABLE public.login_device OWNER TO idm;

--
-- Name: login_magic_link_tokens; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_magic_link_tokens (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    login_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone
);


ALTER TABLE public.login_magic_link_tokens OWNER TO idm;

--
-- Name: login_password_history; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_password_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    login_id uuid NOT NULL,
    password_hash bytea NOT NULL,
    password_version integer DEFAULT 1 NOT NULL
);


ALTER TABLE public.login_password_history OWNER TO idm;

--
-- Name: login_password_reset_tokens; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login_password_reset_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT (now() AT TIME ZONE 'UTC'::text) NOT NULL,
    expire_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    login_id uuid NOT NULL
);


ALTER TABLE public.login_password_reset_tokens OWNER TO idm;

--
-- Name: oauth2_client_redirect_uris; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.oauth2_client_redirect_uris (
    client_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    deleted_at timestamp without time zone
);


ALTER TABLE public.oauth2_client_redirect_uris OWNER TO idm;

--
-- Name: oauth2_client_scopes; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.oauth2_client_scopes (
    client_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    deleted_at timestamp without time zone
);


ALTER TABLE public.oauth2_client_scopes OWNER TO idm;

--
-- Name: oauth2_clients; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.oauth2_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret_encrypted text NOT NULL,
    client_name character varying(255) NOT NULL,
    client_type character varying(50) NOT NULL,
    require_pkce boolean DEFAULT true NOT NULL,
    description text,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    created_by character varying(255),
    deleted_at timestamp without time zone
);


ALTER TABLE public.oauth2_clients OWNER TO idm;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text
);


ALTER TABLE public.roles OWNER TO idm;

--
-- Name: scopes; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.scopes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    deleted_at timestamp without time zone
);


ALTER TABLE public.scopes OWNER TO idm;

--
-- Name: user_groups; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.user_groups (
    user_id uuid NOT NULL,
    group_id uuid NOT NULL,
    assigned_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text),
    deleted_at timestamp without time zone
);


ALTER TABLE public.user_groups OWNER TO idm;

--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.user_roles (
    user_id uuid NOT NULL,
    role_id uuid NOT NULL
);


ALTER TABLE public.user_roles OWNER TO idm;

--
-- Name: users; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    last_modified_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    created_by character varying(255),
    email character varying(255) NOT NULL,
    name character varying(255),
    login_id uuid,
    phone character varying(255)
);


ALTER TABLE public.users OWNER TO idm;

--
-- Name: goose_db_version id; Type: DEFAULT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.goose_db_version ALTER COLUMN id SET DEFAULT nextval('public.goose_db_version_id_seq'::regclass);


--
-- Name: backup_codes backup_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (id);


--
-- Name: backup_codes backup_codes_user_uuid_code_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_user_uuid_code_key UNIQUE (user_id, code);


--
-- Name: device device_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (fingerprint);


--
-- Name: goose_db_version goose_db_version_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.goose_db_version
    ADD CONSTRAINT goose_db_version_pkey PRIMARY KEY (id);


--
-- Name: groups groups_name_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_name_key UNIQUE (name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: login_2fa login_2fa_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_2fa
    ADD CONSTRAINT login_2fa_pkey PRIMARY KEY (id);


--
-- Name: login_attempt login_attempt_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_attempt
    ADD CONSTRAINT login_attempt_pkey PRIMARY KEY (id);


--
-- Name: login_device login_device_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_device
    ADD CONSTRAINT login_device_pkey PRIMARY KEY (id);


--
-- Name: login login_id_unique; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_id_unique UNIQUE (id);


--
-- Name: login_magic_link_tokens login_magic_link_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_magic_link_tokens
    ADD CONSTRAINT login_magic_link_tokens_pkey PRIMARY KEY (id);


--
-- Name: login_password_history login_password_history_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_password_history
    ADD CONSTRAINT login_password_history_pkey PRIMARY KEY (id);


--
-- Name: login login_uuid_pk; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_uuid_pk PRIMARY KEY (id);


--
-- Name: oauth2_client_redirect_uris oauth2_client_redirect_uris_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_client_redirect_uris
    ADD CONSTRAINT oauth2_client_redirect_uris_pkey PRIMARY KEY (client_id, redirect_uri);


--
-- Name: oauth2_client_scopes oauth2_client_scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_client_scopes
    ADD CONSTRAINT oauth2_client_scopes_pkey PRIMARY KEY (client_id, scope_id);


--
-- Name: oauth2_clients oauth2_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_client_id_key UNIQUE (client_id);


--
-- Name: oauth2_clients oauth2_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_clients
    ADD CONSTRAINT oauth2_clients_pkey PRIMARY KEY (id);


--
-- Name: login_password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (name);


--
-- Name: scopes scopes_name_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_name_key UNIQUE (name);


--
-- Name: scopes scopes_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.scopes
    ADD CONSTRAINT scopes_pkey PRIMARY KEY (id);


--
-- Name: user_groups user_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_pkey PRIMARY KEY (user_id, group_id);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_backup_codes_code; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_backup_codes_code ON public.backup_codes USING btree (code);


--
-- Name: idx_backup_codes_user_uuid; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_backup_codes_user_uuid ON public.backup_codes USING btree (user_id);


--
-- Name: idx_device_device_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_device_device_id ON public.device USING btree (device_id);


--
-- Name: idx_groups_name; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_groups_name ON public.groups USING btree (name);


--
-- Name: idx_login_device_expires_at; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_device_expires_at ON public.login_device USING btree (expires_at);


--
-- Name: idx_login_device_fingerprint; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_device_fingerprint ON public.login_device USING btree (fingerprint);


--
-- Name: idx_login_device_login_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_device_login_id ON public.login_device USING btree (login_id);


--
-- Name: idx_login_magic_link_tokens_login_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_magic_link_tokens_login_id ON public.login_magic_link_tokens USING btree (login_id);


--
-- Name: idx_login_magic_link_tokens_token; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_magic_link_tokens_token ON public.login_magic_link_tokens USING btree (token);


--
-- Name: idx_login_password_reset_tokens_login_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_password_reset_tokens_login_id ON public.login_password_reset_tokens USING btree (login_id);


--
-- Name: idx_login_password_reset_tokens_token; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_login_password_reset_tokens_token ON public.login_password_reset_tokens USING btree (token);


--
-- Name: idx_user_groups_group_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_user_groups_group_id ON public.user_groups USING btree (group_id);


--
-- Name: idx_user_groups_user_id; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_user_groups_user_id ON public.user_groups USING btree (user_id);


--
-- Name: login_attempt_login_id_idx; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX login_attempt_login_id_idx ON public.login_attempt USING btree (login_id);


--
-- Name: login_password_history_login_id_idx; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX login_password_history_login_id_idx ON public.login_password_history USING btree (login_id);


--
-- Name: backup_codes backup_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: login_2fa login_2fa_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_2fa
    ADD CONSTRAINT login_2fa_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: login_attempt login_attempt_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_attempt
    ADD CONSTRAINT login_attempt_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: login_device login_device_fingerprint_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_device
    ADD CONSTRAINT login_device_fingerprint_fkey FOREIGN KEY (fingerprint) REFERENCES public.device(fingerprint);


--
-- Name: login_device login_device_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_device
    ADD CONSTRAINT login_device_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: login_magic_link_tokens login_magic_link_tokens_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_magic_link_tokens
    ADD CONSTRAINT login_magic_link_tokens_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: login_password_history login_password_history_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_password_history
    ADD CONSTRAINT login_password_history_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: login_password_reset_tokens login_password_reset_tokens_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login_password_reset_tokens
    ADD CONSTRAINT login_password_reset_tokens_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- Name: oauth2_client_redirect_uris oauth2_client_redirect_uris_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_client_redirect_uris
    ADD CONSTRAINT oauth2_client_redirect_uris_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id);


--
-- Name: oauth2_client_scopes oauth2_client_scopes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_client_scopes
    ADD CONSTRAINT oauth2_client_scopes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id);


--
-- Name: oauth2_client_scopes oauth2_client_scopes_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.oauth2_client_scopes
    ADD CONSTRAINT oauth2_client_scopes_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.scopes(id);


--
-- Name: user_groups user_groups_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: user_groups user_groups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_groups
    ADD CONSTRAINT user_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id);


--
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: users users_login_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_login_id_fkey FOREIGN KEY (login_id) REFERENCES public.login(id);


--
-- PostgreSQL database dump complete
--

