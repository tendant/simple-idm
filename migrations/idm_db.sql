--
-- PostgreSQL database dump
--

-- Dumped from database version 16.6 (Homebrew)
-- Dumped by pg_dump version 17.2 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
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
    uuid uuid DEFAULT gen_random_uuid() NOT NULL,
    user_uuid uuid NOT NULL,
    code text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    used_at timestamp with time zone,
    deleted_at timestamp with time zone
);


ALTER TABLE public.backup_codes OWNER TO idm;

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


ALTER SEQUENCE public.goose_db_version_id_seq OWNER TO idm;

--
-- Name: goose_db_version_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: idm
--

ALTER SEQUENCE public.goose_db_version_id_seq OWNED BY public.goose_db_version.id;


--
-- Name: login; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.login (
    uuid uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    updated_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    created_by character varying(255),
    password bytea,
    username character varying(255),
    two_factor_secret text,
    two_factor_enabled boolean DEFAULT false,
    two_factor_backup_codes text[]
);


ALTER TABLE public.login OWNER TO idm;

--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.password_reset_tokens (
    uuid uuid DEFAULT gen_random_uuid() NOT NULL,
    user_uuid uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expire_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone
);


ALTER TABLE public.password_reset_tokens OWNER TO idm;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.roles (
    uuid uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text
);


ALTER TABLE public.roles OWNER TO idm;

--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.user_roles (
    user_uuid uuid NOT NULL,
    role_uuid uuid NOT NULL
);


ALTER TABLE public.user_roles OWNER TO idm;

--
-- Name: users; Type: TABLE; Schema: public; Owner: idm
--

CREATE TABLE public.users (
    uuid uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    last_modified_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    created_by character varying(255),
    email character varying(255) NOT NULL,
    name character varying(255),
    password bytea,
    verified_at timestamp without time zone,
    username character varying(255),
    two_factor_secret text,
    two_factor_enabled boolean DEFAULT false,
    two_factor_backup_codes text[],
    login_uuid uuid
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
    ADD CONSTRAINT backup_codes_pkey PRIMARY KEY (uuid);


--
-- Name: backup_codes backup_codes_user_uuid_code_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_user_uuid_code_key UNIQUE (user_uuid, code);


--
-- Name: goose_db_version goose_db_version_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.goose_db_version
    ADD CONSTRAINT goose_db_version_pkey PRIMARY KEY (id);


--
-- Name: login login_uuid_unique; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.login
    ADD CONSTRAINT login_uuid_unique UNIQUE (uuid);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (uuid);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (uuid);


--
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (name);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_uuid, role_uuid);


--
-- Name: users users_login_uuid_key; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_login_uuid_key UNIQUE (login_uuid);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (uuid);


--
-- Name: idx_backup_codes_code; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_backup_codes_code ON public.backup_codes USING btree (code);


--
-- Name: idx_backup_codes_user_uuid; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_backup_codes_user_uuid ON public.backup_codes USING btree (user_uuid);


--
-- Name: idx_password_reset_tokens_token; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_password_reset_tokens_token ON public.password_reset_tokens USING btree (token);


--
-- Name: idx_password_reset_tokens_user_uuid; Type: INDEX; Schema: public; Owner: idm
--

CREATE INDEX idx_password_reset_tokens_user_uuid ON public.password_reset_tokens USING btree (user_uuid);


--
-- Name: backup_codes backup_codes_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.backup_codes
    ADD CONSTRAINT backup_codes_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);


--
-- Name: password_reset_tokens fk_user; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT fk_user FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);


--
-- Name: password_reset_tokens password_reset_tokens_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);


--
-- Name: user_roles user_roles_role_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_uuid_fkey FOREIGN KEY (role_uuid) REFERENCES public.roles(uuid);


--
-- Name: user_roles user_roles_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.users(uuid);


--
-- Name: users users_login_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: idm
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_login_uuid_fkey FOREIGN KEY (login_uuid) REFERENCES public.login(uuid);


--
-- PostgreSQL database dump complete
--

