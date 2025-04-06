--
-- PostgreSQL database dump
--

-- Dumped from database version 17.2 (Debian 17.2-1.pgdg120+1)
-- Dumped by pg_dump version 17.2 (Debian 17.2-1.pgdg120+1)

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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: note; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.note (
    id integer NOT NULL,
    title character varying(255) NOT NULL,
    content_md text NOT NULL,
    content_html text,
    encrypted boolean,
    created_at timestamp without time zone,
    user_id integer NOT NULL,
    signature character varying(512) NOT NULL,
    password_hash character varying(256),
    is_public boolean
);


ALTER TABLE public.note OWNER TO postgres;

--
-- Name: note_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.note_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.note_id_seq OWNER TO postgres;

--
-- Name: note_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.note_id_seq OWNED BY public.note.id;


--
-- Name: shared_note; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.shared_note (
    id integer NOT NULL,
    note_id integer NOT NULL,
    user_id integer,
    shared_at timestamp without time zone
);


ALTER TABLE public.shared_note OWNER TO postgres;

--
-- Name: shared_note_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.shared_note_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.shared_note_id_seq OWNER TO postgres;

--
-- Name: shared_note_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.shared_note_id_seq OWNED BY public.shared_note.id;


--
-- Name: signature; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.signature (
    id integer NOT NULL,
    note_id integer NOT NULL,
    user_id integer NOT NULL,
    signature character varying(512) NOT NULL,
    signed_at timestamp without time zone
);


ALTER TABLE public.signature OWNER TO postgres;

--
-- Name: signature_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.signature_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.signature_id_seq OWNER TO postgres;

--
-- Name: signature_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.signature_id_seq OWNED BY public.signature.id;


--
-- Name: user; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    username character varying(80) NOT NULL,
    email character varying(120) NOT NULL,
    password_hash character varying(256) NOT NULL,
    totp_secret character varying(32),
    is_2fa_verified boolean
);


ALTER TABLE public."user" OWNER TO postgres;

--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_id_seq OWNER TO postgres;

--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: note id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.note ALTER COLUMN id SET DEFAULT nextval('public.note_id_seq'::regclass);


--
-- Name: shared_note id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.shared_note ALTER COLUMN id SET DEFAULT nextval('public.shared_note_id_seq'::regclass);


--
-- Name: signature id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.signature ALTER COLUMN id SET DEFAULT nextval('public.signature_id_seq'::regclass);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Data for Name: note; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.note (id, title, content_md, content_html, encrypted, created_at, user_id, signature, password_hash, is_public) FROM stdin;
1	fvfc	dvredcd	\N	f	2025-03-16 18:57:08.546782	2	6bd9e74c5e215d8820ace76aae00dee59abaefa572ceab41a3158c9e975996b0	\N	t
\.


--
-- Data for Name: shared_note; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.shared_note (id, note_id, user_id, shared_at) FROM stdin;
\.


--
-- Data for Name: signature; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.signature (id, note_id, user_id, signature, signed_at) FROM stdin;
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."user" (id, username, email, password_hash, totp_secret, is_2fa_verified) FROM stdin;
1	axmed	Axmed@gmail.com	7e8c2dc0b21e257d467030eaf2bfd865$pbkdf2:sha256:1000000$G86GdFDohpsw0csV$fcf61074439abe9027956ae36d4f8f138b7ac4b298202b673843219654e2b0d3	YZEM4ZRRPCHELTBJJWSYV73TRS7ODRJO	f
2	create	hup@gmail.com	ba703c1692c7dac80240be085c883651$pbkdf2:sha256:1000000$uQYJfqRE2l4J1oNY$68c9114f6c5b7dca08623cffb70a40ac8726136ccbe491cabaf8ffa5db81f247	TE5RGQDMOCMMB6PWORDQK6JUF7L5CVKY	t
\.


--
-- Name: note_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.note_id_seq', 1, true);


--
-- Name: shared_note_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.shared_note_id_seq', 1, false);


--
-- Name: signature_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.signature_id_seq', 1, false);


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.user_id_seq', 2, true);


--
-- Name: note note_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.note
    ADD CONSTRAINT note_pkey PRIMARY KEY (id);


--
-- Name: shared_note shared_note_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.shared_note
    ADD CONSTRAINT shared_note_pkey PRIMARY KEY (id);


--
-- Name: signature signature_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.signature
    ADD CONSTRAINT signature_pkey PRIMARY KEY (id);


--
-- Name: user user_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_email_key UNIQUE (email);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: user user_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_username_key UNIQUE (username);


--
-- Name: note note_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.note
    ADD CONSTRAINT note_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: shared_note shared_note_note_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.shared_note
    ADD CONSTRAINT shared_note_note_id_fkey FOREIGN KEY (note_id) REFERENCES public.note(id);


--
-- Name: shared_note shared_note_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.shared_note
    ADD CONSTRAINT shared_note_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: signature signature_note_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.signature
    ADD CONSTRAINT signature_note_id_fkey FOREIGN KEY (note_id) REFERENCES public.note(id);


--
-- Name: signature signature_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.signature
    ADD CONSTRAINT signature_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- PostgreSQL database dump complete
--

