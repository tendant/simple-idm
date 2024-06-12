CREATE TABLE users (
    uuid uuid DEFAULT uuid_generate_v4() NOT NULL,
    created_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    last_modified_at timestamp without time zone DEFAULT (now() AT TIME ZONE 'utc'::text) NOT NULL,
    deleted_at timestamp without time zone,
    created_by character varying(255),
    email character varying(255) NOT NULL
);