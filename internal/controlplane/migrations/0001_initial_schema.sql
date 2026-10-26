CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenants_issuer_subject_unique UNIQUE (issuer, subject)
);

CREATE TABLE hosts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname text NOT NULL,
    os_pretty_name text NOT NULL,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT hosts_tenant_hostname_unique UNIQUE (tenant_id, hostname)
);

CREATE INDEX hosts_tenant_enrolled_id_idx ON hosts (tenant_id, enrolled_at, id);
