CREATE TABLE jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    operation text NOT NULL CHECK (operation = 'get_system_info'),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'leased', 'completed', 'failed', 'cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0 AND attempt <= 3),
    requested_at timestamptz NOT NULL DEFAULT now(),
    lease_token uuid,
    lease_expires_at timestamptz,
    completed_at timestamptz,
    result jsonb,
    error_text text
);

CREATE INDEX jobs_pending_host_requested_idx ON jobs (host_id, requested_at, id)
    WHERE status = 'pending';
CREATE INDEX jobs_expired_lease_host_idx ON jobs (host_id, lease_expires_at, requested_at, id)
    WHERE status = 'leased';
