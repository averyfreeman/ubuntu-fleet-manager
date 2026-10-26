ALTER TABLE jobs DROP CONSTRAINT jobs_operation_check;

ALTER TABLE jobs ADD CONSTRAINT jobs_operation_check
    CHECK (operation IN (
        'get_system_info',
        'list_directory',
        'read_file',
        'search_packages',
        'write_file',
        'restore_file',
        'apt_update',
        'apt_install',
        'apt_remove',
        'apt_upgrade',
        'apt_rollback'
    ));

CREATE TABLE package_actions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object' AND
        payload->>'ufm_encrypted_payload' = 'ubuntu-fleet-manager:aes-256-gcm:v1'
    ),
    status text NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'rolling_back', 'rolled_back', 'not_reversible')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '7 days'),
    rollback_started_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK ((status = 'rolling_back') = (rollback_started_at IS NOT NULL))
);

CREATE INDEX package_actions_expiry_idx ON package_actions (expires_at);
CREATE INDEX package_actions_tenant_host_created_idx ON package_actions (tenant_id, host_id, created_at DESC);
