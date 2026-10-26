ALTER TABLE jobs DROP CONSTRAINT jobs_operation_check;

ALTER TABLE jobs ADD CONSTRAINT jobs_operation_check
    CHECK (operation IN (
        'get_system_info',
        'list_directory',
        'read_file',
        'search_packages',
        'write_file',
        'restore_file'
    ));

-- Job payloads created before this migration were transient plaintext JSON.
-- They cannot survive an application restart usefully, so clear them before
-- all new payloads are written as authenticated ciphertext.
UPDATE jobs
SET status = CASE WHEN status IN ('pending', 'leased') THEN 'cancelled' ELSE status END,
    input = '{}'::jsonb,
    result = NULL,
    error_text = CASE WHEN status IN ('pending', 'leased') THEN 'cancelled during encrypted payload migration' ELSE NULL END,
    completed_at = COALESCE(completed_at, clock_timestamp()),
    lease_expires_at = NULL;

CREATE TABLE file_actions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    payload jsonb NOT NULL CHECK (
        jsonb_typeof(payload) = 'object' AND
        payload->>'ufm_encrypted_payload' = 'ubuntu-fleet-manager:aes-256-gcm:v1'
    ),
    status text NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'rolling_back', 'rolled_back')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '7 days'),
    rollback_started_at timestamptz,
    CHECK (expires_at > created_at)
);

CREATE INDEX file_actions_expiry_idx ON file_actions (expires_at);
CREATE INDEX file_actions_tenant_host_created_idx ON file_actions (tenant_id, host_id, created_at DESC);
