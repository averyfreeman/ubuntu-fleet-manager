ALTER TABLE hosts DROP CONSTRAINT hosts_tenant_hostname_unique;

CREATE UNIQUE INDEX hosts_tenant_hostname_active_unique ON hosts (tenant_id, hostname)
    WHERE removed_at IS NULL;
