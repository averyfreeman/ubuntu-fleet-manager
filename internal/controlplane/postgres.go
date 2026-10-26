package controlplane

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/averyfreeman/ubuntu-fleet-manager/internal/mcpserver"
	"github.com/averyfreeman/ubuntu-fleet-manager/internal/securepayload"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type postgresStore struct {
	pool   *pgxpool.Pool
	cipher *securepayload.Cipher
}

func openPostgresStore(ctx context.Context, databaseURL string) (*postgresStore, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse PostgreSQL configuration: %w", err)
	}
	config.MaxConns = 20
	config.ConnConfig.ConnectTimeout = 10 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL connection pool: %w", err)
	}
	store := &postgresStore{pool: pool}
	if err := store.ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *postgresStore) ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("PostgreSQL readiness check failed: %w", err)
	}
	return nil
}

func (s *postgresStore) close() {
	s.pool.Close()
}

func (s *postgresStore) migrate(ctx context.Context) error {
	connection, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL connection for migrations: %w", err)
	}
	defer connection.Release()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin PostgreSQL migration transaction: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = transaction.Rollback(rollbackCtx)
	}()
	if _, err := transaction.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x55464d)); err != nil {
		return fmt.Errorf("lock PostgreSQL migrations: %w", err)
	}
	if _, err := transaction.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		var applied bool
		if err := transaction.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}
		sql, err := migrationFiles.ReadFile(filepath.ToSlash(filepath.Join("migrations", entry.Name())))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		if _, err := transaction.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := transaction.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit PostgreSQL migrations: %w", err)
	}
	return nil
}

func (s *postgresStore) ensureTenant(ctx context.Context, issuer, subject string) (string, error) {
	var tenantID string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenants (issuer, subject)
		VALUES ($1, $2)
		ON CONFLICT (issuer, subject) DO NOTHING
		RETURNING id::text
	`, issuer, subject).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = s.pool.QueryRow(ctx, "SELECT id::text FROM tenants WHERE issuer = $1 AND subject = $2", issuer, subject).Scan(&tenantID)
	}
	if err != nil {
		return "", fmt.Errorf("create or find personal tenant: %w", err)
	}
	return tenantID, nil
}

func (s *postgresStore) createPairingCode(ctx context.Context, tenantID string) (mcpserver.PairingCode, error) {
	code, codeHash, err := newOpaqueSecret("ufm_pair_")
	if err != nil {
		return mcpserver.PairingCode{}, err
	}
	var expiresAt time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO pairing_codes (tenant_id, code_hash, expires_at)
		VALUES ($1::uuid, $2, now() + interval '10 minutes')
		RETURNING expires_at
	`, tenantID, codeHash[:]).Scan(&expiresAt)
	if err != nil {
		return mcpserver.PairingCode{}, fmt.Errorf("store pairing code: %w", err)
	}
	return mcpserver.PairingCode{Code: code, ExpiresAt: expiresAt.UTC()}, nil
}

func (s *postgresStore) removeHost(ctx context.Context, tenantID, hostID string) (mcpserver.HostRemoval, error) {
	parsedHostID, err := uuid.Parse(hostID)
	if err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("host identifier is invalid")
	}
	transaction, err := s.pool.Begin(ctx)
	if err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("begin host removal: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = transaction.Rollback(rollbackCtx)
	}()

	var removedHostID string
	err = transaction.QueryRow(ctx, `
		UPDATE hosts
		SET removed_at = COALESCE(removed_at, now())
		WHERE id = $1 AND tenant_id = $2::uuid
		RETURNING id::text
	`, parsedHostID, tenantID).Scan(&removedHostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return mcpserver.HostRemoval{}, fmt.Errorf("host not found in the authenticated personal tenant")
	}
	if err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("mark host as removed: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE jobs
		SET status = 'cancelled',
		    result = NULL,
		    input = '{}'::jsonb,
		    error_text = 'host was removed',
		    completed_at = clock_timestamp(),
		    lease_expires_at = NULL
		WHERE host_id = $1 AND (
		    status IN ('pending', 'leased') OR (status = 'completed' AND result IS NOT NULL)
		)
	`, parsedHostID); err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("cancel removed host jobs: %w", err)
	}
	if _, err := transaction.Exec(ctx, `
		UPDATE host_credentials
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE host_id = $1 AND revoked_at IS NULL
	`, parsedHostID); err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("revoke host credential: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return mcpserver.HostRemoval{}, fmt.Errorf("commit host removal: %w", err)
	}
	return mcpserver.HostRemoval{HostID: removedHostID, Removed: true}, nil
}

func (s *postgresStore) listHosts(ctx context.Context, tenantID string, input mcpserver.ListHostsInput) (mcpserver.HostPage, error) {
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return mcpserver.HostPage{}, fmt.Errorf("limit must be between 1 and 200")
	}

	var cursorTime *time.Time
	var cursorID *string
	if input.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(input.Cursor)
		if err != nil {
			return mcpserver.HostPage{}, fmt.Errorf("cursor is invalid")
		}
		timestamp, hostID, ok := strings.Cut(string(decoded), "\n")
		if !ok {
			return mcpserver.HostPage{}, fmt.Errorf("cursor is invalid")
		}
		parsedTimestamp, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return mcpserver.HostPage{}, fmt.Errorf("cursor is invalid")
		}
		if _, err := uuid.Parse(hostID); err != nil {
			return mcpserver.HostPage{}, fmt.Errorf("cursor is invalid")
		}
		cursorTime = &parsedTimestamp
		cursorID = &hostID
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id::text, hostname, os_pretty_name, enrolled_at, last_seen_at
		FROM hosts
		WHERE tenant_id = $1::uuid AND removed_at IS NULL
		  AND ($2::timestamptz IS NULL OR (enrolled_at, id) > ($2::timestamptz, $3::uuid))
		ORDER BY enrolled_at ASC, id ASC
		LIMIT $4
	`, tenantID, cursorTime, cursorID, limit+1)
	if err != nil {
		return mcpserver.HostPage{}, fmt.Errorf("query personal host inventory: %w", err)
	}
	defer rows.Close()

	hosts := make([]mcpserver.Host, 0, limit)
	for rows.Next() {
		var host mcpserver.Host
		if err := rows.Scan(&host.ID, &host.Hostname, &host.OSPrettyName, &host.EnrolledAt, &host.LastSeenAt); err != nil {
			return mcpserver.HostPage{}, fmt.Errorf("read personal host inventory: %w", err)
		}
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return mcpserver.HostPage{}, fmt.Errorf("read personal host inventory: %w", err)
	}

	page := mcpserver.HostPage{Hosts: hosts}
	if len(hosts) > limit {
		last := hosts[limit-1]
		page.Hosts = hosts[:limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(last.EnrolledAt.UTC().Format(time.RFC3339Nano) + "\n" + last.ID))
	}
	return page, nil
}
