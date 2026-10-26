ALTER TABLE jobs DROP CONSTRAINT jobs_operation_check;

ALTER TABLE jobs ADD CONSTRAINT jobs_operation_check
    CHECK (operation IN ('get_system_info', 'list_directory', 'read_file', 'search_packages'));

ALTER TABLE jobs ADD COLUMN input jsonb NOT NULL DEFAULT '{}'::jsonb;
