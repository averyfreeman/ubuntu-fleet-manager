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
        'apt_rollback',
        'execute_command'
    ));
