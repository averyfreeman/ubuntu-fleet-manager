ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_attempt_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_attempt_nonnegative_check CHECK (attempt >= 0);
