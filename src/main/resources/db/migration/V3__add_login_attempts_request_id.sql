-- ============================================================================
-- Migration: Add request_id column to login_attempts for cloud audit traceability
-- Purpose: Link each login attempt to an optional cloud_audit entry
-- Database: PostgreSQL
-- ============================================================================

-- 1) Add request_id column (nullable for backward compatibility)
--    Type matches cloud_audit.request_id (VARCHAR(100))
ALTER TABLE login_attempts
    ADD COLUMN IF NOT EXISTS request_id VARCHAR(100);

-- 2) (Optional) Add foreign key to cloud_audit.request_id, guarded so that
--    migration is safe if the table/column/constraint already exist or are missing.
DO $$
BEGIN
    -- Only add FK if cloud_audit table and request_id column exist
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'cloud_audit'
    ) AND EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'cloud_audit' AND column_name = 'request_id'
    ) THEN
        -- Check if FK already exists
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.table_constraints
            WHERE constraint_type = 'FOREIGN KEY'
              AND table_name = 'login_attempts'
              AND constraint_name = 'fk_login_attempts_cloud_audit'
        ) THEN
            ALTER TABLE login_attempts
                ADD CONSTRAINT fk_login_attempts_cloud_audit
                FOREIGN KEY (request_id) REFERENCES cloud_audit(request_id);
        END IF;
    END IF;
END$$;

-- 3) Index for faster lookup by request_id when joining with audit logs
CREATE INDEX IF NOT EXISTS idx_login_attempts_request_id ON login_attempts(request_id);

-- ============================================================================
-- Migration complete - login_attempts.request_id added with optional FK + index
-- ============================================================================
