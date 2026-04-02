-- ============================================================
-- Migration: crm_integrations schema improvements
-- Safe to run on a live table — no data loss, no column drops.
-- Run inside a transaction and verify row counts before committing.
-- ============================================================

-- ── Issue #2: Drop the redundant standalone account_id index ────────────────
-- The composite unique index (account_id, provider) already serves all
-- WHERE account_id = ? queries. The standalone index doubles write overhead
-- on every INSERT and UPDATE touching account_id.
--
-- Find the actual index name first:
--   SHOW INDEX FROM crm_integrations WHERE Column_name = 'account_id' AND Non_unique = 1;
-- Then drop it (replace IDX_xxx with the real name TypeORM generated):
ALTER TABLE crm_integrations DROP INDEX IDX_crm_integrations_accountId;


-- ── Issue #6: Add covering index for getAllConnected query ───────────────────
-- Eliminates filesort on: WHERE account_id = ? AND is_active = ? ORDER BY created_at DESC
-- TypeORM @Index decorator above handles this, but in case it is not picked up:
CREATE INDEX IF NOT EXISTS idx_crm_account_active_created
  ON crm_integrations (account_id, is_active, created_at DESC);


-- ── Issue #7: Add CHECK constraint on provider column ───────────────────────
-- Prevents invalid provider values from being written at the DB level.
-- MySQL 8.0.16+ enforces CHECK constraints. On older versions this is parsed
-- but silently ignored — upgrade to 8.0.16+ or enforce at app layer only.
ALTER TABLE crm_integrations
  ADD CONSTRAINT chk_provider_valid
  CHECK (provider IN (
    'hubspot', 'zoho', 'pipedrive', 'salesforce',
    'freshdesk', 'odoo', 'bitrix24', 'kommo', 'shopify'
  ));


-- ── Issue #3: Add foreign key to accounts table (when it exists) ─────────────
-- Uncomment and adjust table/column names once the accounts table is in scope.
-- ON DELETE CASCADE ensures tokens are wiped when an account is deleted,
-- preventing orphaned rows with live encrypted tokens.
--
-- ALTER TABLE crm_integrations
--   ADD CONSTRAINT fk_crm_account_id
--   FOREIGN KEY (account_id) REFERENCES accounts(id)
--   ON DELETE CASCADE
--   ON UPDATE CASCADE;


-- ── Verify ───────────────────────────────────────────────────────────────────
SHOW INDEX FROM crm_integrations;
