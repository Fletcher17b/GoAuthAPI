CREATE TABLE IF NOT EXISTS apikeys (
    apikey_id UUID PRIMARY KEY,
    apikeyowner_id UUID NOT NULL,
    apikey_hash TEXT NOT NULL,

    name TEXT,
    -- apikey_prefix VARCHAR(16) NOT NULL -- May be useful

    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,

    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (apikeyowner_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_tenants_apikey_id'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT fk_tenants_apikey_id
            FOREIGN KEY (apikey_id)
            REFERENCES apikeys(apikey_id)
            ON DELETE SET NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_apikeys_owner ON apikeys(apikeyowner_id);