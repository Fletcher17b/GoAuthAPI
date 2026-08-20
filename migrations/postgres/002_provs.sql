CREATE TABLE IF NOT EXISTS tenants (
    tenant_id UUID PRIMARY KEY,
    tenant_name TEXT NOT NULL UNIQUE,
    name TEXT,

    url TEXT NOT NULL,
    email TEXT NOT NULL,
    status TEXT NOT NULL,
    CHECK (status IN ('pending', 'active', 'suspended'))

    public_key TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    allowed_origins JSONB,
    
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenantname_unique
ON tenants (username);