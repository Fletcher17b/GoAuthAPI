-- Dev seed data. Idempotent. safe to re-run.
INSERT INTO tenants (
    tenant_id, tenant_name, name, url, email, status,
    public_key, allowed_origins, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'acme',
    'Acme Inc.',
    'https://acme.com',
    'admin@acme.com',
    'active',
    'test-public-key',
    '["https://acme.com"]'::jsonb,
    NOW(),
    NOW()
) ON CONFLICT DO NOTHING;

INSERT INTO tenants (
    tenant_id, tenant_name, name, url, email, status,
    public_key, allowed_origins, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000002',
    'interal',
    'internal handler',
    'non',
    'non',
    'active',
    'test-public-key',
    '["https://acme.com"]'::jsonb,
    NOW(),
    NOW()
) ON CONFLICT DO NOTHING;