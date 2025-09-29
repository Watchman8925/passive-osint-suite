-- Initialize audit database for OSINT Suite
-- This script sets up the audit trail tables for tracking investigations

-- Create audit schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS audit;

-- Create investigations table
CREATE TABLE IF NOT EXISTS audit.investigations (
    id SERIAL PRIMARY KEY,
    investigation_id UUID UNIQUE NOT NULL,
    target TEXT NOT NULL,
    investigation_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    metadata JSONB
);

-- Create audit_events table for detailed logging
CREATE TABLE IF NOT EXISTS audit.audit_events (
    id SERIAL PRIMARY KEY,
    investigation_id UUID REFERENCES audit.investigations(investigation_id),
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100),
    source_ip INET,
    metadata JSONB
);

-- Create capability_executions table
CREATE TABLE IF NOT EXISTS audit.capability_executions (
    id SERIAL PRIMARY KEY,
    investigation_id UUID REFERENCES audit.investigations(investigation_id),
    capability_name VARCHAR(100) NOT NULL,
    target TEXT NOT NULL,
    execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_ms INTEGER,
    status VARCHAR(20) NOT NULL,
    result_hash VARCHAR(64),
    error_message TEXT,
    metadata JSONB
);

-- Create results table for storing encrypted results
CREATE TABLE IF NOT EXISTS audit.results (
    id SERIAL PRIMARY KEY,
    investigation_id UUID REFERENCES audit.investigations(investigation_id),
    capability_name VARCHAR(100) NOT NULL,
    result_hash VARCHAR(64) UNIQUE NOT NULL,
    encrypted_data BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_investigations_target ON audit.investigations(target);
CREATE INDEX IF NOT EXISTS idx_investigations_type ON audit.investigations(investigation_type);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON audit.investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON audit.investigations(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_investigation_id ON audit.audit_events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit.audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit.audit_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_capability_executions_investigation_id ON audit.capability_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_capability_executions_capability ON audit.capability_executions(capability_name);
CREATE INDEX IF NOT EXISTS idx_capability_executions_status ON audit.capability_executions(status);

CREATE INDEX IF NOT EXISTS idx_results_investigation_id ON audit.results(investigation_id);
CREATE INDEX IF NOT EXISTS idx_results_hash ON audit.results(result_hash);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION audit.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for investigations table
DROP TRIGGER IF EXISTS update_investigations_updated_at ON audit.investigations;
CREATE TRIGGER update_investigations_updated_at
    BEFORE UPDATE ON audit.investigations
    FOR EACH ROW
    EXECUTE FUNCTION audit.update_updated_at_column();

-- Grant permissions to osint_user
GRANT USAGE ON SCHEMA audit TO osint_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO osint_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO osint_user;

-- Insert initial system investigation
INSERT INTO audit.investigations (investigation_id, target, investigation_type, status, created_by)
VALUES (
    gen_random_uuid(),
    'system',
    'system_initialization',
    'completed',
    'system'
) ON CONFLICT (investigation_id) DO NOTHING;