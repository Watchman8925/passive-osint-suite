-- PostgreSQL Database Initialization Script for OSINT Suite
-- Run this script to set up the complete database schema

-- Create database and user (run as postgres superuser first)
-- CREATE DATABASE osint_db;
-- CREATE USER osint_user WITH ENCRYPTED PASSWORD 'password';
-- GRANT ALL PRIVILEGES ON DATABASE osint_db TO osint_user;

-- Connect to osint_db and run the following:

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "postgis";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Investigations table
CREATE TABLE investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_type VARCHAR(50) NOT NULL, -- 'domain', 'ip', 'email', 'crypto_address', 'aircraft', etc.
    target_value VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed', 'failed')),
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    tags TEXT[],
    metadata JSONB DEFAULT '{}'
);

-- Investigation tasks
CREATE TABLE investigation_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    module_name VARCHAR(100) NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    priority INTEGER DEFAULT 0,
    parameters JSONB DEFAULT '{}',
    result_data JSONB DEFAULT '{}',
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    execution_time INTERVAL,
    retry_count INTEGER DEFAULT 0
);

-- ============================================================================
-- INTELLIGENCE DATA TABLES
-- ============================================================================

-- Domain intelligence
CREATE TABLE domain_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    whois_data JSONB DEFAULT '{}',
    dns_records JSONB DEFAULT '{}',
    ssl_certificates JSONB DEFAULT '{}',
    subdomains TEXT[],
    technologies JSONB DEFAULT '{}',
    security_score INTEGER,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IP intelligence
CREATE TABLE ip_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL UNIQUE,
    geolocation JSONB DEFAULT '{}',
    asn_info JSONB DEFAULT '{}',
    threat_intelligence JSONB DEFAULT '{}',
    services JSONB DEFAULT '{}',
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email intelligence
CREATE TABLE email_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    domain_part VARCHAR(255),
    breaches JSONB DEFAULT '{}',
    social_profiles JSONB DEFAULT '{}',
    professional_info JSONB DEFAULT '{}',
    risk_score INTEGER,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cryptocurrency intelligence
CREATE TABLE crypto_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address VARCHAR(100) NOT NULL,
    currency VARCHAR(10) NOT NULL, -- BTC, ETH, LTC, DOGE
    balance DECIMAL(36,18),
    transaction_count INTEGER,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    exchanges JSONB DEFAULT '{}',
    risk_score INTEGER,
    patterns JSONB DEFAULT '{}',
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(address, currency)
);

-- Flight intelligence
CREATE TABLE flight_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    aircraft_registration VARCHAR(10) NOT NULL UNIQUE,
    icao_code VARCHAR(10),
    aircraft_type VARCHAR(50),
    owner_info JSONB DEFAULT '{}',
    flight_history JSONB DEFAULT '{}',
    route_patterns JSONB DEFAULT '{}',
    risk_indicators JSONB DEFAULT '{}',
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Social media intelligence
CREATE TABLE social_media_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    platform VARCHAR(50) NOT NULL,
    username VARCHAR(100) NOT NULL,
    profile_url VARCHAR(500),
    profile_data JSONB DEFAULT '{}',
    posts_data JSONB DEFAULT '{}',
    connections JSONB DEFAULT '{}',
    risk_score INTEGER,
    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(platform, username)
);

-- ============================================================================
-- SECURITY & AUDIT TABLES
-- ============================================================================

-- Users and authentication
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys management
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    service_name VARCHAR(100) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit INTEGER DEFAULT 1000,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- ANALYTICS & REPORTING TABLES
-- ============================================================================

-- Reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    content JSONB DEFAULT '{}',
    generated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    file_path VARCHAR(500)
);

-- Analytics data
CREATE TABLE analytics_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(20,6),
    dimensions JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Core indexes
CREATE INDEX idx_investigations_status ON investigations(status);
CREATE INDEX idx_investigations_created_at ON investigations(created_at);
CREATE INDEX idx_investigations_target ON investigations(target_type, target_value);
CREATE INDEX idx_investigation_tasks_investigation ON investigation_tasks(investigation_id);
CREATE INDEX idx_investigation_tasks_status ON investigation_tasks(status);

-- Intelligence data indexes
CREATE INDEX idx_domain_intelligence_domain ON domain_intelligence(domain);
CREATE INDEX idx_ip_intelligence_ip ON ip_intelligence(ip_address);
CREATE INDEX idx_email_intelligence_email ON email_intelligence(email);
CREATE INDEX idx_crypto_intelligence_address ON crypto_intelligence(address, currency);
CREATE INDEX idx_flight_intelligence_registration ON flight_intelligence(aircraft_registration);
CREATE INDEX idx_social_media_platform_username ON social_media_intelligence(platform, username);

-- Security indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Analytics indexes
CREATE INDEX idx_reports_investigation ON reports(investigation_id);
CREATE INDEX idx_analytics_metric ON analytics_data(metric_name, timestamp);

-- ============================================================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- ============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers
CREATE TRIGGER update_investigations_updated_at BEFORE UPDATE ON investigations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Create default admin user (password: admin123 - CHANGE THIS!)
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@osint-suite.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeCt1uB0Y1uFe3Qa', 'admin');

-- Create sample investigation
INSERT INTO investigations (name, description, target_type, target_value, priority) VALUES
('Sample Domain Analysis', 'Example investigation for demonstration', 'domain', 'example.com', 'medium');

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active investigations view
CREATE VIEW active_investigations AS
SELECT * FROM investigations
WHERE status IN ('active', 'paused')
ORDER BY priority DESC, created_at DESC;

-- Recent intelligence view
CREATE VIEW recent_intelligence AS
SELECT 'domain' as type, domain as identifier, last_scanned FROM domain_intelligence
UNION ALL
SELECT 'ip' as type, ip_address::text as identifier, last_scanned FROM ip_intelligence
UNION ALL
SELECT 'email' as type, email as identifier, last_scanned FROM email_intelligence
ORDER BY last_scanned DESC
LIMIT 100;

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to get investigation statistics
CREATE OR REPLACE FUNCTION get_investigation_stats(investigation_uuid UUID)
RETURNS TABLE (
    total_tasks BIGINT,
    completed_tasks BIGINT,
    failed_tasks BIGINT,
    running_tasks BIGINT,
    avg_execution_time INTERVAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*) as total_tasks,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_tasks,
        COUNT(*) FILTER (WHERE status = 'failed') as failed_tasks,
        COUNT(*) FILTER (WHERE status = 'running') as running_tasks,
        AVG(execution_time) as avg_execution_time
    FROM investigation_tasks
    WHERE investigation_id = investigation_uuid;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate risk scores
CREATE OR REPLACE FUNCTION calculate_risk_score(entity_type VARCHAR, entity_data JSONB)
RETURNS INTEGER AS $$
DECLARE
    risk_score INTEGER := 0;
BEGIN
    -- Basic risk scoring logic (can be enhanced with ML models)
    CASE entity_type
        WHEN 'crypto_address' THEN
            -- High balance = higher risk
            IF (entity_data->>'balance')::DECIMAL > 100 THEN
                risk_score := risk_score + 30;
            END IF;
            -- Many transactions = higher risk
            IF (entity_data->>'transaction_count')::INTEGER > 1000 THEN
                risk_score := risk_score + 20;
            END IF;
        WHEN 'domain' THEN
            -- Recently registered domains are riskier
            IF (entity_data->>'days_since_creation')::INTEGER < 30 THEN
                risk_score := risk_score + 40;
            END IF;
        WHEN 'email' THEN
            -- Breached emails are high risk
            IF jsonb_array_length(entity_data->'breaches') > 0 THEN
                risk_score := risk_score + 50;
            END IF;
    END CASE;

    RETURN LEAST(risk_score, 100);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PERMISSIONS
-- ============================================================================

-- Grant permissions to osint_user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO osint_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO osint_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO osint_user;

-- ============================================================================
-- FINAL SETUP NOTES
-- ============================================================================

-- After running this script:
-- 1. Change the default admin password
-- 2. Configure your API keys in config/config.ini
-- 3. Set up Redis and Elasticsearch if using those features
-- 4. Configure backup procedures
-- 5. Set up monitoring and alerting

COMMIT;