-- Create the version tracking table
CREATE TABLE IF NOT EXISTS schema_version (
    version INT PRIMARY KEY
);

-- Insert the new version number
INSERT INTO schema_version (version) VALUES (2) ON CONFLICT DO NOTHING;

-- Upgrade the messages table
ALTER TABLE messages ADD COLUMN created_at TIMESTAMP;

-- Grant permissions so our Go apps can read the version table
GRANT SELECT ON TABLE schema_version TO listen;
GRANT SELECT ON TABLE schema_version TO inserter;