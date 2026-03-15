CREATE TABLE IF NOT EXISTS schema_version (version INT PRIMARY KEY);
INSERT INTO schema_version (version) VALUES (1);

CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION notify_new_message() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('new_message_channel', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER message_insert_trigger AFTER INSERT ON messages FOR EACH ROW EXECUTE FUNCTION notify_new_message();

CREATE USER inserter WITH ENCRYPTED PASSWORD 'inserter';
GRANT CONNECT ON DATABASE testdb TO inserter;
GRANT USAGE ON SCHEMA public TO inserter;
GRANT INSERT, SELECT ON TABLE messages TO inserter;
GRANT USAGE, SELECT ON SEQUENCE messages_id_seq TO inserter;
GRANT SELECT ON TABLE schema_version TO inserter;

CREATE USER listen WITH ENCRYPTED PASSWORD 'listen';
GRANT CONNECT ON DATABASE testdb TO listen;
GRANT USAGE ON SCHEMA public TO listen;
GRANT SELECT ON TABLE messages TO listen;
GRANT USAGE, SELECT ON SEQUENCE messages_id_seq TO listen;
GRANT SELECT ON TABLE schema_version TO listen;