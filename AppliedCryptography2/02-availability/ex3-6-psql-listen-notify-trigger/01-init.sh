#!/bin/bash
set -e

# 1. Create a dedicated user for replication
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE repluser WITH REPLICATION PASSWORD 'replpassword' LOGIN;
EOSQL

# 2. Append a rule to pg_hba.conf to allow the replicas to connect
echo "host replication repluser all scram-sha-256" >> "$PGDATA/pg_hba.conf"