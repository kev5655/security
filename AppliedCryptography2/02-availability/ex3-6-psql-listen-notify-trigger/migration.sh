#!/bin/bash

# 1. Reset the environment
echo "🔄 Resetting Docker environment..."
docker compose down -v --remove-orphans
docker volume ls -q | grep "data" | xargs -r docker volume rm
docker system prune -f
docker compose up -d

# Give the full cluster (Master, Replicas, Pgpool) time to initialize!
echo "⏳ Waiting 20 seconds for the database cluster and Pgpool proxy to initialize..."
sleep 20

# 2. Ensure background processes are killed when you exit the script
trap "echo 'Shutting down...'; kill 0; exit" SIGINT SIGTERM

echo "🚀 Starting 3 Listeners in the background..."
go run ./listen/main.go &
go run ./listen/main.go &
go run ./listen/main.go &

# Give listeners a second to connect before starting the inserter
sleep 2 

echo "🚀 Starting the Inserter..."
go run ./insert/main.go &

echo "--------------------------------------------------------"
echo "✅ All applications are running on V1 logic."
echo "--------------------------------------------------------"

# 3. Wait for user input
while true; do
    read -p "Type 'yes' to apply the V2 Database Upgrade: " user_input
    if [ "$user_input" = "yes" ]; then
        echo "Applying 03-upgrade.sql to the database..."
        
        # CHANGED: 'db' is now 'master' in docker-compose ps!
        docker exec -i $(docker compose ps -q master) psql -U admin -d testdb < 03-upgrade.sql
        
        echo "✅ Upgrade applied! Watch the output below to see the apps switch to V2."
        break
    else
        echo "Waiting..."
    fi
done

# Keep the script running so you can see the terminal output of the Go apps
wait