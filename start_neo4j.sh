#!/bin/bash
echo "Starting Neo4j Docker container..."
docker run --name neo4j \
  -p7474:7474 -p7687:7687 \
  -d \
  -e NEO4J_AUTH=neo4j/password123 \
  neo4j:5
echo ""
echo "Neo4j container started!"
echo "Access Neo4j Browser at: http://localhost:7474"
echo "Username: neo4j"
echo "Password: password123"

