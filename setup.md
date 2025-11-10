# MITRE ATT&CK Ingestion Pipeline

## Requirements

### 1.  System Dependencies
- Docker (recommended for Neo4j setup)
- Python 3.8+
- `py2neo` library

### 2. Python Setup
```bash
pip install py2neo
```
### Neo4j Setup
```bash
docker run --name neo4j \
  -p7474:7474 -p7687:7687 \
  -d \
  -e NEO4J_AUTH=<username>/<password>\
  neo4j:5
```
### 3. Create files

create a file named "cred.json" in the base folder that looks like this and make sure they match whatever you put above

```bash
{
    "username": "username",
    "password": "password"
}
```
### 4. View Neo4j dashboard
To Access Neo4j Browser
Open http://localhost:7474 Login: <username> / <password>

### 5. graph creation
Run graph.py and it will create the graph. it may take a few minutes depending on how good your computer hardware is. You can then go back to the dashboard and run the command
``` bash
match (n:tactic) return n
```to see the main tactics of the mitre attack framework
