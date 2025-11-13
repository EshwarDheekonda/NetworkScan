from py2neo import Graph, Node, Relationship
import json
import re

with open("cred.json") as file:
    creds = json.load(file)

# Connect to Neo4j
graph = Graph("bolt://localhost:7687", auth=(creds["username"], creds["password"]))

# Load STIX data
with open("enterprise-attack.json") as f:
    data = json.load(f)

# Map STIX types to Neo4j labels
type_map = {
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "intrusion-set": "Group",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "course-of-action": "Mitigation"
}

# Create nodes
for obj in data["objects"]:
    label = type_map.get(obj["type"])
    if label:
        node = Node(label,
                    id=obj["id"],
                    name=obj.get("name", ""),
                    description=obj.get("description", ""))
        graph.merge(node, label, "id")

# Create relationships from STIX relationship objects
for obj in data["objects"]:
    if obj["type"] == "relationship":
        source = obj["source_ref"]
        target = obj["target_ref"]
        rel_type = obj["relationship_type"].upper().replace("-", "_")
        graph.run(f"""
            MATCH (a {{id: '{source}'}}), (b {{id: '{target}'}})
            MERGE (a)-[:`{rel_type}`]->(b)
        """)

# Normalize phase_name to match existing tactic names
def normalize_phase_name(name):
    return " ".join(part.title() if part != 'and' else part for part in name.split("-"))

# Create :USES relationships from Tactic → Technique
for obj in data["objects"]:
    if obj["type"] == "attack-pattern":
        technique_id = obj["id"]
        external_id = None
        for ref in obj.get("external_references", []):
            if "external_id" in ref:
                external_id = ref["external_id"]

        technique_node = Node("Technique",
                              id=technique_id,
                              external_id=external_id,
                              name=obj["name"],
                              description=obj.get("description", ""))
        graph.merge(technique_node, "Technique", "id")

        for phase in obj.get("kill_chain_phases", []):
            normalized_name = normalize_phase_name(phase["phase_name"])
            graph.run(f"""
                MATCH (t:Tactic {{name: '{normalized_name}'}})
                MATCH (tech:Technique {{id: '{technique_id}'}})
                MERGE (t)-[:USES]->(tech)
            """)

# Create NEXT_PHASE relationships between tactics
tactic_order = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

for i in range(len(tactic_order) - 1):
    graph.run(f"""
        MATCH (a:Tactic {{name: '{tactic_order[i]}'}}), (b:Tactic {{name: '{tactic_order[i+1]}'}})
        MERGE (a)-[:NEXT_PHASE]->(b)
    """)
