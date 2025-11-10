"""
Helper script to start Neo4j and run Knowledge Fusion module.

This script will:
1. Check if Docker is running
2. Start Neo4j container if needed
3. Wait for Neo4j to be ready
4. Run the complete Knowledge Fusion module
"""

import subprocess
import time
import sys
import json
from py2neo import Graph

def check_docker_running():
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

def wait_for_docker(max_wait=60):
    """Wait for Docker Desktop to start."""
    print("Waiting for Docker Desktop to start...")
    for i in range(max_wait):
        if check_docker_running():
            print("✅ Docker is running!")
            return True
        print(f"   Waiting... ({i+1}/{max_wait} seconds)")
        time.sleep(1)
    return False

def check_neo4j_container():
    """Check if Neo4j container exists and is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=neo4j", "--format", "{{.Names}} {{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and "neo4j" in result.stdout:
            return result.stdout.strip()
        return None
    except Exception:
        return None

def start_neo4j():
    """Start Neo4j container."""
    container_status = check_neo4j_container()
    
    if container_status:
        if "Up" in container_status:
            print("✅ Neo4j container is already running!")
            return True
        else:
            print("Starting existing Neo4j container...")
            try:
                subprocess.run(["docker", "start", "neo4j"], check=True, timeout=30)
                print("✅ Neo4j container started!")
                return True
            except Exception as e:
                print(f"❌ Failed to start container: {e}")
                return False
    else:
        print("Creating and starting Neo4j container...")
        try:
            # Load credentials
            try:
                with open("cred.json") as f:
                    creds = json.load(f)
                    username = creds.get("username", "neo4j")
                    password = creds.get("password", "password123")
            except FileNotFoundError:
                print("⚠️  cred.json not found, using defaults (neo4j/password123)")
                username = "neo4j"
                password = "password123"
            
            auth = f"{username}/{password}"
            
            subprocess.run([
                "docker", "run", "--name", "neo4j",
                "-p", "7474:7474",
                "-p", "7687:7687",
                "-d",
                "-e", f"NEO4J_AUTH={auth}",
                "neo4j:5"
            ], check=True, timeout=60)
            print("✅ Neo4j container created and started!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create container: {e}")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

def wait_for_neo4j(max_wait=30):
    """Wait for Neo4j to be ready to accept connections."""
    print("Waiting for Neo4j to be ready...")
    
    try:
        with open("cred.json") as f:
            creds = json.load(f)
            username = creds.get("username", "neo4j")
            password = creds.get("password", "password123")
    except FileNotFoundError:
        username = "neo4j"
        password = "password123"
    
    for i in range(max_wait):
        try:
            graph = Graph("bolt://localhost:7687", auth=(username, password))
            graph.run("RETURN 1 as test")
            print("✅ Neo4j is ready!")
            return True
        except Exception:
            if i < max_wait - 1:
                print(f"   Waiting... ({i+1}/{max_wait} seconds)")
            time.sleep(1)
    
    print("❌ Neo4j did not become ready in time")
    return False

def main():
    print("=" * 70)
    print("KNOWLEDGE FUSION MODULE - SETUP AND RUN")
    print("=" * 70)
    print()
    
    # Step 1: Check Docker
    print("[1/4] Checking Docker...")
    if not check_docker_running():
        print("⚠️  Docker is not running. Waiting for Docker Desktop to start...")
        if not wait_for_docker():
            print("❌ Docker did not start in time. Please start Docker Desktop manually.")
            print("   Then run this script again.")
            sys.exit(1)
    else:
        print("✅ Docker is running!")
    print()
    
    # Step 2: Start Neo4j
    print("[2/4] Starting Neo4j...")
    if not start_neo4j():
        print("❌ Failed to start Neo4j. Please check Docker logs.")
        sys.exit(1)
    print()
    
    # Step 3: Wait for Neo4j to be ready
    print("[3/4] Waiting for Neo4j to be ready...")
    if not wait_for_neo4j():
        print("❌ Neo4j did not become ready. Please check the container logs:")
        print("   docker logs neo4j")
        sys.exit(1)
    print()
    
    # Step 4: Run Knowledge Fusion
    print("[4/4] Running Knowledge Fusion Module...")
    print()
    print("=" * 70)
    print()
    
    try:
        import run_knowledge_fusion
        run_knowledge_fusion.run_complete_knowledge_fusion()
    except ImportError:
        print("❌ Could not import run_knowledge_fusion module")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error running Knowledge Fusion: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        sys.exit(1)


