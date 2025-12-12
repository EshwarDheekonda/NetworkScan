"""
Backend Server Initialization Script
Starts the Flask API server with all agents and services configured.
"""

import logging
import sys
from typing import Optional

from agents.crew_orchestrator import CrewOrchestrator
from attack_testing.test_orchestrator import TestOrchestrator
from attack_testing.api import run_api_server
from baseline_training.training_orchestrator import TrainingOrchestrator
from baseline_training import training_api
from communication.message_bus import MessageBus
from knowledge_fusion.fusion_core import KnowledgeFusion

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def initialize_message_bus() -> Optional[MessageBus]:
    """Initialize Redis message bus if available."""
    try:
        message_bus = MessageBus(host='localhost', port=6379)
        if message_bus.is_connected():
            logger.info("Message bus connected successfully")
            return message_bus
        else:
            logger.warning("Message bus connection failed - continuing without real-time updates")
            return None
    except Exception as e:
        logger.warning(f"Could not connect to message bus: {e} - continuing without real-time updates")
        return None


def main():
    """Main function to start the backend server."""
    logger.info("=" * 60)
    logger.info("Network Scan Backend Server")
    logger.info("=" * 60)
    
    # Initialize message bus (optional)
    logger.info("Initializing message bus...")
    message_bus = initialize_message_bus()
    
    # Initialize training orchestrator FIRST (before agents)
    logger.info("Initializing training orchestrator...")
    try:
        training_orchestrator = TrainingOrchestrator()
        training_api.set_orchestrator(training_orchestrator)
        logger.info("Training orchestrator initialized")
    except Exception as e:
        logger.warning(f"Error initializing training orchestrator: {e} - continuing without training")
        training_orchestrator = None
    
    # Initialize Knowledge Fusion for MITRE ATT&CK integration
    logger.info("Initializing Knowledge Fusion...")
    try:
        knowledge_fusion = KnowledgeFusion()
        logger.info("Knowledge Fusion initialized")
    except Exception as e:
        logger.warning(f"Error initializing Knowledge Fusion: {e} - continuing without MITRE integration")
        knowledge_fusion = None
    
    # Initialize agents WITH training orchestrator (to use trained baselines)
    logger.info("Initializing agents...")
    try:
        crew_orchestrator = CrewOrchestrator(
            training_orchestrator=training_orchestrator,
            knowledge_fusion=knowledge_fusion
        )
        agents = crew_orchestrator.agents
        logger.info(f"Initialized {len(agents)} agents: {list(agents.keys())}")
        if training_orchestrator:
            logger.info("Agents initialized with training orchestrator integration")
    except Exception as e:
        logger.error(f"Error initializing agents: {e}", exc_info=True)
        sys.exit(1)
    
    # Initialize test orchestrator
    logger.info("Initializing test orchestrator...")
    try:
        test_orchestrator = TestOrchestrator(
            agents=agents,
            training_orchestrator=training_orchestrator
        )
        logger.info("Test orchestrator initialized")
    except Exception as e:
        logger.error(f"Error initializing test orchestrator: {e}", exc_info=True)
        sys.exit(1)
    
    # Setup message bus publishers for agents (if message bus available)
    if message_bus:
        logger.info("Setting up agent message bus publishers...")
        from communication.agent_publisher import AgentPublisher
        for agent_id, agent in agents.items():
            try:
                publisher = AgentPublisher(message_bus, agent_id)
                agent.publisher = publisher
                logger.info(f"Publisher set up for {agent_id} agent")
            except Exception as e:
                logger.warning(f"Could not set up publisher for {agent_id}: {e}")
    
    # Start API server
    logger.info("=" * 60)
    logger.info("Starting Flask API server on http://0.0.0.0:5000")
    logger.info("API Documentation: http://localhost:5000/health")
    logger.info("=" * 60)
    
    try:
        run_api_server(
            test_orchestrator=test_orchestrator,
            agents=agents,
            message_bus=message_bus,
            host='0.0.0.0',
            port=5000,
            debug=True
        )
    except KeyboardInterrupt:
        logger.info("\nShutting down server...")
    except Exception as e:
        logger.error(f"Error running server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()




