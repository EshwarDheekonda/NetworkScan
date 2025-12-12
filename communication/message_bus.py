"""
Message Bus Implementation

Redis Pub/Sub wrapper for real-time event streaming.
"""

import json
import logging
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import redis
from redis.exceptions import ConnectionError, TimeoutError

from communication.message_types import Message, Topics


class MessageBus:
    """Redis Pub/Sub message bus."""
    
    def __init__(self, host: str = "localhost", port: int = 6379, 
                 db: int = 0, password: Optional[str] = None,
                 decode_responses: bool = True):
        """
        Initialize message bus connection.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password (if required)
            decode_responses: Whether to decode responses as strings
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.decode_responses = decode_responses
        self.redis_client = None
        self.logger = logging.getLogger(__name__)
        self._connect()
    
    def _connect(self):
        """Connect to Redis."""
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=self.decode_responses,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            self.logger.info(f"Connected to Redis at {self.host}:{self.port}")
        except (ConnectionError, TimeoutError) as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error connecting to Redis: {e}")
            raise
    
    def is_connected(self) -> bool:
        """Check if connected to Redis."""
        try:
            if self.redis_client:
                self.redis_client.ping()
                return True
        except:
            pass
        return False
    
    def reconnect(self):
        """Reconnect to Redis."""
        self._connect()
    
    def publish(self, topic: str, message: Dict[str, Any]) -> int:
        """
        Publish a message to a topic.
        
        Args:
            topic: Topic name
            message: Message dictionary (will be JSON serialized)
            
        Returns:
            Number of subscribers that received the message
        """
        if not self.is_connected():
            self.reconnect()
        
        try:
            message_json = json.dumps(message, default=str)
            subscribers = self.redis_client.publish(topic, message_json)
            self.logger.debug(f"Published to {topic}, {subscribers} subscribers")
            return subscribers
        except Exception as e:
            self.logger.error(f"Failed to publish to {topic}: {e}")
            raise
    
    def subscribe(self, topics: list, callback: Callable[[str, Dict[str, Any]], None]):
        """
        Subscribe to topics and process messages.
        
        Args:
            topics: List of topic names or patterns (e.g., ["agent.*.observations"])
            callback: Callback function(topic, message_dict)
        """
        if not self.is_connected():
            self.reconnect()
        
        pubsub = self.redis_client.pubsub()
        
        # Subscribe to topics
        for topic in topics:
            pubsub.subscribe(topic)
            self.logger.info(f"Subscribed to topic: {topic}")
        
        # Process messages
        try:
            for message in pubsub.listen():
                if message['type'] == 'message':
                    topic = message['channel']
                    try:
                        message_data = json.loads(message['data'])
                        callback(topic, message_data)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to decode message from {topic}: {e}")
                    except Exception as e:
                        self.logger.error(f"Error processing message from {topic}: {e}")
        except KeyboardInterrupt:
            self.logger.info("Subscription interrupted")
        finally:
            pubsub.close()
    
    def close(self):
        """Close Redis connection."""
        if self.redis_client:
            self.redis_client.close()
            self.logger.info("Redis connection closed")


class MessageBusPublisher:
    """Publisher for sending messages to message bus."""
    
    def __init__(self, message_bus: MessageBus, topic: str):
        """
        Initialize publisher.
        
        Args:
            message_bus: MessageBus instance
            topic: Topic to publish to
        """
        self.message_bus = message_bus
        self.topic = topic
        self.logger = logging.getLogger(f"{__name__}.Publisher")
    
    def publish(self, data: Any):
        """
        Publish data to topic.
        
        Args:
            data: Data to publish (will be serialized)
        """
        try:
            # If data is a Pydantic model, convert to dict
            if hasattr(data, 'model_dump'):
                message_dict = data.model_dump()
            elif hasattr(data, 'dict'):
                message_dict = data.dict()
            elif isinstance(data, dict):
                message_dict = data
            else:
                message_dict = {'data': str(data)}
            
            # Add metadata
            message_dict['_metadata'] = {
                'timestamp': datetime.now().isoformat(),
                'topic': self.topic
            }
            
            self.message_bus.publish(self.topic, message_dict)
            self.logger.debug(f"Published to {self.topic}")
        except Exception as e:
            self.logger.error(f"Failed to publish to {self.topic}: {e}")
            raise


class MessageBusSubscriber:
    """Subscriber for receiving messages from message bus."""
    
    def __init__(self, message_bus: MessageBus, topics: list, 
                 callback: Callable[[str, Dict[str, Any]], None]):
        """
        Initialize subscriber.
        
        Args:
            message_bus: MessageBus instance
            topics: List of topics to subscribe to
            callback: Callback function(topic, message_dict)
        """
        self.message_bus = message_bus
        self.topics = topics if isinstance(topics, list) else [topics]
        self.callback = callback
        self.logger = logging.getLogger(f"{__name__}.Subscriber")
        self.is_running = False
    
    def start(self, blocking: bool = True):
        """
        Start subscribing to topics.
        
        Args:
            blocking: If True, blocks and processes messages. If False, runs in background.
        """
        self.is_running = True
        self.logger.info(f"Starting subscriber for topics: {self.topics}")
        
        if blocking:
            self.message_bus.subscribe(self.topics, self._handle_message)
        else:
            import threading
            thread = threading.Thread(target=self._run_subscriber, daemon=True)
            thread.start()
    
    def _run_subscriber(self):
        """Run subscriber in background thread."""
        self.message_bus.subscribe(self.topics, self._handle_message)
    
    def _handle_message(self, topic: str, message_dict: Dict[str, Any]):
        """Handle incoming message."""
        try:
            self.callback(topic, message_dict)
        except Exception as e:
            self.logger.error(f"Error in message callback: {e}")
    
    def stop(self):
        """Stop subscriber."""
        self.is_running = False
        self.logger.info("Subscriber stopped")




