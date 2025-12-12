/**
 * WebSocket/SSE Client Module
 * Handles real-time agent updates from message bus
 */

class WebSocketClient {
    constructor() {
        this.socket = null;
        this.eventSource = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 3000;
        this.listeners = new Map();
        this.isConnected = false;
    }

    connect() {
        // Try WebSocket first, fallback to SSE
        if (window.WebSocket) {
            this.connectWebSocket();
        } else if (window.EventSource) {
            this.connectSSE();
        } else {
            console.error('WebSocket and EventSource not supported');
        }
    }

    connectWebSocket() {
        // Use Socket.IO if available, otherwise fallback to native WebSocket
        if (window.io) {
            this.connectSocketIO();
            return;
        }
        
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.hostname}:5000/ws/agent-updates`;
        
        try {
            this.socket = new WebSocket(wsUrl);
            
            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.emit('connected', {});
            };

            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.emit('error', { error });
            };

            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.isConnected = false;
                this.emit('disconnected', {});
                this.attemptReconnect();
            };
        } catch (error) {
            console.error('WebSocket connection failed, trying SSE:', error);
            this.connectSSE();
        }
    }

    connectSSE() {
        const sseUrl = `http://${window.location.hostname}:5000/api/events/stream`;
        
        try {
            this.eventSource = new EventSource(sseUrl);
            
            this.eventSource.onopen = () => {
                console.log('SSE connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.emit('connected', {});
            };

            this.eventSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (error) {
                    console.error('Error parsing SSE message:', error);
                }
            };

            this.eventSource.addEventListener('agent.router.observations', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.emit('router-observation', data);
                } catch (error) {
                    console.error('Error parsing router observation:', error);
                }
            });

            this.eventSource.addEventListener('agent.computer.observations', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.emit('computer-observation', data);
                } catch (error) {
                    console.error('Error parsing computer observation:', error);
                }
            });

            this.eventSource.addEventListener('agent.email.observations', (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.emit('email-observation', data);
                } catch (error) {
                    console.error('Error parsing email observation:', error);
                }
            });

            this.eventSource.onerror = (error) => {
                console.error('SSE error:', error);
                this.isConnected = false;
                this.emit('error', { error });
                this.attemptReconnect();
            };
        } catch (error) {
            console.error('SSE connection failed:', error);
        }
    }

    connectSocketIO() {
        // Socket.IO connection (preferred for Flask-SocketIO)
        try {
            this.socket = window.io('http://' + window.location.hostname + ':5000', {
                transports: ['websocket', 'polling']
            });
            
            this.socket.on('connect', () => {
                console.log('Socket.IO connected');
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.emit('connected', {});
                
                // Subscribe to hacker events
                this.socket.emit('subscribe_hacker_events');
            });
            
            this.socket.on('disconnect', () => {
                console.log('Socket.IO disconnected');
                this.isConnected = false;
                this.emit('disconnected', {});
                this.attemptReconnect();
            });
            
            // Handle hacker execution events
            this.socket.on('hacker.execution.start', (data) => {
                this.emit('hacker.execution.start', data);
            });
            
            this.socket.on('hacker.step.start', (data) => {
                this.emit('hacker.step.start', data);
            });
            
            this.socket.on('hacker.step.progress', (data) => {
                this.emit('hacker.step.progress', data);
            });
            
            this.socket.on('hacker.step.complete', (data) => {
                this.emit('hacker.step.complete', data);
            });
            
            this.socket.on('hacker.step.failed', (data) => {
                this.emit('hacker.step.failed', data);
            });
            
            this.socket.on('hacker.agent.reaction', (data) => {
                this.emit('hacker.agent.reaction', data);
            });
            
            this.socket.on('hacker.execution.complete', (data) => {
                this.emit('hacker.execution.complete', data);
            });
            
            this.socket.on('hacker.execution.failed', (data) => {
                this.emit('hacker.execution.failed', data);
            });
            
            // Handle agent observations
            this.socket.on('router-observation', (data) => {
                this.emit('router-observation', data);
            });
            
            this.socket.on('computer-observation', (data) => {
                this.emit('computer-observation', data);
            });
            
            this.socket.on('email-observation', (data) => {
                this.emit('email-observation', data);
            });
            
            this.socket.on('error', (error) => {
                console.error('Socket.IO error:', error);
                this.emit('error', { error });
            });
            
        } catch (error) {
            console.error('Socket.IO connection failed:', error);
            this.connectSSE();
        }
    }

    handleMessage(data) {
        const { topic, message } = data;
        
        if (topic) {
            if (topic.includes('router')) {
                this.emit('router-observation', message);
            } else if (topic.includes('computer')) {
                this.emit('computer-observation', message);
            } else if (topic.includes('email')) {
                this.emit('email-observation', message);
            }
        }
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
            
            setTimeout(() => {
                if (this.socket) {
                    this.connectWebSocket();
                } else if (this.eventSource) {
                    this.connectSSE();
                }
            }, this.reconnectDelay);
        } else {
            console.error('Max reconnection attempts reached');
            this.emit('reconnect-failed', {});
        }
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
    }

    off(event, callback) {
        if (this.listeners.has(event)) {
            const callbacks = this.listeners.get(event);
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        }
    }

    emit(event, data) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error in event listener for ${event}:`, error);
                }
            });
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        this.isConnected = false;
    }
}

// Export singleton instance
const wsClient = new WebSocketClient();
window.wsClient = wsClient; // Make available globally



