/**
 * Main Application
 * Orchestrates all components and handles system-wide functionality
 */

class App {
    constructor() {
        this.systemStatus = 'ready';
        this.isSystemRunning = false;
        this.initializeEventListeners();
        this.initializeNavbar();
        this.checkBackendHealth();
    }

    initializeEventListeners() {
        // System control buttons
        const stopBtn = document.getElementById('stopSystemBtn');
        const resetBtn = document.getElementById('resetSystemBtn');
        const startBtn = document.getElementById('startSystemBtn');

        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                this.stopSystem();
            });
        }

        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                this.resetSystem();
            });
        }

        if (startBtn) {
            startBtn.addEventListener('click', () => {
                this.startSystem();
            });
        }

        // Navbar scroll effect
        window.addEventListener('scroll', () => {
            this.handleNavbarScroll();
        });
    }

    initializeNavbar() {
        this.updateSystemStatus('ready');
    }

    handleNavbarScroll() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }

    async checkBackendHealth() {
        try {
            await apiClient.healthCheck();
            this.updateSystemStatus('ready');
        } catch (error) {
            this.updateSystemStatus('error');
            console.error('Backend health check failed:', error);
        }
    }

    updateSystemStatus(status) {
        this.systemStatus = status;
        const statusIndicator = document.getElementById('systemStatus');
        const statusText = document.getElementById('systemStatusText');

        if (statusIndicator && statusText) {
            switch (status) {
                case 'ready':
                    statusIndicator.className = 'status-indicator';
                    statusIndicator.textContent = '●';
                    statusText.textContent = 'Ready';
                    break;
                case 'running':
                    statusIndicator.className = 'status-indicator';
                    statusIndicator.textContent = '●';
                    statusText.textContent = 'Running';
                    this.isSystemRunning = true;
                    break;
                case 'stopped':
                    statusIndicator.className = 'status-indicator warning';
                    statusIndicator.textContent = '●';
                    statusText.textContent = 'Stopped';
                    this.isSystemRunning = false;
                    break;
                case 'error':
                    statusIndicator.className = 'status-indicator danger';
                    statusIndicator.textContent = '●';
                    statusText.textContent = 'Error';
                    break;
                default:
                    statusIndicator.className = 'status-indicator';
                    statusIndicator.textContent = '●';
                    statusText.textContent = 'Unknown';
            }
        }
    }

    async startSystem() {
        this.showLoading('Starting system...');
        
        try {
            await apiClient.startSystem();
            this.updateSystemStatus('running');
            
            // Connect WebSocket
            if (wsClient && !wsClient.isConnected) {
                wsClient.connect();
            }
            
            this.hideLoading();
            this.showNotification('System started successfully', 'success');
        } catch (error) {
            this.hideLoading();
            this.showNotification(`Error starting system: ${error.message}`, 'error');
            console.error('Error starting system:', error);
        }
    }

    async stopSystem() {
        if (!confirm('Are you sure you want to stop the system?')) {
            return;
        }

        this.showLoading('Stopping system...');
        
        try {
            await apiClient.stopSystem();
            this.updateSystemStatus('stopped');
            
            // Disconnect WebSocket
            if (wsClient && wsClient.isConnected) {
                wsClient.disconnect();
            }
            
            this.hideLoading();
            this.showNotification('System stopped', 'success');
        } catch (error) {
            this.hideLoading();
            this.showNotification(`Error stopping system: ${error.message}`, 'error');
            console.error('Error stopping system:', error);
        }
    }

    async resetSystem() {
        if (!confirm('Are you sure you want to reset the system? This will clear all data.')) {
            return;
        }

        this.showLoading('Resetting system...');
        
        try {
            await apiClient.resetSystem();
            
            // Clear agent data
            if (window.agentMonitor) {
                window.agentMonitor.clearAll();
            }
            
            // Clear test info
            if (window.testManager) {
                window.testManager.clearAttackInfo();
            }
            
            // Clear results
            if (window.resultsManager) {
                window.resultsManager.hideResults();
            }
            
            // Reload training status
            if (window.trainingManager) {
                window.trainingManager.loadTrainingStatus();
            }
            
            this.updateSystemStatus('ready');
            this.hideLoading();
            this.showNotification('System reset successfully', 'success');
        } catch (error) {
            this.hideLoading();
            this.showNotification(`Error resetting system: ${error.message}`, 'error');
            console.error('Error resetting system:', error);
        }
    }

    showLoading(text = 'Loading...') {
        const overlay = document.getElementById('loadingOverlay');
        const loadingText = document.getElementById('loadingText');
        
        if (overlay) {
            overlay.style.display = 'flex';
        }
        
        if (loadingText) {
            loadingText.textContent = text;
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            padding: 15px 25px;
            background: ${type === 'success' ? 'var(--success-color)' : type === 'error' ? 'var(--danger-color)' : 'var(--netflix-gray)'};
            color: white;
            border-radius: 4px;
            z-index: 10000;
            animation: slideInRight 0.3s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
}

// Initialize app when DOM is ready
let app;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        app = new App();
        
        // Connect WebSocket after a short delay
        setTimeout(() => {
            if (wsClient) {
                wsClient.connect();
            }
        }, 1000);
    });
} else {
    app = new App();
    
    // Connect WebSocket after a short delay
    setTimeout(() => {
        if (wsClient) {
            wsClient.connect();
        }
    }, 1000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);




