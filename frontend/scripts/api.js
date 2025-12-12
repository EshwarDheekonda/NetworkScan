/**
 * API Client Module
 * Handles all backend API communication
 */

const API_BASE_URL = 'http://localhost:5000/api';

class APIClient {
    constructor(baseURL = API_BASE_URL) {
        this.baseURL = baseURL;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || `HTTP error! status: ${response.status}`);
            }
            
            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    }

    // Training API
    async uploadTrainingData(agentId, file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('agent_id', agentId);

        const response = await fetch(`${this.baseURL}/training/upload`, {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Upload failed');
        }

        return await response.json();
    }

    async getTrainingStatus(agentId) {
        return this.request(`/training/status/${agentId}`);
    }

    async getTrainingStatistics(agentId) {
        return this.request(`/training/statistics/${agentId}`);
    }

    async clearBaseline(agentId) {
        return this.request(`/training/clear/${agentId}`, {
            method: 'POST',
        });
    }

    // Test API
    async getTestStatus() {
        return this.request('/test/status');
    }

    async processChat(message, context = null, agentType = null) {
        return this.request('/test/chat', {
            method: 'POST',
            body: JSON.stringify({
                message,
                context,
                agent_type: agentType,
            }),
        });
    }

    async generateAttack(attackType, agentType, description = null, techniqueId = null) {
        return this.request('/test/generate-attack', {
            method: 'POST',
            body: JSON.stringify({
                attack_type: attackType,
                agent_type: agentType,
                description,
                technique_id: techniqueId,
            }),
        });
    }

    async runTest(attackData, agentId, expectedDetection = true) {
        return this.request('/test/run-test', {
            method: 'POST',
            body: JSON.stringify({
                attack_data: attackData,
                agent_id: agentId,
                expected_detection: expectedDetection,
            }),
        });
    }

    async getTestResults(limit = null, testId = null) {
        const params = new URLSearchParams();
        if (limit) params.append('limit', limit);
        if (testId) params.append('test_id', testId);
        
        const query = params.toString();
        return this.request(`/test/results${query ? '?' + query : ''}`);
    }

    async generateReport(testId = null) {
        return this.request('/test/generate-report', {
            method: 'POST',
            body: JSON.stringify({
                test_id: testId,
            }),
        });
    }

    async clearResults() {
        return this.request('/test/clear-results', {
            method: 'POST',
        });
    }

    // System Control API
    async stopSystem() {
        return this.request('/system/stop', {
            method: 'POST',
        });
    }

    async resetSystem() {
        return this.request('/system/reset', {
            method: 'POST',
        });
    }

    async startSystem() {
        return this.request('/system/start', {
            method: 'POST',
        });
    }

    // Health check
    async healthCheck() {
        try {
            const response = await fetch(`${this.baseURL.replace('/api', '')}/health`);
            return await response.json();
        } catch (error) {
            throw new Error('Backend not available');
        }
    }

    // Auto Test API
    async autoTest() {
        return this.request('/test/auto-test', {
            method: 'POST',
        });
    }

    // Hacker Assistant API
    async hackerInit() {
        return this.request('/test/hacker/init', {
            method: 'GET',
        });
    }

    async getPredefinedScenarios(agentType) {
        return this.request(`/test/hacker/predefined-scenarios?agent_type=${agentType}`, {
            method: 'GET',
        });
    }

    async executePredefinedAttack(agentType, attackType, executionId = null) {
        const execId = executionId || `exec_${Date.now()}`;
        return this.request('/test/hacker/execute-predefined', {
            method: 'POST',
            body: JSON.stringify({
                agent_type: agentType,
                attack_type: attackType,
                execution_id: execId,
            }),
        });
    }

    async executeDynamicAttack(agentType, context = null, executionId = null) {
        const execId = executionId || `exec_${Date.now()}`;
        return this.request('/test/hacker/execute-dynamic', {
            method: 'POST',
            body: JSON.stringify({
                agent_type: agentType,
                context: context,
                execution_id: execId,
            }),
        });
    }

    async getExecutionStatus() {
        return this.request('/test/hacker/execution-status', {
            method: 'GET',
        });
    }

    async stopHackerExecution(executionId = null) {
        return this.request('/test/hacker/stop', {
            method: 'POST',
            body: JSON.stringify({
                execution_id: executionId,
            }),
        });
    }
}

// Export singleton instance
const apiClient = new APIClient();



