/**
 * Chat Interface Component
 * Handles LLM chat for attack injection with Hacker Assistant
 */

class ChatInterface {
    constructor() {
        this.messages = [];
        this.currentAttackData = null;
        this.executionState = {
            isExecuting: false,
            currentExecutionId: null,
            lastRequestTime: 0
        };
        this.hackerMode = null; // 'predefined' or 'dynamic' or null
        this.selectedAgentType = null;
        this.initializeEventListeners();
        this.initializeHackerAssistant();
    }

    initializeEventListeners() {
        const chatInput = document.getElementById('chatInput');
        const sendBtn = document.getElementById('sendBtn');
        const executeBtn = document.getElementById('executeAttackBtn');
        const agentTypeSelect = document.getElementById('agentTypeSelect');

        // Send message on Enter key
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Send button click
        sendBtn.addEventListener('click', () => {
            this.sendMessage();
        });

        // Execute attack button
        executeBtn.addEventListener('click', () => {
            this.executeAttack();
        });

        // Agent type selection
        agentTypeSelect.addEventListener('change', () => {
            this.selectedAgentType = agentTypeSelect.value;
            this.updateExecuteButton();
            // If hacker mode is active, show scenarios when agent type is selected
            if (this.hackerMode === 'predefined' && this.selectedAgentType) {
                this.loadPredefinedScenarios();
            }
        });
    }

    async initializeHackerAssistant() {
        try {
            const response = await apiClient.hackerInit();
            if (response.success) {
                this.addMessage('assistant', response.message);
                this.showModeSelection();
            }
        } catch (error) {
            console.error('Error initializing hacker assistant:', error);
            this.addSystemMessage('Welcome! Describe the attack you want to test, or select an agent type and attack type from the options above.');
        }
    }

    showModeSelection() {
        const modeContainer = document.createElement('div');
        modeContainer.className = 'mode-selection-container';
        modeContainer.innerHTML = `
            <div class="mode-buttons">
                <button class="btn btn-mode" id="predefinedModeBtn" data-mode="predefined">
                    📋 Predefined Scenarios
                </button>
                <button class="btn btn-mode" id="dynamicModeBtn" data-mode="dynamic">
                    🎯 Dynamic Hacker Mode
                </button>
            </div>
        `;
        
        const messagesContainer = document.getElementById('chatMessages');
        messagesContainer.appendChild(modeContainer);
        
        // Add event listeners
        document.getElementById('predefinedModeBtn').addEventListener('click', () => {
            this.selectMode('predefined');
        });
        
        document.getElementById('dynamicModeBtn').addEventListener('click', () => {
            this.selectMode('dynamic');
        });
    }

    selectMode(mode) {
        this.hackerMode = mode;
        this.addMessage('assistant', `Selected: ${mode === 'predefined' ? 'Predefined Scenarios' : 'Dynamic Hacker Mode'}`);
        
        if (mode === 'predefined') {
            if (this.selectedAgentType) {
                this.loadPredefinedScenarios();
            } else {
                this.addMessage('assistant', 'Please select an agent type first to see available scenarios.');
            }
        } else if (mode === 'dynamic') {
            this.addMessage('assistant', 'Dynamic hacker mode ready. Select an agent type and click the button below to start, or I will generate attacks dynamically.');
            // Add button to start dynamic attack
            const dynamicBtn = document.createElement('button');
            dynamicBtn.className = 'btn btn-primary';
            dynamicBtn.textContent = 'Start Dynamic Attack';
            dynamicBtn.onclick = () => this.executeDynamicAttack();
            const messagesContainer = document.getElementById('chatMessages');
            messagesContainer.appendChild(dynamicBtn);
        }
    }

    async loadPredefinedScenarios() {
        if (!this.selectedAgentType) {
            return;
        }
        
        try {
            const response = await apiClient.getPredefinedScenarios(this.selectedAgentType);
            if (response.success && response.scenarios) {
                this.displayPredefinedScenarios(response.scenarios);
            }
        } catch (error) {
            console.error('Error loading predefined scenarios:', error);
            this.addMessage('assistant', `Error loading scenarios: ${error.message}`);
        }
    }

    displayPredefinedScenarios(scenarios) {
        const scenariosContainer = document.createElement('div');
        scenariosContainer.className = 'scenarios-container';
        
        let html = '<h4>Available Attack Scenarios:</h4><div class="scenarios-list">';
        
        scenarios.forEach((scenario, index) => {
            html += `
                <div class="scenario-item" data-attack-type="${scenario.attack_type}">
                    <div class="scenario-header">
                        <strong>${scenario.name}</strong>
                        <button class="btn btn-small" onclick="chatInterface.executePredefinedScenario('${scenario.attack_type}')">
                            Execute
                        </button>
                    </div>
                    <div class="scenario-description">${scenario.description}</div>
                    ${scenario.techniques && scenario.techniques.length > 0 ? 
                        `<div class="scenario-techniques">MITRE: ${scenario.techniques.join(', ')}</div>` : ''}
                </div>
            `;
        });
        
        html += '</div>';
        scenariosContainer.innerHTML = html;
        
        const messagesContainer = document.getElementById('chatMessages');
        messagesContainer.appendChild(scenariosContainer);
    }

    async executePredefinedScenario(attackType) {
        if (!this.selectedAgentType) {
            this.addMessage('system', 'Please select an agent type first.');
            return;
        }
        
        if (this.executionState.isExecuting) {
            this.addMessage('system', 'An execution is already in progress. Please wait.');
            return;
        }
        
        const executionId = `exec_${Date.now()}`;
        this.executionState.isExecuting = true;
        this.executionState.currentExecutionId = executionId;
        this.executionState.lastRequestTime = Date.now();
        
        // Add execution start message
        this.addMessage('assistant', `🔴 Starting ${attackType} attack on ${this.selectedAgentType} agent...`);
        
        // Add stop button
        this.showStopButton(executionId);
        
        try {
            // Subscribe to WebSocket events for this execution
            this.subscribeToExecutionEvents(executionId);
            
            // Start execution
            const response = await apiClient.executePredefinedAttack(
                this.selectedAgentType,
                attackType,
                executionId
            );
            
            if (response.success) {
                this.addMessage('assistant', `Execution started. Waiting for scenario generation...`);
            } else {
                throw new Error(response.error || 'Failed to start execution');
            }
        } catch (error) {
            this.executionState.isExecuting = false;
            this.hideStopButton();
            this.addMessage('assistant', `Error starting execution: ${error.message}`);
            console.error('Execution error:', error);
        }
    }
    
    showStopButton(executionId) {
        const messagesContainer = document.getElementById('chatMessages');
        const stopBtnContainer = document.createElement('div');
        stopBtnContainer.id = 'stopButtonContainer';
        stopBtnContainer.className = 'stop-button-container';
        stopBtnContainer.innerHTML = `
            <button class="btn btn-danger" id="stopExecutionBtn" onclick="chatInterface.stopExecution('${executionId}')">
                ⏹ Stop Attack
            </button>
        `;
        messagesContainer.appendChild(stopBtnContainer);
    }
    
    hideStopButton() {
        const stopBtn = document.getElementById('stopButtonContainer');
        if (stopBtn) {
            stopBtn.remove();
        }
    }
    
    async stopExecution(executionId) {
        try {
            const response = await apiClient.stopHackerExecution(executionId);
            if (response.success) {
                this.addMessage('system', '⏹ Stop request sent. Execution will stop after current step.');
                this.hideStopButton();
            }
        } catch (error) {
            this.addMessage('assistant', `Error stopping execution: ${error.message}`);
        }
    }

    async executeDynamicAttack() {
        if (!this.selectedAgentType) {
            this.addMessage('system', 'Please select an agent type first.');
            return;
        }
        
        if (this.executionState.isExecuting) {
            this.addMessage('system', 'An execution is already in progress. Please wait.');
            return;
        }
        
        const executionId = `exec_${Date.now()}`;
        this.executionState.isExecuting = true;
        this.executionState.currentExecutionId = executionId;
        this.executionState.lastRequestTime = Date.now();
        
        // Add execution start message
        const stepContainer = this.addStepMessage(0, 'Initializing dynamic hacker attack...', 'initializing');
        
        try {
            // Subscribe to WebSocket events
            this.subscribeToExecutionEvents(executionId);
            
            // Start execution
            const response = await apiClient.executeDynamicAttack(
                this.selectedAgentType,
                null,
                executionId
            );
            
            if (response.success) {
                this.addMessage('assistant', `Dynamic attack execution started on ${this.selectedAgentType} agent`);
            } else {
                throw new Error(response.error || 'Failed to start execution');
            }
        } catch (error) {
            this.executionState.isExecuting = false;
            this.addMessage('assistant', `Error starting execution: ${error.message}`);
            console.error('Execution error:', error);
        }
    }

    subscribeToExecutionEvents(executionId) {
        if (!window.wsClient) {
            console.error('WebSocket client not available');
            return;
        }
        
        // Subscribe to hacker execution events
        window.wsClient.on('hacker.execution.start', (data) => {
            if (data.execution_id === executionId) {
                this.handleExecutionStart(data);
            }
        });
        
        window.wsClient.on('hacker.scenario.generated', (data) => {
            if (data.execution_id === executionId) {
                this.handleScenarioGenerated(data);
            }
        });
        
        window.wsClient.on('hacker.step.start', (data) => {
            if (data.execution_id === executionId) {
                this.handleStepStart(data);
            }
        });
        
        window.wsClient.on('hacker.step.progress', (data) => {
            if (data.execution_id === executionId) {
                this.handleStepProgress(data);
            }
        });
        
        window.wsClient.on('hacker.step.complete', (data) => {
            if (data.execution_id === executionId) {
                this.handleStepComplete(data);
            }
        });
        
        window.wsClient.on('hacker.attack.starting', (data) => {
            if (data.execution_id === executionId) {
                this.handleAttackStarting(data);
            }
        });
        
        window.wsClient.on('hacker.attack.completed', (data) => {
            if (data.execution_id === executionId) {
                this.handleAttackCompleted(data);
            }
        });
        
        window.wsClient.on('hacker.attack.attempt', (data) => {
            if (data.execution_id === executionId) {
                this.handleAttackAttempt(data);
            }
        });
        
        window.wsClient.on('hacker.agent.reaction', (data) => {
            if (data.execution_id === executionId) {
                this.handleAgentReaction(data);
            }
        });
        
        // Also listen to agent observation events from message bus
        window.wsClient.on('router-observation', (data) => {
            if (this.executionState.isExecuting) {
                this.handleAgentObservation('router', data);
            }
        });
        
        window.wsClient.on('computer-observation', (data) => {
            if (this.executionState.isExecuting) {
                this.handleAgentObservation('computer', data);
            }
        });
        
        window.wsClient.on('email-observation', (data) => {
            if (this.executionState.isExecuting) {
                this.handleAgentObservation('email', data);
            }
        });
        
        window.wsClient.on('hacker.execution.complete', (data) => {
            if (data.execution_id === executionId) {
                this.handleExecutionComplete(data);
            }
        });
        
        window.wsClient.on('hacker.execution.cancelled', (data) => {
            if (data.execution_id === executionId) {
                this.handleExecutionCancelled(data);
            }
        });
        
        window.wsClient.on('hacker.execution.failed', (data) => {
            if (data.execution_id === executionId) {
                this.handleExecutionFailed(data);
            }
        });
    }
    
    handleScenarioGenerated(data) {
        const scenario = data.scenario || '';
        const attackName = data.attack_name || '';
        
        let message = `📋 **Hacker Attack Plan Generated**\n\n`;
        message += `**Attack Type:** ${attackName}\n\n`;
        message += `**Scenario:**\n${scenario}\n\n`;
        message += `🔴 **Starting attack execution...**`;
        
        this.addMessage('assistant', message);
    }
    
    handleAttackStarting(data) {
        this.addMessage('assistant', `⚡ Launching attack attempt...`);
    }
    
    handleAttackCompleted(data) {
        const detected = data.detected ? '✅ DETECTED' : '❌ NOT DETECTED';
        const reactionCount = data.reaction_count || 0;
        this.addMessage('assistant', `Attack completed: ${detected} (${reactionCount} agent reactions)`);
    }
    
    handleAttackAttempt(data) {
        const attempt = data.attempt || 0;
        const detected = data.detected ? '✅ DETECTED' : '❌ NOT DETECTED';
        const confidence = ((data.confidence || 0) * 100).toFixed(1);
        this.addMessage('assistant', `**Attempt ${attempt} Result:** ${detected} (Confidence: ${confidence}%)`);
    }
    
    handleAgentObservation(agentType, data) {
        const message = data.message || data;
        const observations = message.observations || [];
        
        if (observations.length > 0) {
            observations.forEach(obs => {
                const description = obs.description || 'Anomaly detected';
                const severity = obs.metadata?.severity || 'medium';
                const confidence = ((obs.metadata?.confidence || 0) * 100).toFixed(1);
                this.addMessage('system', `🔔 **${agentType.toUpperCase()} Agent:** ${description} (Severity: ${severity}, Confidence: ${confidence}%)`);
            });
        }
    }
    
    handleExecutionCancelled(data) {
        this.executionState.isExecuting = false;
        this.executionState.currentExecutionId = null;
        this.hideStopButton();
        this.addMessage('assistant', `⏹ Execution cancelled. Total attempts: ${data.total_attempts || 0}`);
    }

    handleExecutionStart(data) {
        this.addMessage('assistant', `🔴 Attack execution started (${data.mode} mode)`);
    }

    handleStepStart(data) {
        const step = data.step;
        this.addStepMessage(
            step.step_number,
            step.description,
            'running',
            step.action
        );
    }

    handleStepProgress(data) {
        this.updateStepMessage(
            data.step_number,
            data.description,
            'executing'
        );
    }

    handleStepComplete(data) {
        const step = data.step;
        this.updateStepMessage(
            step.step_number,
            step.description,
            'completed',
            step.result
        );
    }

    handleAgentReaction(data) {
        const reaction = data.reaction || {};
        const agentType = data.agent_type || 'unknown';
        const description = reaction.description || 'Anomaly detected';
        const severity = reaction.severity || 'medium';
        const confidence = ((reaction.confidence || 0) * 100).toFixed(1);
        const anomalyScore = ((reaction.anomaly_score || 0) * 100).toFixed(1);
        
        let message = `🔔 **${agentType.toUpperCase()} Agent Reaction:**\n`;
        message += `- ${description}\n`;
        message += `- Severity: ${severity}\n`;
        message += `- Confidence: ${confidence}%\n`;
        message += `- Anomaly Score: ${anomalyScore}%`;
        
        if (reaction.indicators && reaction.indicators.length > 0) {
            message += `\n- Indicators: ${reaction.indicators.join(', ')}`;
        }
        
        this.addMessage('system', message);
        
        // Also update agent monitoring if available
        if (window.agentMonitor) {
            window.agentMonitor.handleReaction(agentType, reaction);
        }
    }

    handleExecutionComplete(data) {
        this.executionState.isExecuting = false;
        this.executionState.currentExecutionId = null;
        this.hideStopButton();
        
        const totalAttempts = data.total_attempts || 0;
        const detectedCount = data.detected_count || 0;
        const detectionRate = data.detection_rate || 0;
        
        let message = `✅ **Execution Completed!**\n\n`;
        message += `**Total Attack Attempts:** ${totalAttempts}\n`;
        message += `**Detected:** ${detectedCount} / ${totalAttempts}\n`;
        message += `**Detection Rate:** ${(detectionRate * 100).toFixed(1)}%\n`;
        
        if (data.total_duration_ms) {
            message += `**Total Duration:** ${(data.total_duration_ms / 1000).toFixed(2)}s\n`;
        }
        
        if (detectedCount === 0) {
            message += `\n⚠️ **Warning:** No attacks were detected. System may need improvement.`;
        } else if (detectedCount === totalAttempts) {
            message += `\n✅ **Excellent:** All attacks were detected!`;
        } else {
            message += `\n⚠️ **Partial Detection:** Some attacks went undetected.`;
        }
        
        this.addMessage('assistant', message);
        
        // Show test result if available
        if (window.resultsManager && data.attack_results && data.attack_results.length > 0) {
            // Display the last test result
            const lastResult = data.attack_results[data.attack_results.length - 1];
            if (lastResult.test_result) {
                window.resultsManager.displayResult(lastResult.test_result);
            }
        }
    }

    handleExecutionFailed(data) {
        this.executionState.isExecuting = false;
        this.executionState.currentExecutionId = null;
        this.addMessage('assistant', `❌ Execution failed: ${data.error || 'Unknown error'}`);
    }

    addStepMessage(stepNumber, description, status, data = null) {
        const messagesContainer = document.getElementById('chatMessages');
        const stepDiv = document.createElement('div');
        stepDiv.className = `execution-step step-${status}`;
        stepDiv.setAttribute('data-step-number', stepNumber);
        
        let html = `<div class="step-header">`;
        html += `<span class="step-number">Step ${stepNumber}</span>`;
        html += `<span class="step-status status-${status}">${status.toUpperCase()}</span>`;
        html += `</div>`;
        html += `<div class="step-description">${description}</div>`;
        
        if (data) {
            html += `<div class="step-data">${JSON.stringify(data, null, 2)}</div>`;
        }
        
        stepDiv.innerHTML = html;
        messagesContainer.appendChild(stepDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        return stepDiv;
    }

    updateStepMessage(stepNumber, description, status, result = null) {
        const stepDiv = document.querySelector(`.execution-step[data-step-number="${stepNumber}"]`);
        if (!stepDiv) {
            return;
        }
        
        stepDiv.className = `execution-step step-${status}`;
        const statusSpan = stepDiv.querySelector('.step-status');
        if (statusSpan) {
            statusSpan.className = `step-status status-${status}`;
            statusSpan.textContent = status.toUpperCase();
        }
        
        if (result) {
            let resultHtml = '<div class="step-result">';
            if (result.analysis) {
                resultHtml += `<div class="result-analysis">${JSON.stringify(result.analysis, null, 2)}</div>`;
            }
            if (result.test_result) {
                resultHtml += `<div class="result-test">Test Result: ${result.test_result.detected ? 'DETECTED' : 'NOT DETECTED'}</div>`;
            }
            resultHtml += '</div>';
            stepDiv.innerHTML += resultHtml;
        }
        
        const messagesContainer = document.getElementById('chatMessages');
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    async sendMessage() {
        const chatInput = document.getElementById('chatInput');
        const message = chatInput.value.trim();
        
        if (!message) return;
        
        // Check for execution state to prevent looping
        const currentTime = Date.now();
        if (this.executionState.isExecuting && 
            (currentTime - this.executionState.lastRequestTime) < 1000) {
            console.log('Request debounced - execution in progress');
            return;
        }

        // Add user message to UI
        this.addMessage('user', message);
        chatInput.value = '';

        // Show loading
        const loadingMessage = this.addMessage('assistant', 'Thinking...', true);

        try {
            const agentType = document.getElementById('agentTypeSelect').value;
            const response = await apiClient.processChat(message, null, agentType || null);

            // Remove loading message
            loadingMessage.remove();

            if (response.requires_clarification) {
                this.addMessage('assistant', response.message);
                if (response.questions && response.questions.length > 0) {
                    response.questions.forEach(question => {
                        this.addMessage('system', question);
                    });
                }
            } else {
                this.addMessage('assistant', response.message);
                
                if (response.attack_data) {
                    this.currentAttackData = response.attack_data;
                    this.showAttackPreview(response.attack_data, response.intent);
                    this.updateExecuteButton();
                }

                if (response.test_result) {
                    // Test was automatically executed
                    this.showTestResult(response.test_result);
                }
            }
        } catch (error) {
            loadingMessage.remove();
            this.addMessage('assistant', `Error: ${error.message}`);
            console.error('Chat error:', error);
        }
    }

    addMessage(type, content, isLoading = false) {
        const messagesContainer = document.getElementById('chatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        
        if (isLoading) {
            messageDiv.classList.add('loading');
        }
        
        const contentP = document.createElement('p');
        // Support markdown-like formatting
        contentP.innerHTML = content.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                                     .replace(/\n/g, '<br>');
        messageDiv.appendChild(contentP);
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        this.messages.push({ type, content, timestamp: new Date() });
        
        return messageDiv;
    }

    addSystemMessage(content) {
        this.addMessage('system', content);
    }

    showAttackPreview(attackData, intent) {
        const previewDiv = document.getElementById('attackPreview');
        const previewContent = document.getElementById('previewContent');
        
        let previewText = `Agent Type: ${intent?.agent_type || attackData.agent_type || 'Unknown'}\n`;
        previewText += `Attack Type: ${intent?.attack_type || attackData.attack_type || 'Unknown'}\n`;
        
        if (attackData.description) {
            previewText += `\nDescription: ${attackData.description}\n`;
        }
        
        if (attackData.technique_id) {
            previewText += `MITRE Technique: ${attackData.technique_id}`;
            if (attackData.technique_name) {
                previewText += ` - ${attackData.technique_name}`;
            }
            previewText += '\n';
        }
        
        if (attackData.indicators && attackData.indicators.length > 0) {
            previewText += `\nIndicators:\n${attackData.indicators.map(ind => `  - ${ind}`).join('\n')}\n`;
        }
        
        previewText += `\nAttack Data:\n${JSON.stringify(attackData, null, 2)}`;
        
        previewContent.textContent = previewText;
        previewDiv.style.display = 'block';
    }

    updateExecuteButton() {
        const executeBtn = document.getElementById('executeAttackBtn');
        const agentType = document.getElementById('agentTypeSelect').value;
        
        if (this.currentAttackData && agentType) {
            executeBtn.disabled = false;
        } else {
            executeBtn.disabled = true;
        }
    }

    async executeAttack() {
        if (!this.currentAttackData) {
            this.addMessage('system', 'No attack data available. Please generate an attack first.');
            return;
        }

        const agentType = document.getElementById('agentTypeSelect').value;
        if (!agentType) {
            this.addMessage('system', 'Please select an agent type first.');
            return;
        }

        const loadingMessage = this.addMessage('assistant', 'Executing attack test...', true);

        try {
            const result = await apiClient.runTest(
                this.currentAttackData,
                agentType,
                true
            );

            loadingMessage.remove();

            if (result.success && result.test_result) {
                this.showTestResult(result.test_result);
                this.addMessage('assistant', `Attack test completed. ${result.test_result.detected ? 'Threat detected!' : 'No threat detected.'}`);
            } else {
                throw new Error('Test execution failed');
            }
        } catch (error) {
            loadingMessage.remove();
            this.addMessage('assistant', `Error executing attack: ${error.message}`);
            console.error('Attack execution error:', error);
        }
    }

    showTestResult(testResult) {
        // Trigger agent monitoring update
        if (window.agentMonitor) {
            window.agentMonitor.handleTestResult(testResult);
        }

        // Show results section
        if (window.resultsManager) {
            window.resultsManager.displayResult(testResult);
        }
    }

    clearChat() {
        const messagesContainer = document.getElementById('chatMessages');
        messagesContainer.innerHTML = '';
        this.messages = [];
        this.currentAttackData = null;
        this.hackerMode = null;
        this.executionState.isExecuting = false;
        this.executionState.currentExecutionId = null;
        document.getElementById('attackPreview').style.display = 'none';
        this.initializeHackerAssistant();
    }
}

// Initialize chat interface when DOM is ready
let chatInterface;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        chatInterface = new ChatInterface();
        window.chatInterface = chatInterface; // Make available globally
    });
} else {
    chatInterface = new ChatInterface();
    window.chatInterface = chatInterface; // Make available globally
}
