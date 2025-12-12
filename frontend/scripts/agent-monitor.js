/**
 * Agent Monitor Component
 * Displays real-time observations, communications, and outputs for all three agents
 */

class AgentMonitor {
    constructor() {
        this.agents = ['router', 'computer', 'email'];
        this.observations = {
            router: [],
            computer: [],
            email: []
        };
        this.warnings = {
            router: [],
            computer: [],
            email: []
        };
        this.communications = {
            router: [],
            computer: [],
            email: []
        };
        this.outputs = {
            router: [],
            computer: [],
            email: []
        };
        this.mitreData = {
            router: { techniques: [], tactics: [] },
            computer: { techniques: [], tactics: [] },
            email: { techniques: [], tactics: [] }
        };
        this.metrics = {
            router: { anomalyScore: 0, confidence: 0, observationCount: 0 },
            computer: { anomalyScore: 0, confidence: 0, observationCount: 0 },
            email: { anomalyScore: 0, confidence: 0, observationCount: 0 }
        };
        
        this.initializeWebSocket();
        this.initializeUI();
    }

    initializeWebSocket() {
        // Listen for real-time updates
        wsClient.on('router-observation', (data) => {
            console.log('Received router-observation:', data);
            this.handleObservation('router', data);
        });

        wsClient.on('computer-observation', (data) => {
            console.log('Received computer-observation:', data);
            this.handleObservation('computer', data);
        });

        wsClient.on('email-observation', (data) => {
            console.log('Received email-observation:', data);
            this.handleObservation('email', data);
        });

        // Listen for proactive warnings
        wsClient.on('proactive_warning', (data) => {
            console.log('Received proactive_warning:', data);
            this.handleProactiveWarning(data);
        });

        // Listen for agent outputs
        wsClient.on('agent-output', (data) => {
            console.log('Received agent-output:', data);
            if (data.agent_id && data.output) {
                this.addOutput(data.agent_id, data.output);
            }
        });

        // Listen for agent communications (collaboration)
        wsClient.on('collaborative_detection', (data) => {
            console.log('Received collaborative_detection:', data);
            if (data.message) {
                const message = data.message;
                const detectedBy = message.detected_by || [];
                detectedBy.forEach(agentId => {
                    this.addCommunication(agentId, {
                        from: message.detected_by ? message.detected_by.join(', ') : 'System',
                        to: agentId,
                        message: `Collaborative detection: ${message.attack_type || 'Threat detected'}`,
                        direction: 'incoming',
                        timestamp: data.timestamp || new Date().toISOString()
                    });
                });
            }
        });

        wsClient.on('connected', () => {
            console.log('WebSocket connected for agent monitoring');
            this.updateAgentStatus('router', 'idle');
            this.updateAgentStatus('computer', 'idle');
            this.updateAgentStatus('email', 'idle');
        });

        wsClient.on('disconnected', () => {
            console.log('WebSocket disconnected');
            this.updateAgentStatus('router', 'idle');
            this.updateAgentStatus('computer', 'idle');
            this.updateAgentStatus('email', 'idle');
        });
    }

    initializeUI() {
        // Initialize empty states
        this.agents.forEach(agentId => {
            this.updateMetrics(agentId);
        });
    }

    handleObservation(agentId, data) {
        console.log(`handleObservation called for ${agentId}:`, data);
        // Update agent status
        this.updateAgentStatus(agentId, 'analyzing');

        // Handle both wrapped and direct formats
        const messageData = data.message || data;
        console.log(`Extracted messageData for ${agentId}:`, messageData);

        // Extract observations from AgentOutput
        let observations = [];
        if (messageData.observations && Array.isArray(messageData.observations)) {
            observations = messageData.observations;
        } else if (messageData.observation) {
            observations = [messageData.observation];
        } else if (messageData.type === 'observation') {
            observations = [messageData];
        }

        // Process each observation
        observations.forEach(obs => {
            this.addObservation(agentId, obs);
        });

        // Update metrics from message data
        if (messageData.confidence !== undefined) {
            this.metrics[agentId].confidence = messageData.confidence;
        }

        // Extract max anomaly score from metadata or observations
        let maxAnomalyScore = 0.0;
        if (messageData.metadata && messageData.metadata.max_anomaly_score !== undefined) {
            maxAnomalyScore = messageData.metadata.max_anomaly_score;
        } else if (messageData.metadata && messageData.metadata.anomaly_score !== undefined) {
            maxAnomalyScore = messageData.metadata.anomaly_score;
        } else if (observations.length > 0) {
            // Extract from observation metadata
            for (const obs of observations) {
                if (obs.metadata) {
                    const obsMaxScore = obs.metadata.max_anomaly_score || 
                                      (obs.metadata.anomaly_scores && 
                                       typeof obs.metadata.anomaly_scores === 'object' ? 
                                       Math.max(...Object.values(obs.metadata.anomaly_scores)) : 0.0);
                    maxAnomalyScore = Math.max(maxAnomalyScore, obsMaxScore);
                }
            }
        }
        
        if (maxAnomalyScore > 0) {
            this.metrics[agentId].anomalyScore = maxAnomalyScore;
        }

        // Update observation count
        this.metrics[agentId].observationCount += observations.length;

        // Add agent output to outputs feed
        if (observations.length > 0) {
            const outputData = {
                agent_id: agentId,
                timestamp: messageData.timestamp || new Date().toISOString(),
                observations_count: observations.length,
                confidence: messageData.confidence || 0.0,
                max_anomaly_score: maxAnomalyScore
            };
            this.addOutput(agentId, outputData);
        }

        // Update UI
        this.updateMetrics(agentId);

        // Reset status after a delay
        setTimeout(() => {
            this.updateAgentStatus(agentId, 'idle');
        }, 2000);
    }

    addObservation(agentId, observation) {
        const observationsFeed = document.getElementById(`${agentId}Observations`);
        if (!observationsFeed) return;

        // Create observation item
        const obsItem = document.createElement('div');
        obsItem.className = `observation-item ${observation.severity || 'medium'}`;

        const timestamp = new Date(observation.timestamp || Date.now()).toLocaleTimeString();
        const timestampDiv = document.createElement('div');
        timestampDiv.className = 'observation-timestamp';
        timestampDiv.textContent = timestamp;
        obsItem.appendChild(timestampDiv);

        const descriptionDiv = document.createElement('div');
        descriptionDiv.className = 'observation-description';
        descriptionDiv.textContent = observation.description || 'Observation';
        obsItem.appendChild(descriptionDiv);

        // Extract and display MITRE techniques from metadata
        if (observation.metadata) {
            const llmAnalysis = observation.metadata.llm_analysis;
            if (llmAnalysis) {
                const proactiveMitre = llmAnalysis.proactive_mitre;
                if (proactiveMitre && proactiveMitre.matched_techniques) {
                    const mitreDiv = document.createElement('div');
                    mitreDiv.className = 'observation-mitre';
                    proactiveMitre.matched_techniques.forEach(tech => {
                        const badge = document.createElement('span');
                        badge.className = 'mitre-badge';
                        // Use external_id (T1071) if available, otherwise use name
                        const displayText = tech.external_id || tech.name || 'MITRE';
                        badge.textContent = displayText;
                        // Set tooltip with full technique name and description
                        const tooltip = tech.name ? `${tech.external_id || ''} - ${tech.name}${tech.description ? ': ' + tech.description : ''}` : '';
                        badge.title = tooltip;
                        mitreDiv.appendChild(badge);
                    });
                    obsItem.appendChild(mitreDiv);
                }
            }
        }

        if (observation.indicators && observation.indicators.length > 0) {
            const indicatorsDiv = document.createElement('div');
            indicatorsDiv.className = 'observation-indicators';
            observation.indicators.forEach(indicator => {
                // Filter out Neo4j node IDs (attack-pattern--uuid format)
                if (typeof indicator === 'string' && indicator.startsWith('attack-pattern--')) {
                    return; // Skip Neo4j node IDs
                }
                const span = document.createElement('span');
                span.className = 'indicator-badge';
                span.textContent = indicator;
                indicatorsDiv.appendChild(span);
            });
            // Only append if there are valid indicators after filtering
            if (indicatorsDiv.children.length > 0) {
                obsItem.appendChild(indicatorsDiv);
            }
        }

        // Add to feed
        observationsFeed.appendChild(obsItem);
        observationsFeed.scrollTop = observationsFeed.scrollHeight;

        // Keep only last 50 observations
        while (observationsFeed.children.length > 50) {
            observationsFeed.removeChild(observationsFeed.firstChild);
        }

        // Update count
        this.metrics[agentId].observationCount++;
        this.observations[agentId].push(observation);

        // Update MITRE display
        this.updateMitreDisplay(agentId, observation);
    }

    handleProactiveWarning(data) {
        // Handle both wrapped and direct formats
        const message = data.message || data;
        const warningData = message.message || message;
        const agentId = warningData.detected_by && warningData.detected_by.length > 0 
            ? warningData.detected_by[0] 
            : null;
        
        if (!agentId || !this.agents.includes(agentId)) {
            console.warn('Unknown agent ID in proactive warning:', agentId);
            return;
        }

        this.addWarning(agentId, warningData);
        this.updateMitreDisplay(agentId, null, warningData);
        this.updateAgentStatus(agentId, 'alert');
    }

    addWarning(agentId, warning) {
        const warningsFeed = document.getElementById(`${agentId}Warnings`);
        if (!warningsFeed) return;

        const warningItem = document.createElement('div');
        warningItem.className = `warning-item ${warning.severity || 'medium'}`;

        const timestamp = new Date(warning.timestamp || Date.now()).toLocaleTimeString();
        const headerDiv = document.createElement('div');
        headerDiv.className = 'warning-header';
        headerDiv.innerHTML = `
            <span class="warning-severity ${warning.severity || 'medium'}">${(warning.severity || 'medium').toUpperCase()}</span>
            <span class="warning-time">${timestamp}</span>
        `;
        warningItem.appendChild(headerDiv);

        const attackTypeDiv = document.createElement('div');
        attackTypeDiv.className = 'warning-attack-type';
        attackTypeDiv.textContent = warning.attack_type || 'Security Threat';
        warningItem.appendChild(attackTypeDiv);

        if (warning.description) {
            const descDiv = document.createElement('div');
            descDiv.className = 'warning-description';
            descDiv.textContent = warning.description;
            warningItem.appendChild(descDiv);
        }

        // Display MITRE techniques
        if (warning.mitre_techniques && warning.mitre_techniques.length > 0) {
            const mitreDiv = document.createElement('div');
            mitreDiv.className = 'warning-mitre-techniques';
            mitreDiv.innerHTML = '<strong>MITRE Techniques:</strong>';
            const techList = document.createElement('ul');
            warning.mitre_techniques.forEach(tech => {
                const li = document.createElement('li');
                // Prefer external_id (T1071) over Neo4j node id
                const techId = tech.external_id || (tech.id && !tech.id.startsWith('attack-pattern--') ? tech.id : '');
                const techName = tech.name || 'Unknown Technique';
                li.innerHTML = `<span class="mitre-tech-id">${techId || 'T-XXXX'}</span> - ${techName}`;
                // Set tooltip with description if available
                if (tech.description) {
                    li.title = `${techId || ''} - ${techName}: ${tech.description}`;
                } else {
                    li.title = `${techId || ''} - ${techName}`;
                }
                techList.appendChild(li);
            });
            mitreDiv.appendChild(techList);
            warningItem.appendChild(mitreDiv);
        }

        // Display MITRE tactics
        if (warning.mitre_tactics && warning.mitre_tactics.length > 0) {
            const tacticsDiv = document.createElement('div');
            tacticsDiv.className = 'warning-mitre-tactics';
            tacticsDiv.innerHTML = '<strong>MITRE Tactics:</strong>';
            const tacticsList = document.createElement('ul');
            warning.mitre_tactics.forEach(tactic => {
                const li = document.createElement('li');
                li.textContent = tactic.name || '';
                if (tactic.description) {
                    li.title = tactic.description;
                }
                tacticsList.appendChild(li);
            });
            tacticsDiv.appendChild(tacticsList);
            warningItem.appendChild(tacticsDiv);
        }

        // Display mitigations
        if (warning.mitigations && warning.mitigations.length > 0) {
            const mitigationsDiv = document.createElement('div');
            mitigationsDiv.className = 'warning-mitigations';
            mitigationsDiv.innerHTML = '<strong>Mitigations:</strong>';
            const mitigationsList = document.createElement('ul');
            warning.mitigations.forEach(mitigation => {
                const li = document.createElement('li');
                li.textContent = mitigation.name || mitigation.description || '';
                mitigationsList.appendChild(li);
            });
            mitigationsDiv.appendChild(mitigationsList);
            warningItem.appendChild(mitigationsDiv);
        }

        // Display recommended actions
        if (warning.recommended_actions && warning.recommended_actions.length > 0) {
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'warning-actions';
            actionsDiv.innerHTML = '<strong>Recommended Actions:</strong>';
            const actionsList = document.createElement('ul');
            warning.recommended_actions.forEach(action => {
                const li = document.createElement('li');
                li.textContent = action;
                actionsList.appendChild(li);
            });
            actionsDiv.appendChild(actionsList);
            warningItem.appendChild(actionsDiv);
        }

        if (warning.confidence !== undefined) {
            const confidenceDiv = document.createElement('div');
            confidenceDiv.className = 'warning-confidence';
            confidenceDiv.textContent = `Confidence: ${(warning.confidence * 100).toFixed(1)}%`;
            warningItem.appendChild(confidenceDiv);
        }

        warningsFeed.appendChild(warningItem);
        warningsFeed.scrollTop = warningsFeed.scrollHeight;

        // Keep only last 20 warnings
        while (warningsFeed.children.length > 20) {
            warningsFeed.removeChild(warningsFeed.firstChild);
        }

        this.warnings[agentId].push(warning);
    }

    updateMitreDisplay(agentId, observation = null, warning = null) {
        const mitreContent = document.getElementById(`${agentId}Mitre`);
        if (!mitreContent) return;

        // Collect MITRE techniques and tactics
        const techniques = [];
        const tactics = [];

        // From observations
        if (observation && observation.metadata) {
            const llmAnalysis = observation.metadata.llm_analysis;
            if (llmAnalysis && llmAnalysis.proactive_mitre) {
                if (llmAnalysis.proactive_mitre.matched_techniques) {
                    techniques.push(...llmAnalysis.proactive_mitre.matched_techniques);
                }
                if (llmAnalysis.proactive_mitre.matched_tactics) {
                    tactics.push(...llmAnalysis.proactive_mitre.matched_tactics);
                }
            }
        }

        // From warnings
        if (warning) {
            if (warning.mitre_techniques) {
                techniques.push(...warning.mitre_techniques);
            }
            if (warning.mitre_tactics) {
                tactics.push(...warning.mitre_tactics);
            }
        }

        // Deduplicate
        const uniqueTechniques = [];
        const seenTechIds = new Set();
        techniques.forEach(tech => {
            const id = tech.id || tech.external_id || tech.name;
            if (id && !seenTechIds.has(id)) {
                seenTechIds.add(id);
                uniqueTechniques.push(tech);
            }
        });

        const uniqueTactics = [];
        const seenTacticNames = new Set();
        tactics.forEach(tactic => {
            const name = tactic.name || tactic.tactic;
            if (name && !seenTacticNames.has(name)) {
                seenTacticNames.add(name);
                uniqueTactics.push(tactic);
            }
        });

        // Update display
        if (uniqueTechniques.length === 0 && uniqueTactics.length === 0) {
            mitreContent.innerHTML = '<p class="no-mitre-data">No MITRE data available</p>';
            return;
        }

        let html = '';

        if (uniqueTechniques.length > 0) {
            html += '<div class="mitre-section"><h5>Techniques</h5><ul class="mitre-techniques-list">';
            uniqueTechniques.forEach(tech => {
                // Prefer external_id (T1071) over Neo4j node id
                const techId = tech.external_id || (tech.id && !tech.id.startsWith('attack-pattern--') ? tech.id : '');
                const techName = tech.name || 'Unknown Technique';
                html += `<li><span class="mitre-tech-id">${techId || 'T-XXXX'}</span> - ${techName}</li>`;
            });
            html += '</ul></div>';
        }

        if (uniqueTactics.length > 0) {
            html += '<div class="mitre-section"><h5>Tactics</h5><ul class="mitre-tactics-list">';
            uniqueTactics.forEach(tactic => {
                html += `<li>${tactic.name || tactic.tactic || ''}</li>`;
            });
            html += '</ul></div>';
        }

        mitreContent.innerHTML = html;
    }

    addCommunication(agentId, communication) {
        const communicationsFeed = document.getElementById(`${agentId}Communications`);
        if (!communicationsFeed) return;

        const commItem = document.createElement('div');
        commItem.className = `communication-item ${communication.direction || ''}`;
        
        const timestamp = new Date(communication.timestamp || Date.now()).toLocaleTimeString();
        commItem.textContent = `[${timestamp}] ${communication.from || 'Unknown'} → ${communication.to || 'Unknown'}: ${communication.message || communication.content || ''}`;
        
        communicationsFeed.appendChild(commItem);
        communicationsFeed.scrollTop = communicationsFeed.scrollHeight;

        // Keep only last 30 communications
        while (communicationsFeed.children.length > 30) {
            communicationsFeed.removeChild(communicationsFeed.firstChild);
        }

        this.communications[agentId].push(communication);
    }

    addOutput(agentId, output) {
        const outputFeed = document.getElementById(`${agentId}Outputs`);
        if (!outputFeed) return;

        const outputItem = document.createElement('div');
        outputItem.className = 'output-item';
        
        // Format output nicely
        if (typeof output === 'string') {
            outputItem.textContent = output;
        } else if (output.observations_count !== undefined) {
            // Format agent output
            const timestamp = output.timestamp ? new Date(output.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
            const confidence = output.confidence ? (output.confidence * 100).toFixed(1) + '%' : 'N/A';
            const anomalyScore = output.max_anomaly_score !== undefined ? output.max_anomaly_score.toFixed(2) : 'N/A';
            const detected = output.detected ? 'Yes' : 'No';
            const attackType = output.attack_type || 'Unknown';
            
            outputItem.innerHTML = `
                <div class="output-header">
                    <span class="output-timestamp">[${timestamp}]</span>
                    <span class="output-type">${attackType}</span>
                </div>
                <div class="output-details">
                    <span>Observations: ${output.observations_count}</span>
                    <span>Confidence: ${confidence}</span>
                    <span>Anomaly Score: ${anomalyScore}</span>
                    <span>Detected: ${detected}</span>
                </div>
            `;
        } else {
            outputItem.textContent = JSON.stringify(output, null, 2);
        }
        
        outputFeed.appendChild(outputItem);
        outputFeed.scrollTop = outputFeed.scrollHeight;

        // Keep only last 20 outputs
        while (outputFeed.children.length > 20) {
            outputFeed.removeChild(outputFeed.firstChild);
        }

        this.outputs[agentId].push(output);
    }

    updateAgentStatus(agentId, status) {
        const statusDot = document.getElementById(`${agentId}AgentStatus`);
        const statusText = document.getElementById(`${agentId}AgentStatusText`);
        const agentWindow = document.querySelector(`.agent-window[data-agent="${agentId}"]`);

        if (statusDot) {
            statusDot.className = `status-dot ${status}`;
        }

        if (statusText) {
            statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }

        if (agentWindow) {
            if (status === 'analyzing' || status === 'active') {
                agentWindow.classList.add('active');
            } else {
                agentWindow.classList.remove('active');
            }
        }
    }

    updateMetrics(agentId) {
        const metrics = this.metrics[agentId];
        
        const anomalyScoreEl = document.getElementById(`${agentId}AnomalyScore`);
        if (anomalyScoreEl) {
            anomalyScoreEl.textContent = metrics.anomalyScore.toFixed(2);
            anomalyScoreEl.className = 'metric-value';
            if (metrics.anomalyScore > 0.7) {
                anomalyScoreEl.classList.add('high');
            } else if (metrics.anomalyScore > 0.4) {
                anomalyScoreEl.classList.add('medium');
            } else {
                anomalyScoreEl.classList.add('low');
            }
        }

        const confidenceEl = document.getElementById(`${agentId}Confidence`);
        if (confidenceEl) {
            confidenceEl.textContent = (metrics.confidence * 100).toFixed(1) + '%';
        }

        const observationCountEl = document.getElementById(`${agentId}ObservationCount`);
        if (observationCountEl) {
            observationCountEl.textContent = metrics.observationCount;
        }
    }

    handleTestResult(testResult) {
        // Update agent windows based on test result
        const agentId = testResult.agent_id;
        
        if (testResult.detections && testResult.detections.length > 0) {
            testResult.detections.forEach(detection => {
                this.addObservation(agentId, detection);
            });
        }

        // Update metrics
        if (testResult.max_anomaly_score !== undefined) {
            this.metrics[agentId].anomalyScore = testResult.max_anomaly_score;
        }
        if (testResult.confidence !== undefined) {
            this.metrics[agentId].confidence = testResult.confidence;
        }

        this.updateMetrics(agentId);
        this.updateAgentStatus(agentId, testResult.detected ? 'alert' : 'idle');
    }

    clearAgentData(agentId) {
        const observationsFeed = document.getElementById(`${agentId}Observations`);
        const warningsFeed = document.getElementById(`${agentId}Warnings`);
        const mitreContent = document.getElementById(`${agentId}Mitre`);
        const communicationsFeed = document.getElementById(`${agentId}Communications`);
        const outputFeed = document.getElementById(`${agentId}Outputs`);

        if (observationsFeed) observationsFeed.innerHTML = '';
        if (warningsFeed) warningsFeed.innerHTML = '';
        if (mitreContent) mitreContent.innerHTML = '<p class="no-mitre-data">No MITRE data available</p>';
        if (communicationsFeed) communicationsFeed.innerHTML = '';
        if (outputFeed) outputFeed.innerHTML = '';

        this.observations[agentId] = [];
        this.warnings[agentId] = [];
        this.communications[agentId] = [];
        this.outputs[agentId] = [];
        this.mitreData[agentId] = { techniques: [], tactics: [] };
        this.metrics[agentId] = { anomalyScore: 0, confidence: 0, observationCount: 0 };
        this.updateMetrics(agentId);
    }

    clearAll() {
        this.agents.forEach(agentId => {
            this.clearAgentData(agentId);
        });
    }
}

// Initialize agent monitor when DOM is ready
let agentMonitor;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        agentMonitor = new AgentMonitor();
        window.agentMonitor = agentMonitor;
    });
} else {
    agentMonitor = new AgentMonitor();
    window.agentMonitor = agentMonitor;
}




