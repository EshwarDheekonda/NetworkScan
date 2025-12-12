/**
 * Training Component
 * Handles baseline training data upload for all three agents
 */

class TrainingManager {
    constructor() {
        this.agents = ['router', 'computer', 'email'];
        this.initializeEventListeners();
        this.loadTrainingStatus();
    }

    initializeEventListeners() {
        this.agents.forEach(agentId => {
            const uploadArea = document.getElementById(`${agentId}Upload`);
            const fileInput = document.getElementById(`${agentId}File`);
            const uploadContent = uploadArea.querySelector('.upload-content');

            // Click to browse
            uploadArea.addEventListener('click', () => {
                fileInput.click();
            });

            // File selection
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    this.handleFileUpload(agentId, file);
                }
            });

            // Drag and drop
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });

            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });

            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                
                const file = e.dataTransfer.files[0];
                if (file && this.isValidFile(file)) {
                    this.handleFileUpload(agentId, file);
                } else {
                    this.showError(agentId, 'Invalid file type. Please upload JSON, CSV, or JSONL files.');
                }
            });
        });
    }

    isValidFile(file) {
        const validExtensions = ['.json', '.csv', '.jsonl'];
        const fileName = file.name.toLowerCase();
        return validExtensions.some(ext => fileName.endsWith(ext));
    }

    async handleFileUpload(agentId, file) {
        const uploadArea = document.getElementById(`${agentId}Upload`);
        const progressDiv = document.getElementById(`${agentId}Progress`);
        const progressFill = document.getElementById(`${agentId}ProgressFill`);
        const progressText = document.getElementById(`${agentId}ProgressText`);
        const statusBadge = document.getElementById(`${agentId}Status`);

        // Show progress
        uploadArea.style.display = 'none';
        progressDiv.style.display = 'block';
        progressFill.style.width = '0%';
        progressText.textContent = 'Uploading...';
        statusBadge.textContent = 'Training';
        statusBadge.className = 'status-badge training';

        try {
            // Simulate progress
            this.animateProgress(progressFill, 0, 50, 1000);

            // Upload file
            const result = await apiClient.uploadTrainingData(agentId, file);
            
            // Complete progress
            this.animateProgress(progressFill, 50, 100, 1000);

            if (result.success) {
                progressText.textContent = 'Training completed!';
                statusBadge.textContent = 'Ready';
                statusBadge.className = 'status-badge ready';
                
                // Update stats
                this.updateTrainingStats(agentId, result);
                
                // Show stats
                setTimeout(() => {
                    progressDiv.style.display = 'none';
                    document.getElementById(`${agentId}Stats`).style.display = 'flex';
                    uploadArea.style.display = 'block';
                }, 2000);
            } else {
                throw new Error(result.error_message || 'Training failed');
            }
        } catch (error) {
            console.error(`Training error for ${agentId}:`, error);
            progressText.textContent = `Error: ${error.message}`;
            statusBadge.textContent = 'Error';
            statusBadge.className = 'status-badge not-trained';
            
            setTimeout(() => {
                progressDiv.style.display = 'none';
                uploadArea.style.display = 'block';
            }, 3000);
            
            this.showError(agentId, error.message);
        }
    }

    animateProgress(element, start, end, duration) {
        const startTime = performance.now();
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const current = start + (end - start) * progress;
            element.style.width = `${current}%`;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        requestAnimationFrame(animate);
    }

    updateTrainingStats(agentId, result) {
        const recordsElement = document.getElementById(`${agentId}Records`);
        const baselineStatusElement = document.getElementById(`${agentId}BaselineStatus`);
        
        if (recordsElement) {
            recordsElement.textContent = result.records_valid || result.records_processed || 0;
        }
        
        if (baselineStatusElement) {
            const status = result.status || {};
            baselineStatusElement.textContent = status.baseline_ready ? 'Ready' : 'Not Ready';
        }
        
        // Load and display detailed metrics
        this.loadDetailedMetrics(agentId);
    }
    
    async loadDetailedMetrics(agentId) {
        try {
            const stats = await apiClient.getTrainingStatistics(agentId);
            this.displayDetailedMetrics(agentId, stats);
        } catch (error) {
            console.error(`Error loading detailed metrics for ${agentId}:`, error);
        }
    }
    
    displayDetailedMetrics(agentId, stats) {
        // Show metrics section
        const metricsDiv = document.getElementById(`${agentId}Metrics`);
        if (metricsDiv) {
            metricsDiv.style.display = 'block';
        }
        
        // Update key metrics
        const status = stats.status || {};
        this.updateElement(`${agentId}RecordsProcessed`, status.records_processed || 0);
        this.updateElement(`${agentId}RecordsValid`, status.records_valid || 0);
        this.updateElement(`${agentId}RecordsInvalid`, status.records_invalid || 0);
        this.updateElement(`${agentId}BaselineReady`, status.baseline_ready ? 'Yes' : 'No');
        this.updateElement(`${agentId}TrainingMode`, stats.mode || status.mode || '-');
        
        // Update baseline metrics
        const baselineStats = stats.baseline_stats || {};
        this.displayNumericBaselines(agentId, baselineStats.numeric_baselines || {});
        this.displayPatternBaselines(agentId, baselineStats.pattern_baselines || {});
    }
    
    displayNumericBaselines(agentId, numericBaselines) {
        const container = document.getElementById(`${agentId}NumericBaselines`);
        if (!container) return;
        
        container.innerHTML = '';
        
        if (Object.keys(numericBaselines).length === 0) {
            container.innerHTML = '<p class="no-data">No numeric baselines available</p>';
            return;
        }
        
        for (const [baselineName, baselineData] of Object.entries(numericBaselines)) {
            const baselineCard = document.createElement('div');
            baselineCard.className = 'baseline-card numeric-baseline';
            
            const shortName = baselineName.split('.').pop() || baselineName;
            const isReady = baselineData.is_ready ? 'Ready' : 'Not Ready';
            const readyClass = baselineData.is_ready ? 'ready' : 'not-ready';
            
            baselineCard.innerHTML = `
                <div class="baseline-header">
                    <h6>${shortName}</h6>
                    <span class="baseline-status ${readyClass}">${isReady}</span>
                </div>
                <div class="baseline-details">
                    <div class="detail-row">
                        <span class="detail-label">Sample Count:</span>
                        <span class="detail-value">${baselineData.sample_count || 0}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Mean:</span>
                        <span class="detail-value">${this.formatNumber(baselineData.mean)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Std Dev:</span>
                        <span class="detail-value">${this.formatNumber(baselineData.std)}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Median:</span>
                        <span class="detail-value">${this.formatNumber(baselineData.median)}</span>
                    </div>
                    ${baselineData.percentiles ? `
                    <div class="detail-row percentiles">
                        <span class="detail-label">Percentiles:</span>
                        <div class="percentile-values">
                            <span>P25: ${this.formatNumber(baselineData.percentiles.p25)}</span>
                            <span>P50: ${this.formatNumber(baselineData.percentiles.p50)}</span>
                            <span>P75: ${this.formatNumber(baselineData.percentiles.p75)}</span>
                            <span>P95: ${this.formatNumber(baselineData.percentiles.p95)}</span>
                            <span>P99: ${this.formatNumber(baselineData.percentiles.p99)}</span>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
            
            container.appendChild(baselineCard);
        }
    }
    
    displayPatternBaselines(agentId, patternBaselines) {
        const container = document.getElementById(`${agentId}PatternBaselines`);
        if (!container) return;
        
        container.innerHTML = '';
        
        if (Object.keys(patternBaselines).length === 0) {
            container.innerHTML = '<p class="no-data">No pattern baselines available</p>';
            return;
        }
        
        for (const [baselineName, baselineData] of Object.entries(patternBaselines)) {
            const baselineCard = document.createElement('div');
            baselineCard.className = 'baseline-card pattern-baseline';
            
            const shortName = baselineName.split('.').pop() || baselineName;
            const isReady = baselineData.is_ready ? 'Ready' : 'Not Ready';
            const readyClass = baselineData.is_ready ? 'ready' : 'not-ready';
            
            baselineCard.innerHTML = `
                <div class="baseline-header">
                    <h6>${shortName}</h6>
                    <span class="baseline-status ${readyClass}">${isReady}</span>
                </div>
                <div class="baseline-details">
                    <div class="detail-row">
                        <span class="detail-label">Total Observations:</span>
                        <span class="detail-value">${baselineData.total_observations || 0}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Unique Patterns:</span>
                        <span class="detail-value">${baselineData.unique_patterns || 0}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Known Patterns:</span>
                        <span class="detail-value">${baselineData.known_patterns || 0}</span>
                    </div>
                </div>
            `;
            
            container.appendChild(baselineCard);
        }
    }
    
    formatNumber(value) {
        if (value === null || value === undefined) return '-';
        if (typeof value === 'number') {
            return value.toFixed(2);
        }
        return value;
    }
    
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }
    
    toggleMetrics(agentId) {
        const content = document.getElementById(`${agentId}MetricsContent`);
        const toggleIcon = document.querySelector(`#${agentId}Metrics .toggle-icon`);
        
        if (content) {
            const isVisible = content.style.display !== 'none';
            content.style.display = isVisible ? 'none' : 'block';
            if (toggleIcon) {
                toggleIcon.textContent = isVisible ? '▼' : '▲';
            }
        }
    }

    async loadTrainingStatus() {
        for (const agentId of this.agents) {
            try {
                const status = await apiClient.getTrainingStatus(agentId);
                this.updateStatusDisplay(agentId, status);
                
                // Load detailed metrics if baseline is ready
                if (status.baseline_ready) {
                    this.loadDetailedMetrics(agentId);
                }
            } catch (error) {
                console.error(`Error loading status for ${agentId}:`, error);
            }
        }
    }

    updateStatusDisplay(agentId, status) {
        const statusBadge = document.getElementById(`${agentId}Status`);
        const statsDiv = document.getElementById(`${agentId}Stats`);
        const recordsElement = document.getElementById(`${agentId}Records`);
        const baselineStatusElement = document.getElementById(`${agentId}BaselineStatus`);

        if (status.baseline_ready) {
            statusBadge.textContent = 'Ready';
            statusBadge.className = 'status-badge ready';
            statsDiv.style.display = 'flex';
            
            if (recordsElement) {
                recordsElement.textContent = status.records_processed || status.records_valid || 0;
            }
            
            if (baselineStatusElement) {
                baselineStatusElement.textContent = 'Ready';
            }
        } else {
            statusBadge.textContent = 'Not Trained';
            statusBadge.className = 'status-badge not-trained';
        }
    }

    showError(agentId, message) {
        // Create temporary error message
        const uploadArea = document.getElementById(`${agentId}Upload`);
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.cssText = `
            position: absolute;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--danger-color);
            color: white;
            padding: 10px 20px;
            border-radius: 4px;
            z-index: 1000;
        `;
        
        uploadArea.parentElement.style.position = 'relative';
        uploadArea.parentElement.appendChild(errorDiv);
        
        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
}

// Initialize training manager when DOM is ready
let trainingManager;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        trainingManager = new TrainingManager();
    });
} else {
    trainingManager = new TrainingManager();
}




