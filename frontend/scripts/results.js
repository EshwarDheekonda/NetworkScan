/**
 * Results Manager Component
 * Displays test results and statistics
 */

class ResultsManager {
    constructor() {
        this.currentResult = null;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const closeBtn = document.getElementById('closeResultsBtn');
        const exportBtn = document.getElementById('exportResultsBtn');
        const generateReportBtn = document.getElementById('generateReportBtn');

        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.hideResults();
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportResults();
            });
        }

        if (generateReportBtn) {
            generateReportBtn.addEventListener('click', () => {
                this.generateReport();
            });
        }
    }

    displayResult(testResult) {
        this.currentResult = testResult;
        const resultsSection = document.getElementById('resultsSection');
        const summaryDiv = document.getElementById('resultsSummary');
        const detailsDiv = document.getElementById('resultsDetails');

        // Build summary
        summaryDiv.innerHTML = this.buildSummary(testResult);

        // Build details
        detailsDiv.innerHTML = this.buildDetails(testResult);

        // Show results section
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    buildSummary(testResult) {
        const detected = testResult.detected ? 'Yes' : 'No';
        const detectedClass = testResult.detected ? 'success' : 'danger';
        const confidence = (testResult.confidence * 100).toFixed(1);
        const executionTime = testResult.execution_time_ms ? testResult.execution_time_ms.toFixed(2) : 'N/A';

        return `
            <div class="summary-grid">
                <div class="summary-item">
                    <span class="summary-label">Threat Detected:</span>
                    <span class="summary-value ${detectedClass}">${detected}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Confidence:</span>
                    <span class="summary-value">${confidence}%</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Anomaly Score:</span>
                    <span class="summary-value">${testResult.max_anomaly_score?.toFixed(2) || 'N/A'}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Execution Time:</span>
                    <span class="summary-value">${executionTime} ms</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Agent:</span>
                    <span class="summary-value">${testResult.agent_id || 'Unknown'}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Attack Type:</span>
                    <span class="summary-value">${testResult.attack_type || 'Unknown'}</span>
                </div>
            </div>
        `;
    }

    buildDetails(testResult) {
        let html = '';

        // Detections
        if (testResult.detections && testResult.detections.length > 0) {
            html += '<div class="details-section">';
            html += '<h3>Detections</h3>';
            testResult.detections.forEach((detection, index) => {
                html += `
                    <div class="detection-item">
                        <h4>Detection ${index + 1}</h4>
                        <p><strong>Description:</strong> ${detection.description || 'N/A'}</p>
                        <p><strong>Severity:</strong> <span class="severity-${detection.severity || 'medium'}">${detection.severity || 'medium'}</span></p>
                        ${detection.indicators ? `<p><strong>Indicators:</strong> ${detection.indicators.join(', ')}</p>` : ''}
                        ${detection.metadata ? `<pre>${JSON.stringify(detection.metadata, null, 2)}</pre>` : ''}
                    </div>
                `;
            });
            html += '</div>';
        }

        // Attack Data
        if (testResult.attack_data) {
            html += '<div class="details-section">';
            html += '<h3>Attack Data</h3>';
            html += `<pre class="attack-data">${JSON.stringify(testResult.attack_data, null, 2)}</pre>`;
            html += '</div>';
        }

        // Metrics
        if (testResult.metrics) {
            html += '<div class="details-section">';
            html += '<h3>Metrics</h3>';
            html += `<pre>${JSON.stringify(testResult.metrics, null, 2)}</pre>`;
            html += '</div>';
        }

        return html || '<p>No detailed information available.</p>';
    }

    hideResults() {
        const resultsSection = document.getElementById('resultsSection');
        resultsSection.style.display = 'none';
    }

    async exportResults() {
        if (!this.currentResult) {
            alert('No results to export');
            return;
        }

        const dataStr = JSON.stringify(this.currentResult, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `test-result-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
    }

    async generateReport() {
        if (!this.currentResult) {
            alert('No results available');
            return;
        }

        try {
            const testId = this.currentResult.test_id;
            const response = await apiClient.generateReport(testId);
            
            if (response.success && response.report) {
                // Display report
                const detailsDiv = document.getElementById('resultsDetails');
                detailsDiv.innerHTML = `
                    <div class="report-section">
                        <h3>Comprehensive Test Report</h3>
                        <pre>${JSON.stringify(response.report, null, 2)}</pre>
                        ${response.summary ? `<div class="report-summary">${response.summary}</div>` : ''}
                    </div>
                `;
            } else {
                throw new Error('Failed to generate report');
            }
        } catch (error) {
            console.error('Error generating report:', error);
            alert(`Error generating report: ${error.message}`);
        }
    }

    async loadRecentResults() {
        try {
            const response = await apiClient.getTestResults(10);
            if (response.success && response.results) {
                // Display list of recent results
                return response.results;
            }
        } catch (error) {
            console.error('Error loading recent results:', error);
        }
        return [];
    }
}

// Initialize results manager when DOM is ready
let resultsManager;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        resultsManager = new ResultsManager();
        window.resultsManager = resultsManager;
    });
} else {
    resultsManager = new ResultsManager();
    window.resultsManager = resultsManager;
}




