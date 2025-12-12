/**
 * Test Manager Component
 * Handles automatic attack test generation and display
 */

class TestManager {
    constructor() {
        this.currentAttack = null;
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        const runTestBtn = document.getElementById('runAttackTestBtn');
        if (runTestBtn) {
            runTestBtn.addEventListener('click', () => this.runAutoTest());
        }
    }

    async runAutoTest() {
        const runTestBtn = document.getElementById('runAttackTestBtn');
        const attackInfo = document.getElementById('attackInfo');
        
        // Disable button and show loading
        if (runTestBtn) {
            runTestBtn.disabled = true;
            runTestBtn.innerHTML = '<span>Generating Attack...</span>';
        }

        try {
            // Call auto-test API
            const response = await apiClient.autoTest();
            
            if (response.success && response.attack_info) {
                this.currentAttack = response.attack_info;
                this.displayAttackInfo(response.attack_info);
            } else {
                this.showError(response.error || 'Failed to generate attack');
            }
        } catch (error) {
            console.error('Error running auto-test:', error);
            this.showError(error.message || 'Failed to run test');
        } finally {
            // Re-enable button
            if (runTestBtn) {
                runTestBtn.disabled = false;
                runTestBtn.innerHTML = '<span>Run Attack Test</span>';
            }
        }
    }

    displayAttackInfo(attackInfo) {
        const attackInfoDiv = document.getElementById('attackInfo');
        const agentTypeEl = document.getElementById('attackAgentType');
        const attackTypeEl = document.getElementById('attackType');
        const attackDescriptionEl = document.getElementById('attackDescription');
        const techniqueItem = document.getElementById('techniqueItem');
        const attackTechniqueEl = document.getElementById('attackTechnique');

        if (attackInfoDiv) {
            attackInfoDiv.style.display = 'block';
        }

        if (agentTypeEl) {
            agentTypeEl.textContent = attackInfo.agent_type.charAt(0).toUpperCase() + attackInfo.agent_type.slice(1);
        }

        if (attackTypeEl) {
            // Format attack type (replace underscores with spaces, capitalize)
            const formattedType = attackInfo.attack_type
                .split('_')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
            attackTypeEl.textContent = formattedType;
        }

        if (attackDescriptionEl) {
            attackDescriptionEl.textContent = attackInfo.description || 'No description available';
        }

        if (attackInfo.technique_name) {
            if (techniqueItem) {
                techniqueItem.style.display = 'block';
            }
            if (attackTechniqueEl) {
                attackTechniqueEl.textContent = attackInfo.technique_name;
            }
        } else {
            if (techniqueItem) {
                techniqueItem.style.display = 'none';
            }
        }
    }

    showError(message) {
        const attackInfoDiv = document.getElementById('attackInfo');
        if (attackInfoDiv) {
            attackInfoDiv.style.display = 'block';
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-message';
            errorDiv.textContent = `Error: ${message}`;
            attackInfoDiv.innerHTML = '';
            attackInfoDiv.appendChild(errorDiv);
        }
    }

    clearAttackInfo() {
        const attackInfoDiv = document.getElementById('attackInfo');
        if (attackInfoDiv) {
            attackInfoDiv.style.display = 'none';
        }
        this.currentAttack = null;
    }
}

// Initialize test manager when DOM is ready
let testManager;
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        testManager = new TestManager();
        window.testManager = testManager;
    });
} else {
    testManager = new TestManager();
    window.testManager = testManager;
}

