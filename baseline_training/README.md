# Baseline Training System

Training infrastructure for uploading and processing baseline training data for Router, Computer, and Email agents.

## Overview

The baseline training system allows you to:
- Upload training data for each agent separately (Router, Computer, Email)
- Support multiple data formats (JSON, CSV, JSONL)
- Track training progress and statistics
- Switch between training modes (training, inference, hybrid)
- Use a simple CLI-based UI for data upload

## Quick Start

### Using the CLI UI

```bash
python -m baseline_training.training_ui
```

This will launch an interactive menu where you can:
1. Upload training data
2. View training status
3. View training statistics
4. Switch agent modes
5. Clear baselines

### Using the API

```python
from baseline_training import upload_training_data, get_training_status

# Upload training data for Router agent
result = upload_training_data(
    agent_id="router",
    file_path="baseline_training/examples/router_training_data.json",
    format="json"
)

if result.success:
    print(f"Uploaded {result.records_processed} records")
    
    # Check training status
    status = get_training_status("router")
    print(f"Baseline ready: {status['baseline_ready']}")
```

## Data Formats

### Router Agent Data

```json
{
  "dest_ip": "8.8.8.8",
  "protocol": "HTTPS",
  "port": 443,
  "bytes_sent": 1024,
  "bytes_received": 2048,
  "duration_seconds": 30.5
}
```

**Required fields**: `dest_ip` or `dest_domain`, `protocol`

### Computer Agent Data

```json
{
  "process_name": "chrome.exe",
  "user": "admin",
  "file_path": "C:\\Program Files\\Chrome\\chrome.exe",
  "command_line": "chrome.exe --start-maximized",
  "pid": 1234
}
```

**Required fields**: `process_name` or `process`

### Email Agent Data

```json
{
  "sender": "noreply@company.com",
  "sender_domain": "company.com",
  "subject": "Weekly Report",
  "attachment_name": "report.pdf",
  "attachment_size": 1024000,
  "links": ["https://company.com/reports"]
}
```

**Required fields**: `sender` or `from`

## Training Modes

- **Training Mode**: Only learning, no anomaly detection
- **Inference Mode**: Only detection, no learning
- **Hybrid Mode**: Initial training complete, continuous learning enabled (default after training)

## API Reference

### `upload_training_data(agent_id, file_path, format=None)`

Upload training data from a file.

**Parameters**:
- `agent_id` (str): Agent identifier ('router', 'computer', 'email')
- `file_path` (str): Path to training data file
- `format` (str, optional): File format ('json', 'csv', 'jsonl'). Auto-detected if None.

**Returns**: `TrainingResult` object

### `get_training_status(agent_id)`

Get training status for an agent.

**Parameters**:
- `agent_id` (str): Agent identifier

**Returns**: Dictionary with status information

### `switch_agent_mode(agent_id, mode)`

Switch agent mode.

**Parameters**:
- `agent_id` (str): Agent identifier
- `mode` (str): Mode ('training', 'inference', 'hybrid')

**Returns**: bool (True if successful)

### `clear_baseline(agent_id)`

Clear baseline for an agent.

**Parameters**:
- `agent_id` (str): Agent identifier

**Returns**: bool (True if successful)

## Example Files

Example training data files are available in `baseline_training/examples/`:
- `router_training_data.json`
- `computer_training_data.json`
- `email_training_data.json`

## Testing

Run the test suite:

```bash
python baseline_training/test_training_system.py
```

This will test:
- Router agent training
- Computer agent training
- Email agent training
- Mode switching

## Integration with Agents

The training system integrates with existing agents through the `BaseAgent` class. Agents can:

1. Use pre-trained baseline learners from the training system
2. Respect training mode settings (training, inference, hybrid)
3. Switch modes dynamically

Example:

```python
from baseline_training.training_api import get_orchestrator
from agents.llm_agents.router_llm_agent import RouterLLMAgent

# Get trained baseline learner
orchestrator = get_orchestrator()
baseline_learner = orchestrator.get_baseline_learner_for_agent("router")

# Create agent with pre-trained baseline
agent = RouterLLMAgent(baseline_learner=baseline_learner)
```

## Configuration

Training parameters can be configured in `baseline_training/config.py` or by creating a custom configuration file.

Default settings:
- `min_samples`: 10 (minimum samples for baseline readiness)
- `window_size`: 1000 (sliding window size)
- `min_frequency`: 3 (minimum frequency for pattern baselines)




