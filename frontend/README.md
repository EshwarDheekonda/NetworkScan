# Network Scan Frontend Application

A modern, single-page frontend application for the Network Scan AI-Powered Security Agent System.

## Features

- **Netflix-Style Landing Page**: Beautiful dark theme with smooth animations
- **Baseline Training**: Upload training data for Router, Computer, and Email agents
- **LLM Chat Interface**: Interact with AI to generate and inject attack scenarios
- **Real-Time Agent Monitoring**: Three-panel view showing live agent reactions, communications, and outputs
- **System Controls**: Start, stop, and reset system functionality
- **Test Results**: Comprehensive results display with statistics and visualization

## Getting Started

### Prerequisites

- Backend API server running on `http://localhost:5000`
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Running the Frontend

1. **Simple HTTP Server** (Python):
   ```bash
   cd frontend
   python -m http.server 8000
   ```
   Then open `http://localhost:8000` in your browser.

2. **Node.js HTTP Server**:
   ```bash
   cd frontend
   npx http-server -p 8000
   ```
   Then open `http://localhost:8000` in your browser.

3. **VS Code Live Server**:
   - Install the "Live Server" extension
   - Right-click on `index.html` and select "Open with Live Server"

## Usage

### 1. Baseline Training

1. Navigate to the "Baseline Training" section
2. For each agent (Router, Computer, Email):
   - Click or drag & drop a training data file (JSON, CSV, or JSONL)
   - Wait for training to complete
   - View training statistics

### 2. Attack Injection

1. Navigate to the "Attack Injection" section
2. Select an agent type (Router, Computer, or Email)
3. Type a description of the attack you want to test in the chat
4. Review the generated attack preview
5. Click "Execute Attack" to run the test

### 3. Agent Monitoring

- Three side-by-side windows show real-time updates for each agent
- Each window displays:
  - **Observations**: Live threat detections
  - **Communications**: Inter-agent messages
  - **Outputs**: Agent actions and reasoning
  - **Metrics**: Anomaly scores, confidence levels, observation counts

### 4. System Control

- **Start System**: Initialize the system and connect to real-time updates
- **Stop System**: Halt all operations
- **Reset System**: Clear all data and reset to initial state

### 5. Results

- Test results are automatically displayed after attack execution
- View detection statistics, attack data, and metrics
- Export results or generate comprehensive reports

## API Endpoints

The frontend communicates with the backend API at `http://localhost:5000/api`:

- Training: `/api/training/upload`, `/api/training/status/:agent_id`, `/api/training/clear/:agent_id`
- Testing: `/api/test/chat`, `/api/test/generate-attack`, `/api/test/run-test`, `/api/test/results`
- System: `/api/system/start`, `/api/system/stop`, `/api/system/reset`
- Real-time: WebSocket at `/ws/agent-updates` or SSE at `/api/events/stream`

## File Structure

```
frontend/
├── index.html              # Main HTML file
├── styles/
│   ├── main.css           # Netflix-style landing page styles
│   ├── components.css     # Component-specific styles
│   └── agent-windows.css  # Agent monitoring window styles
├── scripts/
│   ├── api.js             # API client
│   ├── websocket.js       # WebSocket/SSE client
│   ├── training.js        # Training component
│   ├── chat.js            # Chat interface
│   ├── agent-monitor.js   # Agent monitoring
│   ├── results.js         # Results display
│   └── app.js             # Main application
└── README.md              # This file
```

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Edge 90+
- Safari 14+

## Troubleshooting

### Backend Not Available
- Ensure the backend API server is running on port 5000
- Check the browser console for connection errors
- Verify CORS is enabled on the backend

### WebSocket Connection Failed
- The frontend will automatically fall back to Server-Sent Events (SSE)
- Check that the backend WebSocket/SSE endpoint is accessible
- Verify Redis message bus is running if using real-time updates

### File Upload Issues
- Ensure files are in supported formats (JSON, CSV, JSONL)
- Check file size limits
- Verify backend training API is properly configured

## Development

The frontend uses vanilla JavaScript with no build step required. To modify:

1. Edit the relevant `.js` file in `scripts/`
2. Edit the relevant `.css` file in `styles/`
3. Refresh the browser to see changes

## License

Same as the main Network Scan project.




