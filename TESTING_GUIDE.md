# Network Scan Frontend Testing Guide

This guide will help you test the complete frontend application with the backend.

## Quick Start

### Step 1: Start Backend Server

Open a terminal and run:

```bash
python start_backend_server.py
```

You should see:
```
============================================================
Network Scan Backend Server
============================================================
Initializing message bus...
Initializing agents...
Initialized 3 agents: ['router', 'computer', 'email']
...
Starting Flask API server on http://0.0.0.0:5000
```

**Note:** If you see errors about missing dependencies, install them:
```bash
pip install -r requirements.txt
```

**Note:** Redis is optional. If Redis is not running, the server will continue without real-time updates.

### Step 2: Start Frontend Server

Open a **new terminal** and run:

**Windows:**
```bash
start_frontend_server.bat
```

**Linux/Mac:**
```bash
chmod +x start_frontend_server.sh
./start_frontend_server.sh
```

**Or manually:**
```bash
cd frontend
python -m http.server 8000
```

### Step 3: Open Frontend in Browser

Navigate to: **http://localhost:8000**

You should see the Netflix-style landing page with "Network Scan" heading.

## Testing Each Feature

### 1. Baseline Training

1. Scroll to the "Baseline Training" section
2. For each agent (Router, Computer, Email):
   - Click on the upload area or drag & drop a file
   - Use the test files in `test_data/`:
     - `test_data/router_test.json` for Router agent
     - `test_data/computer_test.json` for Computer agent
     - `test_data/email_test.json` for Email agent
3. Watch for:
   - Progress bar appears
   - Status badge changes to "Training" then "Ready"
   - Training statistics appear

### 2. Attack Injection (Chat Interface)

1. Scroll to the "Attack Injection" section
2. Select an agent type from the dropdown (e.g., "Email")
3. Type a message in the chat, for example:
   - "Generate a phishing attack for email agent"
   - "Create a C2 channel attack for router"
   - "Generate a process injection attack for computer"
4. Press Enter or click Send
5. Watch for:
   - Assistant response appears
   - Attack preview panel shows attack details
   - "Execute Attack" button becomes enabled
6. Click "Execute Attack" to run the test

### 3. Agent Monitoring

1. Scroll to the "Agent Monitoring" section
2. You should see three side-by-side windows (Router, Computer, Email)
3. After executing an attack:
   - Agent status changes to "Analyzing"
   - Observations appear in the observations panel
   - Metrics update (anomaly score, confidence, observation count)
4. Check browser console (F12) for WebSocket/SSE connection status

### 4. System Controls

1. Scroll to the "System Control" section
2. Click "Start System" - status in navbar should change to "Running"
3. Click "Stop System" - status should change to "Stopped"
4. Click "Reset System" - all data should clear

### 5. Results Display

1. After executing an attack, scroll to see the "Test Results" section
2. Verify:
   - Results summary shows detection status
   - Metrics display (confidence, anomaly score, execution time)
   - Results details show attack data
3. Test buttons:
   - "Export Results" - downloads JSON file
   - "Generate Report" - creates comprehensive report

## Troubleshooting

### Backend Server Won't Start

**Error: Module not found**
```bash
pip install -r requirements.txt
```

**Error: Port 5000 already in use**
- Change port in `start_backend_server.py` (line with `port=5000`)
- Or stop the process using port 5000

**Error: Redis connection failed**
- This is OK - server will continue without real-time updates
- To enable real-time updates, start Redis:
  ```bash
  redis-server
  ```

### Frontend Won't Load

**404 errors for CSS/JS files**
- Make sure you're running the server from the project root
- Check that `frontend/` directory exists with all files

**CORS errors in browser console**
- Verify backend is running on port 5000
- Check that Flask-CORS is installed and enabled

**WebSocket connection failed**
- Check browser console for errors
- Frontend will automatically fallback to SSE
- Verify backend WebSocket endpoint is accessible

### Training Upload Fails

**Error: File format not supported**
- Ensure file is JSON, CSV, or JSONL format
- Check file structure matches expected format (see `baseline_training/README.md`)

**Error: Upload failed**
- Check backend console for error messages
- Verify file size is reasonable
- Check backend has write permissions

### Chat Interface Not Working

**No response from chat**
- Check backend is running
- Open browser console (F12) and check for API errors
- Verify `/api/test/chat` endpoint is accessible

**Attack preview not showing**
- Check that attack data was generated
- Verify agent type is selected
- Check browser console for errors

### Agent Monitoring Not Updating

**No real-time updates**
- Check WebSocket/SSE connection in browser console
- Verify Redis is running (if using message bus)
- Check backend console for message bus errors
- Try refreshing the page

## Expected Behavior

### Successful Training
- Progress bar fills to 100%
- Status badge shows "Ready"
- Training statistics display
- No error messages

### Successful Attack Execution
- Chat shows attack generation message
- Attack preview displays
- Execute button works
- Agent windows show observations
- Results section appears
- Metrics update

### Successful System Control
- Start/Stop/Reset buttons work
- System status updates in navbar
- No errors in console

## Complete Workflow Test

1. **Start both servers** (backend and frontend)
2. **Train all three agents** using test data files
3. **Start the system** using System Control
4. **Generate an attack** via chat interface
5. **Execute the attack**
6. **Observe agent monitoring** windows update
7. **View results** in results section
8. **Export results** to verify export works
9. **Reset system** to clear all data

## Next Steps

If all tests pass:
- ✅ System is ready for use
- ✅ All features are working correctly
- ✅ Frontend and backend are properly integrated

If tests fail:
- Check error messages in browser console
- Check error messages in backend console
- Refer to troubleshooting section above
- Verify all dependencies are installed

## Support

For issues or questions:
1. Check `TESTING_CHECKLIST.md` for detailed test items
2. Review error messages in browser and backend consoles
3. Verify all prerequisites are met
4. Check that all files are in correct locations




