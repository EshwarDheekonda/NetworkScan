# System Testing Checklist

## Prerequisites
- [ ] Python environment with all dependencies installed
- [ ] Redis server running (optional, for real-time updates)
- [ ] Backend server started on port 5000
- [ ] Frontend server started on port 8000

## Phase 1: Backend Server Setup
- [ ] Backend server starts without errors
- [ ] Health endpoint responds: `http://localhost:5000/health`
- [ ] API status endpoint works: `http://localhost:5000/api/test/status`

## Phase 2: Frontend Server Setup
- [ ] Frontend loads at `http://localhost:8000`
- [ ] No JavaScript errors in browser console
- [ ] Netflix-style landing page displays correctly
- [ ] All sections are visible (Training, Chat, Monitoring, Controls, Results)

## Phase 3: Baseline Training Testing

### Router Agent
- [ ] Upload `test_data/router_test.json`
- [ ] Progress bar displays during upload
- [ ] Training completes successfully
- [ ] Status badge shows "Ready"
- [ ] Training statistics display correctly

### Computer Agent
- [ ] Upload `test_data/computer_test.json`
- [ ] Progress bar displays during upload
- [ ] Training completes successfully
- [ ] Status badge shows "Ready"
- [ ] Training statistics display correctly

### Email Agent
- [ ] Upload `test_data/email_test.json`
- [ ] Progress bar displays during upload
- [ ] Training completes successfully
- [ ] Status badge shows "Ready"
- [ ] Training statistics display correctly

## Phase 4: Chat Interface Testing
- [ ] Chat input field is functional
- [ ] Send button works
- [ ] Messages appear in chat window
- [ ] Test message: "Generate a phishing attack for email agent"
- [ ] Attack preview displays
- [ ] Attack data is shown correctly
- [ ] Execute Attack button is enabled

## Phase 5: Agent Monitoring Testing
- [ ] Three agent windows display (Router, Computer, Email)
- [ ] Agent status indicators show "Idle"
- [ ] WebSocket/SSE connection establishes (check browser console)
- [ ] After attack execution, observations appear in agent windows
- [ ] Metrics update (anomaly score, confidence, observation count)
- [ ] Agent status changes to "Analyzing" during processing

## Phase 6: System Controls Testing
- [ ] Start System button works
- [ ] System status in navbar updates to "Running"
- [ ] Stop System button works
- [ ] System status updates to "Stopped"
- [ ] Reset System button works
- [ ] All data clears after reset

## Phase 7: Results Display Testing
- [ ] Results section appears after attack execution
- [ ] Results summary displays correctly
- [ ] Detection status shows (Detected/Not Detected)
- [ ] Metrics display (confidence, anomaly score, execution time)
- [ ] Results details show attack data
- [ ] Export Results button works (downloads JSON)
- [ ] Generate Report button works

## Phase 8: End-to-End Workflow
- [ ] Complete workflow:
  1. Upload training data for all three agents
  2. Start system
  3. Generate attack via chat
  4. Execute attack
  5. View agent monitoring updates
  6. View results
  7. Export results
- [ ] Multiple attacks can be executed in sequence
- [ ] Data persists between attacks
- [ ] Error handling works (try disconnecting backend)

## Known Issues to Watch For
- CORS errors (should be handled by Flask-CORS)
- WebSocket connection failures (should fallback to SSE)
- File upload errors (check file format and size)
- Real-time updates not working (check Redis connection)
- API endpoint 404 errors (verify all routes are registered)

## Success Criteria
✅ All frontend components load without errors
✅ Training upload works for all three agents
✅ Chat interface generates attacks correctly
✅ Real-time agent monitoring displays updates
✅ System controls function properly
✅ Results display correctly
✅ Complete end-to-end workflow succeeds




