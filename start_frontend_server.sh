#!/bin/bash
echo "Starting Frontend Server..."
echo ""
echo "Frontend will be available at: http://localhost:8000"
echo ""
cd frontend
python3 -m http.server 8000




