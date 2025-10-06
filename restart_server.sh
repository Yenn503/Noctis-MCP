#!/bin/bash
# Restart Noctis-MCP Server with Education System

echo "🔄 Restarting Noctis-MCP Server..."

# Kill existing server
echo "   Stopping old server..."
pkill -f "python.*noctis_server.py" || echo "   No server running"
sleep 1

# Start new server
echo "   Starting server with education system..."
python3 server/noctis_server.py --port 8888 &

# Wait for server to start
sleep 3

# Test health endpoint
echo "   Testing server health..."
curl -s http://localhost:8888/health | python3 -m json.tool | head -10

echo ""
echo "   Testing education endpoints..."
curl -s http://localhost:8888/api/v2/education/stats 2>&1 | python3 -m json.tool | head -10

echo ""
echo "✅ Server restarted! Check above for any errors."
echo "📚 Education system should now be available at /api/v2/education/*"
