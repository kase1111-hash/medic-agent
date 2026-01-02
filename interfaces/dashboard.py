"""
Medic Agent Dashboard

Provides a web-based dashboard UI for monitoring and managing the Medic Agent.

Features:
- Real-time system status
- Queue management
- Decision and outcome visualization
- Threshold monitoring
- WebSocket-powered live updates
"""

from datetime import datetime
from typing import Any, Dict, Optional

from core.logger import get_logger

logger = get_logger("interfaces.dashboard")

# Dashboard HTML template with embedded CSS and JavaScript
DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Medic Agent Dashboard</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --success: #00d9a5;
            --warning: #ffc107;
            --error: #dc3545;
            --info: #17a2b8;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        .header {
            background: var(--bg-secondary);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--bg-card);
        }

        .header h1 {
            font-size: 1.5rem;
            color: var(--accent);
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--error);
        }

        .status-dot.connected {
            background: var(--success);
        }

        .main {
            padding: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .card {
            background: var(--bg-card);
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .card-header h2 {
            font-size: 1rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .card-value {
            font-size: 2rem;
            font-weight: 700;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 0.5rem;
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .queue-list {
            max-height: 300px;
            overflow-y: auto;
        }

        .queue-item {
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
            margin-bottom: 0.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .queue-item:hover {
            background: rgba(255, 255, 255, 0.1);
        }

        .queue-module {
            font-weight: 500;
        }

        .queue-risk {
            font-size: 0.875rem;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }

        .risk-low { background: var(--success); color: #000; }
        .risk-medium { background: var(--warning); color: #000; }
        .risk-high { background: var(--error); color: #fff; }

        .event-log {
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.75rem;
        }

        .event-item {
            padding: 0.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .event-time {
            color: var(--text-secondary);
        }

        .event-type {
            color: var(--accent);
            margin-left: 0.5rem;
        }

        .chart-container {
            height: 200px;
            display: flex;
            align-items: flex-end;
            justify-content: space-around;
            gap: 4px;
            padding: 1rem 0;
        }

        .chart-bar {
            background: var(--accent);
            width: 100%;
            max-width: 30px;
            border-radius: 4px 4px 0 0;
            transition: height 0.3s ease;
        }

        .chart-bar:hover {
            opacity: 0.8;
        }

        .tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .tab {
            padding: 0.5rem 1rem;
            background: transparent;
            border: 1px solid var(--text-secondary);
            color: var(--text-secondary);
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .tab:hover, .tab.active {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.875rem;
            transition: opacity 0.2s;
        }

        .btn:hover {
            opacity: 0.8;
        }

        .btn-primary {
            background: var(--accent);
            color: #fff;
        }

        .btn-success {
            background: var(--success);
            color: #000;
        }

        .btn-danger {
            background: var(--error);
            color: #fff;
        }

        .full-width {
            grid-column: 1 / -1;
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }

        .badge-success { background: var(--success); color: #000; }
        .badge-warning { background: var(--warning); color: #000; }
        .badge-error { background: var(--error); color: #fff; }
        .badge-info { background: var(--info); color: #fff; }

        .threshold-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
            margin-bottom: 0.5rem;
        }

        .threshold-bar {
            height: 4px;
            background: var(--bg-secondary);
            border-radius: 2px;
            margin-top: 0.5rem;
            overflow: hidden;
        }

        .threshold-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s ease;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .loading {
            animation: pulse 1.5s infinite;
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>Medic Agent Dashboard</h1>
        <div class="connection-status">
            <span id="connection-text">Disconnected</span>
            <div id="status-dot" class="status-dot"></div>
        </div>
    </header>

    <main class="main">
        <!-- System Status Card -->
        <div class="card">
            <div class="card-header">
                <h2>System Status</h2>
                <span id="mode-badge" class="badge badge-info">OBSERVER</span>
            </div>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-label">Uptime</div>
                    <div id="uptime" class="stat-value">--</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Version</div>
                    <div id="version" class="stat-value">--</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">WS Clients</div>
                    <div id="ws-clients" class="stat-value">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Health</div>
                    <div id="health" class="stat-value">--</div>
                </div>
            </div>
        </div>

        <!-- Queue Stats Card -->
        <div class="card">
            <div class="card-header">
                <h2>Approval Queue</h2>
                <button class="btn btn-primary" onclick="refreshQueue()">Refresh</button>
            </div>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-label">Pending</div>
                    <div id="queue-pending" class="stat-value">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Approved</div>
                    <div id="queue-approved" class="stat-value">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Denied</div>
                    <div id="queue-denied" class="stat-value">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Total</div>
                    <div id="queue-total" class="stat-value">0</div>
                </div>
            </div>
        </div>

        <!-- Decisions Card -->
        <div class="card">
            <div class="card-header">
                <h2>Recent Decisions</h2>
            </div>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-label">Auto Approved</div>
                    <div id="decisions-auto" class="stat-value" style="color: var(--success)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Manual</div>
                    <div id="decisions-manual" class="stat-value" style="color: var(--warning)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Rejected</div>
                    <div id="decisions-rejected" class="stat-value" style="color: var(--error)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Deferred</div>
                    <div id="decisions-deferred" class="stat-value" style="color: var(--info)">0</div>
                </div>
            </div>
        </div>

        <!-- Outcomes Card -->
        <div class="card">
            <div class="card-header">
                <h2>Resurrection Outcomes</h2>
            </div>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-label">Successful</div>
                    <div id="outcomes-success" class="stat-value" style="color: var(--success)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Failed</div>
                    <div id="outcomes-failed" class="stat-value" style="color: var(--error)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Rolled Back</div>
                    <div id="outcomes-rollback" class="stat-value" style="color: var(--warning)">0</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Success Rate</div>
                    <div id="outcomes-rate" class="stat-value">--%</div>
                </div>
            </div>
        </div>

        <!-- Pending Queue List -->
        <div class="card">
            <div class="card-header">
                <h2>Pending Items</h2>
            </div>
            <div id="queue-list" class="queue-list">
                <div class="queue-item loading">Loading...</div>
            </div>
        </div>

        <!-- Thresholds Card -->
        <div class="card">
            <div class="card-header">
                <h2>Risk Thresholds</h2>
            </div>
            <div id="thresholds-list">
                <div class="threshold-item loading">Loading...</div>
            </div>
        </div>

        <!-- Event Log Card -->
        <div class="card full-width">
            <div class="card-header">
                <h2>Live Events</h2>
                <button class="btn btn-danger" onclick="clearEvents()">Clear</button>
            </div>
            <div id="event-log" class="event-log">
                <div class="event-item">Waiting for events...</div>
            </div>
        </div>
    </main>

    <script>
        // State
        let ws = null;
        let events = [];
        const maxEvents = 100;

        // DOM elements
        const statusDot = document.getElementById('status-dot');
        const connectionText = document.getElementById('connection-text');
        const eventLog = document.getElementById('event-log');

        // Format uptime
        function formatUptime(seconds) {
            if (!seconds) return '--';
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            if (hours > 0) return `${hours}h ${mins}m`;
            return `${mins}m`;
        }

        // Connect WebSocket
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws?topics=all`;

            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                statusDot.classList.add('connected');
                connectionText.textContent = 'Connected';
                addEvent('system', 'WebSocket connected');

                // Request initial status
                ws.send(JSON.stringify({ action: 'get_status' }));
            };

            ws.onclose = () => {
                statusDot.classList.remove('connected');
                connectionText.textContent = 'Disconnected';
                addEvent('system', 'WebSocket disconnected');

                // Reconnect after 3 seconds
                setTimeout(connectWebSocket, 3000);
            };

            ws.onerror = (error) => {
                addEvent('error', 'WebSocket error');
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleMessage(data);
                } catch (e) {
                    console.error('Failed to parse message:', e);
                }
            };
        }

        // Handle WebSocket messages
        function handleMessage(msg) {
            const type = msg.type;
            const data = msg.data || {};

            switch (type) {
                case 'connected':
                    addEvent('info', `Connected as ${msg.client_id}`);
                    break;

                case 'system_status':
                    updateStatus(data);
                    break;

                case 'heartbeat':
                    // Silent heartbeat
                    break;

                case 'queue_item_added':
                    addEvent('queue', `New item: ${data.item_id}`);
                    refreshQueue();
                    break;

                case 'queue_item_approved':
                    addEvent('success', `Approved: ${data.item_id}`);
                    refreshQueue();
                    break;

                case 'queue_item_denied':
                    addEvent('warning', `Denied: ${data.item_id}`);
                    refreshQueue();
                    break;

                case 'decision_made':
                    addEvent('info', `Decision: ${data.outcome} for ${data.decision_id}`);
                    break;

                case 'resurrection_started':
                    addEvent('info', `Resurrection started: ${data.request_id}`);
                    break;

                case 'resurrection_completed':
                    addEvent('success', `Resurrection completed: ${data.request_id}`);
                    break;

                case 'resurrection_failed':
                    addEvent('error', `Resurrection failed: ${data.request_id}`);
                    break;

                case 'monitor_anomaly':
                    addEvent('warning', `Anomaly detected: ${data.monitor_id}`);
                    break;

                case 'threshold_updated':
                    addEvent('info', `Threshold ${data.key}: ${data.old_value} -> ${data.new_value}`);
                    loadThresholds();
                    break;

                default:
                    addEvent('info', `${type}: ${JSON.stringify(data).slice(0, 50)}`);
            }
        }

        // Update status display
        function updateStatus(data) {
            document.getElementById('uptime').textContent = formatUptime(data.uptime_seconds);
            document.getElementById('ws-clients').textContent = data.connections || 0;

            const modeBadge = document.getElementById('mode-badge');
            modeBadge.textContent = (data.mode || 'observer').toUpperCase();

            if (data.queue) {
                document.getElementById('queue-pending').textContent = data.queue.pending || 0;
                document.getElementById('queue-approved').textContent = data.queue.approved || 0;
                document.getElementById('queue-denied').textContent = data.queue.denied || 0;
                document.getElementById('queue-total').textContent = data.queue.total || 0;
            }
        }

        // Add event to log
        function addEvent(type, message) {
            const now = new Date().toLocaleTimeString();
            events.unshift({ time: now, type, message });
            if (events.length > maxEvents) events.pop();
            renderEvents();
        }

        // Render events
        function renderEvents() {
            eventLog.innerHTML = events.map(e => `
                <div class="event-item">
                    <span class="event-time">${e.time}</span>
                    <span class="event-type">[${e.type}]</span>
                    ${e.message}
                </div>
            `).join('') || '<div class="event-item">No events</div>';
        }

        // Clear events
        function clearEvents() {
            events = [];
            renderEvents();
        }

        // Fetch API data
        async function fetchAPI(endpoint) {
            try {
                const response = await fetch(`/api/v1${endpoint}`);
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return await response.json();
            } catch (e) {
                console.error(`API error ${endpoint}:`, e);
                return null;
            }
        }

        // Refresh queue
        async function refreshQueue() {
            const data = await fetchAPI('/queue?limit=10');
            if (data && data.data) {
                const items = data.data.items || [];
                const queueList = document.getElementById('queue-list');

                if (items.length === 0) {
                    queueList.innerHTML = '<div class="queue-item">No pending items</div>';
                } else {
                    queueList.innerHTML = items.map(item => `
                        <div class="queue-item">
                            <span class="queue-module">${item.target_module || 'Unknown'}</span>
                            <span class="queue-risk risk-${(item.risk_level || 'medium').toLowerCase()}">${item.risk_level || 'N/A'}</span>
                        </div>
                    `).join('');
                }
            }
        }

        // Load thresholds
        async function loadThresholds() {
            const data = await fetchAPI('/config/thresholds');
            if (data && data.data) {
                const thresholds = data.data.thresholds || {};
                const list = document.getElementById('thresholds-list');

                const entries = Object.entries(thresholds);
                if (entries.length === 0) {
                    list.innerHTML = '<div class="threshold-item">No thresholds configured</div>';
                } else {
                    list.innerHTML = entries.map(([key, value]) => `
                        <div class="threshold-item">
                            <div>
                                <div style="font-weight: 500">${key}</div>
                                <div class="threshold-bar">
                                    <div class="threshold-fill" style="width: ${Math.min(value * 100, 100)}%"></div>
                                </div>
                            </div>
                            <span>${typeof value === 'number' ? value.toFixed(2) : value}</span>
                        </div>
                    `).join('');
                }
            }
        }

        // Load health
        async function loadHealth() {
            try {
                const response = await fetch('/health');
                if (response.ok) {
                    const data = await response.json();
                    document.getElementById('health').textContent = data.status || 'Unknown';
                    document.getElementById('version').textContent = data.version || '--';
                }
            } catch (e) {
                document.getElementById('health').textContent = 'Error';
            }
        }

        // Load outcomes stats
        async function loadOutcomes() {
            const data = await fetchAPI('/outcomes/stats');
            if (data && data.data) {
                const stats = data.data;
                document.getElementById('outcomes-success').textContent = stats.successful || 0;
                document.getElementById('outcomes-failed').textContent = stats.failed || 0;
                document.getElementById('outcomes-rollback').textContent = stats.rolled_back || 0;

                const total = (stats.successful || 0) + (stats.failed || 0);
                const rate = total > 0 ? ((stats.successful || 0) / total * 100).toFixed(0) : '--';
                document.getElementById('outcomes-rate').textContent = rate + '%';
            }
        }

        // Initialize
        function init() {
            connectWebSocket();
            loadHealth();
            refreshQueue();
            loadThresholds();
            loadOutcomes();

            // Refresh data periodically
            setInterval(loadHealth, 30000);
            setInterval(refreshQueue, 60000);
            setInterval(loadOutcomes, 60000);
        }

        // Start when DOM is ready
        document.addEventListener('DOMContentLoaded', init);
    </script>
</body>
</html>
'''


def setup_dashboard_routes(app: "FastAPI") -> None:
    """
    Add dashboard routes to a FastAPI application.

    Args:
        app: FastAPI application instance
    """
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse
    except ImportError:
        logger.warning("FastAPI not available, dashboard disabled")
        return

    @app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard():
        """
        Serve the Medic Agent dashboard.

        Returns the single-page dashboard application.
        """
        return DASHBOARD_HTML

    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def root_redirect():
        """Redirect root to dashboard."""
        return DASHBOARD_HTML

    logger.info("Dashboard routes registered at /dashboard")


def get_dashboard_html() -> str:
    """Get the dashboard HTML content."""
    return DASHBOARD_HTML
