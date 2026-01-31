require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "somatic-secure-key-2026-v1";

// Security Middleware
app.use(helmet());
app.use(cors()); // Allow CORS for dashboard
app.use(bodyParser.json());
app.use(bodyParser.text());
app.use(express.static('public'));

// Rate Limiter for API endpoints
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // Limit each IP to 60 requests per windowMs
    message: "Too many requests from this IP, please try again later."
});

// Auth Middleware
const authenticate = (req, res, next) => {
    const apiKey = req.get('x-api-key');
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or missing API Key' });
    }
    next();
};

// Store status in memory (resets on restart, but that's fine for a live dashboard)
let currentStatus = {
    online: false,
    lastUpdate: 0,
    data: {},
    sessionStart: Date.now()
};

// Store event logs (keep last 20 events for performance)
let eventLogs = [];
const MAX_LOGS = 20;

// Track refresh history for health metrics
let lastRefreshTime = null;

// Server lifetime tracking
const serverStartTime = Date.now();

// RECEIVE HEARTBEAT (Protected, Rate Limited)
app.post('/update', apiLimiter, authenticate, (req, res) => {
    const data = req.body;

    // Basic Input Validation
    if (!data || typeof data !== 'object') {
        return res.status(400).json({ error: 'Invalid data format' });
    }

    // Support both old simple heartbeat and new ServerPayload
    const eventType = data.event?.type || data.type;

    if (!eventType) {
        return res.status(400).json({ error: 'Invalid update type' });
    }

    // console.log("Received update:", JSON.stringify(data, null, 2));

    // Update Current Status
    currentStatus = {
        ...currentStatus,
        online: true,
        lastUpdate: Date.now(),
        data: data // Save the full payload
    };

    // If this is a significant event (not just heartbeat), log it properly
    if (eventType !== 'heartbeat' && eventType !== 'launcher_online') {
        const timestamp = new Date().toISOString();
        const msg = `[${eventType.toUpperCase()}] ${data.game?.exeName || 'Unknown Game'} - Reason: ${data.event?.reason || 'Unknown'}`;

        const logEntry = {
            timestamp,
            message: msg,
            time: new Date().toLocaleTimeString()
        };

        eventLogs.unshift(logEntry);
        if (eventLogs.length > MAX_LOGS) eventLogs = eventLogs.slice(0, MAX_LOGS);

        console.log("Logged significant event:", msg);
    }

    res.json({ success: true });
});

// RECEIVE EVENT LOG (Protected, Rate Limited)
app.post('/log', apiLimiter, authenticate, (req, res) => {
    let message = "";

    if (typeof req.body === 'string') {
        message = req.body;
    } else if (req.body && typeof req.body.message === 'string') {
        message = req.body.message;
    } else {
        return res.status(400).json({ error: 'Invalid log format' });
    }

    // Sanitize message strictly if needed, but for logs simple text is ok
    if (message.length > 1000) message = message.substring(0, 1000); // Truncate long logs

    const timestamp = new Date().toISOString();

    const logEntry = {
        timestamp,
        message,
        time: new Date().toLocaleTimeString()
    };

    console.log("Event log:", logEntry);

    // Track refresh events for health metrics
    if (message.includes('refreshed') || message.includes('Detected refresh')) {
        lastRefreshTime = Date.now();
    }

    eventLogs.unshift(logEntry); // Add to beginning
    if (eventLogs.length > MAX_LOGS) {
        eventLogs = eventLogs.slice(0, MAX_LOGS);
    }

    res.json({ success: true });
});

// GET LOGS (Public for Dashboard)
app.get('/logs', (req, res) => {
    res.json({ logs: eventLogs });
});

// GET STATUS (Public for Dashboard)
app.get('/status', (req, res) => {
    // Check timeout (if no heartbeat for 60 seconds, mark as offline)
    const timeSinceLast = Date.now() - currentStatus.lastUpdate;
    if (timeSinceLast > 60000 && currentStatus.online) {
        currentStatus.online = false;
        currentStatus.data.status = "Timeout (Offline)";
    }

    // Calculate session uptime
    const sessionUptimeSeconds = Math.floor((Date.now() - currentStatus.sessionStart) / 1000);

    // Calculate server lifetime
    const serverLifetimeSeconds = Math.floor((Date.now() - serverStartTime) / 1000);

    // Calculate time since last refresh
    const timeSinceRefresh = lastRefreshTime ? Math.floor((Date.now() - lastRefreshTime) / 1000) : null;

    // Determine health status based on recent refreshes
    const refreshes = currentStatus.data.crashes_120s || 0;
    let health = 'excellent';
    if (refreshes >= 4) health = 'critical';
    else if (refreshes >= 2) health = 'warning';
    else if (refreshes >= 1) health = 'good';

    res.json({
        ...currentStatus,
        sessionUptimeSeconds,
        serverLifetimeSeconds,
        timeSinceRefresh,
        health,
        lastUpdateTimestamp: currentStatus.lastUpdate
    });
});

// Serve Dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Somatic Status Server running on port ${PORT}`);
    console.log(`Security: API Key Auth Enabled`);
});
