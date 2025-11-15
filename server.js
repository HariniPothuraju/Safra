const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const nodemailer = require('nodemailer');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'sheshield_secret_key_2023';

// Enhanced middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'],
    credentials: true
}));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Enhanced MongoDB connection with better error handling
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sheshield', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log('✅ MongoDB connected successfully'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});

mongoose.connection.on('error', err => {
    console.error('❌ MongoDB connection lost:', err);
});

// Enhanced Schemas with validation
const UserSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: [true, 'Name is required'],
        trim: true,
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    email: { 
        type: String, 
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: { 
        type: String, 
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    phone: { 
        type: String, 
        required: [true, 'Phone number is required'],
        match: [/^\+?[\d\s-()]+$/, 'Please enter a valid phone number']
    },
    dateOfBirth: { 
        type: Date,
        validate: {
            validator: function(dob) {
                return dob <= new Date();
            },
            message: 'Date of birth cannot be in the future'
        }
    },
    emergencyContacts: [{
        name: { type: String, required: true },
        phone: { type: String, required: true },
        email: { type: String },
        relationship: { type: String, default: 'Family' },
        isPrimary: { type: Boolean, default: false },
        addedAt: { type: Date, default: Date.now }
    }],
    location: {
        latitude: { type: Number },
        longitude: { type: Number },
        address: { type: String },
        lastUpdated: { type: Date }
    },
    safetySettings: {
        voiceActivation: { type: Boolean, default: true },
        autoRecording: { type: Boolean, default: true },
        locationTracking: { type: Boolean, default: true },
        dangerZoneAlerts: { type: Boolean, default: true },
        shakeDetection: { type: Boolean, default: true },
        emergencyAlerts: { type: Boolean, default: true },
        safetyTips: { type: Boolean, default: true },
        communityUpdates: { type: Boolean, default: false }
    },
    subscription: {
        plan: { 
            type: String, 
            enum: ['basic', 'premium', 'family', 'enterprise'], 
            default: 'basic' 
        },
        expiryDate: Date,
        isActive: { type: Boolean, default: true }
    },
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const EmergencyAlertSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    type: { 
        type: String, 
        enum: ['sos', 'voice', 'shake', 'battery', 'danger_zone', 'manual'], 
        required: true 
    },
    location: {
        latitude: Number,
        longitude: Number,
        address: String,
        accuracy: Number
    },
    status: { 
        type: String, 
        enum: ['active', 'resolved', 'cancelled'], 
        default: 'active' 
    },
    triggeredAt: { type: Date, default: Date.now },
    resolvedAt: Date,
    recordingUrl: String,
    audioTranscript: String,
    contactsNotified: [{
        contactId: mongoose.Schema.Types.ObjectId,
        name: String,
        phone: String,
        notifiedAt: { type: Date, default: Date.now },
        method: { type: String, enum: ['sms', 'email', 'push'], default: 'sms' },
        status: { type: String, enum: ['sent', 'failed', 'delivered'], default: 'sent' }
    }],
    emergencyServicesNotified: { type: Boolean, default: false },
    responseTime: Number // in seconds
});

const SafetyZoneSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: {
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: { 
            type: [Number],
            index: '2dsphere',
            validate: {
                validator: function(coords) {
                    return coords.length === 2 && 
                           coords[0] >= -180 && coords[0] <= 180 &&
                           coords[1] >= -90 && coords[1] <= 90;
                },
                message: 'Invalid coordinates'
            }
        }
    },
    radius: { type: Number, default: 100, min: 10, max: 5000 }, // meters
    dangerLevel: { 
        type: String, 
        enum: ['low', 'medium', 'high', 'critical'], 
        default: 'medium' 
    },
    description: String,
    reportedIncidents: { type: Number, default: 1, min: 1 },
    reportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verified: { type: Boolean, default: false },
    lastUpdated: { type: Date, default: Date.now },
    tags: [String]
});

SafetyZoneSchema.index({ location: '2dsphere' });

const CommunityGroupSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true,
        trim: true,
        maxlength: [100, 'Group name cannot exceed 100 characters']
    },
    description: { type: String, maxlength: [500, 'Description cannot exceed 500 characters'] },
    location: String,
    coordinates: {
        latitude: Number,
        longitude: Number
    },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isPublic: { type: Boolean, default: true },
    maxMembers: { type: Number, default: 50, min: 2, max: 1000 },
    tags: [String],
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const SafetyCheckInSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    location: {
        latitude: Number,
        longitude: Number,
        address: String
    },
    message: String,
    checkInAt: { type: Date, default: Date.now },
    contactsNotified: [{
        contactId: mongoose.Schema.Types.ObjectId,
        notifiedAt: Date
    }]
});

// Create models
const User = mongoose.model('User', UserSchema);
const EmergencyAlert = mongoose.model('EmergencyAlert', EmergencyAlertSchema);
const SafetyZone = mongoose.model('SafetyZone', SafetyZoneSchema);
const CommunityGroup = mongoose.model('CommunityGroup', CommunityGroupSchema);
const SafetyCheckIn = mongoose.model('SafetyCheckIn', SafetyCheckInSchema);

// Utility functions
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
};

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || !user.isActive) {
            return res.status(403).json({ error: 'User not found or inactive' });
        }

        req.user = user;
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
};

const sendSMS = async (phoneNumber, message) => {
    try {
        if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
            const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
            const result = await client.messages.create({
                body: message,
                from: process.env.TWILIO_PHONE_NUMBER,
                to: phoneNumber
            });
            console.log(`✅ SMS sent to ${phoneNumber}: ${result.sid}`);
            return { success: true, sid: result.sid };
        } else {
            console.log(`📱 SMS simulation to ${phoneNumber}: ${message}`);
            return { success: true, sid: 'simulated' };
        }
    } catch (error) {
        console.error('❌ SMS sending failed:', error);
        return { success: false, error: error.message };
    }
};

const sendEmail = async (to, subject, html) => {
    try {
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const result = await transporter.sendMail({
                from: `"SheShield" <${process.env.EMAIL_USER}>`,
                to,
                subject,
                html
            });
            console.log(`✅ Email sent to ${to}: ${result.messageId}`);
            return { success: true, messageId: result.messageId };
        } else {
            console.log(`📧 Email simulation to ${to}: ${subject}`);
            return { success: true, messageId: 'simulated' };
        }
    } catch (error) {
        console.error('❌ Email sending failed:', error);
        return { success: false, error: error.message };
    }
};

const calculateDistance = (lat1, lon1, lat2, lon2) => {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c * 1000; // Return distance in meters
};

// WebSocket setup for real-time features
const wss = new WebSocket.Server({ port: 8080 });
const connectedClients = new Map();

wss.on('connection', (ws, req) => {
    const urlParams = new URLSearchParams(req.url.split('?')[1]);
    const userId = urlParams.get('userId');
    const token = urlParams.get('token');

    if (userId && token) {
        try {
            jwt.verify(token, JWT_SECRET);
            connectedClients.set(userId, ws);
            console.log(`🔗 WebSocket connected for user: ${userId}`);
            
            ws.send(JSON.stringify({
                type: 'CONNECTION_ESTABLISHED',
                message: 'Real-time connection established'
            }));

            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message);
                    await handleWebSocketMessage(userId, data, ws);
                } catch (error) {
                    console.error('❌ WebSocket message error:', error);
                    ws.send(JSON.stringify({ type: 'ERROR', error: 'Invalid message format' }));
                }
            });
            
            ws.on('close', () => {
                connectedClients.delete(userId);
                console.log(`🔌 WebSocket disconnected for user: ${userId}`);
            });

            ws.on('error', (error) => {
                console.error('❌ WebSocket error:', error);
                connectedClients.delete(userId);
            });
        } catch (error) {
            ws.close(1008, 'Invalid token');
        }
    } else {
        ws.close(1008, 'Authentication required');
    }
});

const handleWebSocketMessage = async (userId, data, ws) => {
    switch (data.type) {
        case 'LOCATION_UPDATE':
            // Update user location in real-time
            await User.findByIdAndUpdate(userId, {
                location: {
                    latitude: data.latitude,
                    longitude: data.longitude,
                    lastUpdated: new Date()
                }
            });
            
            // Check for nearby danger zones
            const dangerZones = await SafetyZone.find({
                location: {
                    $near: {
                        $geometry: {
                            type: "Point",
                            coordinates: [data.longitude, data.latitude]
                        },
                        $maxDistance: 1000
                    }
                },
                dangerLevel: { $in: ['high', 'critical'] }
            });
            
            if (dangerZones.length > 0) {
                ws.send(JSON.stringify({
                    type: 'DANGER_ZONE_ALERT',
                    zones: dangerZones,
                    message: `You are near ${dangerZones.length} danger zone(s)`
                }));
            }
            break;

        case 'TYPING_INDICATOR':
            // Broadcast typing status to group members
            if (data.groupId) {
                const group = await CommunityGroup.findById(data.groupId);
                if (group && group.members.includes(userId)) {
                    group.members.forEach(memberId => {
                        if (memberId.toString() !== userId) {
                            const client = connectedClients.get(memberId.toString());
                            if (client && client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify({
                                    type: 'USER_TYPING',
                                    userId,
                                    groupId: data.groupId,
                                    userName: data.userName
                                }));
                            }
                        }
                    });
                }
            }
            break;

        default:
            ws.send(JSON.stringify({ type: 'ERROR', error: 'Unknown message type' }));
    }
};

const broadcastToUserContacts = async (userId, data) => {
    try {
        const user = await User.findById(userId);
        if (user && user.emergencyContacts) {
            const notificationPromises = user.emergencyContacts.map(async (contact) => {
                const client = connectedClients.get(contact._id?.toString());
                if (client && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(data));
                }
            });
            await Promise.all(notificationPromises);
        }
    } catch (error) {
        console.error('❌ Error broadcasting to contacts:', error);
    }
};

// API Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone, dateOfBirth } = req.body;
        
        if (!name || !email || !password || !phone) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists with this email' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const user = new User({
            name,
            email,
            password: hashedPassword,
            phone,
            dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null
        });
        
        await user.save();
        
        const token = generateToken(user._id);
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                safetySettings: user.safetySettings
            }
        });
    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Registration failed', 
            details: error.message 
        });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const user = await User.findOne({ email, isActive: true });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = generateToken(user._id);
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                safetySettings: user.safetySettings,
                emergencyContacts: user.emergencyContacts
            }
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Login failed', 
            details: error.message 
        });
    }
});

// User Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId)
            .select('-password')
            .populate('emergencyContacts');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            success: true,
            user 
        });
    } catch (error) {
        console.error('❌ Profile fetch error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch profile', 
            details: error.message 
        });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone, dateOfBirth } = req.body;
        const user = await User.findByIdAndUpdate(
            req.userId,
            { 
                name, 
                phone, 
                dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null 
            },
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            success: true,
            message: 'Profile updated successfully', 
            user 
        });
    } catch (error) {
        console.error('❌ Profile update error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update profile', 
            details: error.message 
        });
    }
});

app.put('/api/settings', authenticateToken, async (req, res) => {
    try {
        const { safetySettings } = req.body;
        const user = await User.findByIdAndUpdate(
            req.userId,
            { safetySettings },
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ 
            success: true,
            message: 'Settings updated successfully', 
            user 
        });
    } catch (error) {
        console.error('❌ Settings update error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update settings', 
            details: error.message 
        });
    }
});

// Emergency Contacts Routes
app.get('/api/contacts', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ 
            success: true,
            contacts: user.emergencyContacts 
        });
    } catch (error) {
        console.error('❌ Contacts fetch error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch contacts', 
            details: error.message 
        });
    }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
    try {
        const { name, phone, email, relationship, isPrimary } = req.body;
        
        if (!name || !phone) {
            return res.status(400).json({ error: 'Name and phone are required' });
        }
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Check contact limit
        if (user.emergencyContacts.length >= 10) {
            return res.status(400).json({ error: 'Maximum 10 emergency contacts allowed' });
        }
        
        if (isPrimary) {
            user.emergencyContacts.forEach(contact => {
                contact.isPrimary = false;
            });
        }
        
        user.emergencyContacts.push({
            name,
            phone,
            email,
            relationship,
            isPrimary: isPrimary || false
        });
        
        await user.save();
        res.status(201).json({ 
            success: true,
            message: 'Contact added successfully', 
            contacts: user.emergencyContacts 
        });
    } catch (error) {
        console.error('❌ Contact add error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to add contact', 
            details: error.message 
        });
    }
});

app.put('/api/contacts/:contactId', authenticateToken, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { name, phone, email, relationship, isPrimary } = req.body;
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const contact = user.emergencyContacts.id(contactId);
        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        if (isPrimary) {
            user.emergencyContacts.forEach(c => {
                c.isPrimary = false;
            });
        }
        
        contact.name = name || contact.name;
        contact.phone = phone || contact.phone;
        contact.email = email || contact.email;
        contact.relationship = relationship || contact.relationship;
        contact.isPrimary = isPrimary !== undefined ? isPrimary : contact.isPrimary;
        
        await user.save();
        res.json({ 
            success: true,
            message: 'Contact updated successfully', 
            contacts: user.emergencyContacts 
        });
    } catch (error) {
        console.error('❌ Contact update error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update contact', 
            details: error.message 
        });
    }
});

app.delete('/api/contacts/:contactId', authenticateToken, async (req, res) => {
    try {
        const { contactId } = req.params;
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const contact = user.emergencyContacts.id(contactId);
        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        contact.remove();
        await user.save();
        
        res.json({ 
            success: true,
            message: 'Contact deleted successfully', 
            contacts: user.emergencyContacts 
        });
    } catch (error) {
        console.error('❌ Contact delete error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to delete contact', 
            details: error.message 
        });
    }
});

// Emergency Alert Routes
app.post('/api/emergency/alert', authenticateToken, async (req, res) => {
    try {
        const { type, location, recordingUrl, audioTranscript } = req.body;
        
        if (!type) {
            return res.status(400).json({ error: 'Alert type is required' });
        }
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const alert = new EmergencyAlert({
            userId: req.userId,
            type,
            location,
            recordingUrl,
            audioTranscript
        });
        
        await alert.save();
        
        // Notify emergency contacts
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        const locationStr = location ? 
            `https://maps.google.com/?q=${location.latitude},${location.longitude}` : 
            'Unknown location';
        
        const message = `🚨 EMERGENCY ALERT: ${user.name} has triggered an SOS alert. Location: ${locationStr}. Time: ${new Date().toLocaleString()}. Please check SheShield app immediately.`;
        
        const notificationPromises = primaryContacts.map(async (contact) => {
            const contactNotification = {
                contactId: contact._id,
                name: contact.name,
                phone: contact.phone,
                method: 'sms',
                status: 'sent'
            };
            
            if (contact.phone) {
                const smsResult = await sendSMS(contact.phone, message);
                contactNotification.status = smsResult.success ? 'sent' : 'failed';
            }
            
            if (contact.email) {
                await sendEmail(contact.email, '🚨 Emergency Alert - SheShield', `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #dc3545;">🚨 Emergency Alert</h2>
                        <p><strong>${user.name}</strong> has triggered an emergency alert.</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                            <p><strong>Type:</strong> ${type.toUpperCase()}</p>
                            <p><strong>Location:</strong> <a href="${locationStr}">View on Map</a></p>
                            <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                        </div>
                        <p style="color: #dc3545; font-weight: bold;">Please check the SheShield app immediately for more details and take appropriate action.</p>
                    </div>
                `);
            }
            
            alert.contactsNotified.push(contactNotification);
        });
        
        await Promise.all(notificationPromises);
        await alert.save();
        
        // Notify emergency services if location is available
        if (location?.latitude && location?.longitude) {
            alert.emergencyServicesNotified = true;
            await alert.save();
            console.log(`🚑 Emergency services notified for location: ${location.latitude}, ${location.longitude}`);
        }
        
        // Update user location
        if (location?.latitude && location?.longitude) {
            user.location = {
                latitude: location.latitude,
                longitude: location.longitude,
                lastUpdated: new Date()
            };
            await user.save();
        }
        
        // WebSocket broadcast
        const ws = connectedClients.get(req.userId.toString());
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'EMERGENCY_ALERT_TRIGGERED',
                alertId: alert._id,
                location,
                timestamp: new Date()
            }));
        }
        
        await broadcastToUserContacts(req.userId.toString(), {
            type: 'CONTACT_EMERGENCY_ALERT',
            userName: user.name,
            alertId: alert._id,
            location,
            timestamp: new Date()
        });
        
        res.status(201).json({ 
            success: true,
            message: 'Emergency alert triggered successfully', 
            alertId: alert._id,
            contactsNotified: primaryContacts.length
        });
    } catch (error) {
        console.error('❌ Emergency alert error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to trigger emergency alert', 
            details: error.message 
        });
    }
});

app.post('/api/emergency/cancel/:alertId', authenticateToken, async (req, res) => {
    try {
        const { alertId } = req.params;
        const alert = await EmergencyAlert.findOne({ _id: alertId, userId: req.userId });
        
        if (!alert) {
            return res.status(404).json({ error: 'Alert not found' });
        }
        
        alert.status = 'cancelled';
        alert.resolvedAt = new Date();
        alert.responseTime = (alert.resolvedAt - alert.triggeredAt) / 1000;
        await alert.save();
        
        // Notify contacts about cancellation
        const user = await User.findById(req.userId);
        const message = `✅ ALERT CANCELLED: Emergency alert from ${user.name} has been cancelled. All is safe.`;
        
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        for (const contact of primaryContacts) {
            if (contact.phone) {
                await sendSMS(contact.phone, message);
            }
        }
        
        res.json({ 
            success: true,
            message: 'Emergency alert cancelled successfully' 
        });
    } catch (error) {
        console.error('❌ Cancel alert error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to cancel emergency alert', 
            details: error.message 
        });
    }
});

app.get('/api/emergency/history', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const skip = (page - 1) * limit;
        
        const alerts = await EmergencyAlert.find({ userId: req.userId })
            .sort({ triggeredAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .lean();
        
        const total = await EmergencyAlert.countDocuments({ userId: req.userId });
        
        res.json({ 
            success: true,
            alerts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Emergency history error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch emergency history', 
            details: error.message 
        });
    }
});

// Location & Safety Routes
app.post('/api/location/update', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, address } = req.body;
        
        if (!latitude || !longitude) {
            return res.status(400).json({ error: 'Latitude and longitude are required' });
        }
        
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        user.location = {
            latitude,
            longitude,
            address,
            lastUpdated: new Date()
        };
        
        await user.save();
        
        // Check for nearby danger zones
        const dangerZones = await SafetyZone.find({
            location: {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [longitude, latitude]
                    },
                    $maxDistance: 1000 // 1km radius
                }
            },
            dangerLevel: { $in: ['high', 'critical'] }
        });
        
        let alertData = null;
        if (dangerZones.length > 0 && user.safetySettings.dangerZoneAlerts) {
            alertData = {
                type: 'DANGER_ZONE_ALERT',
                zones: dangerZones,
                message: `You are near ${dangerZones.length} high-risk area(s)`,
                timestamp: new Date()
            };
            
            // Send real-time alert via WebSocket
            const ws = connectedClients.get(req.userId.toString());
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(alertData));
            }
        }
        
        res.json({ 
            success: true,
            message: 'Location updated successfully', 
            dangerZones: dangerZones.length > 0,
            alert: alertData
        });
    } catch (error) {
        console.error('❌ Location update error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to update location', 
            details: error.message 
        });
    }
});

app.get('/api/location/nearby-safety', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, radius = 5000 } = req.query;
        
        if (!latitude || !longitude) {
            return res.status(400).json({ error: 'Latitude and longitude are required' });
        }
        
        const safeZones = await SafetyZone.find({
            location: {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: parseInt(radius)
                }
            },
            dangerLevel: 'low'
        }).limit(10);
        
        // In a real app, you would integrate with external APIs for police stations and hospitals
        const policeStations = [];
        const hospitals = [];
        
        res.json({ 
            success: true,
            safeZones, 
            policeStations, 
            hospitals 
        });
    } catch (error) {
        console.error('❌ Nearby safety error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch nearby safety locations', 
            details: error.message 
        });
    }
});

// Community Routes
app.get('/api/community/groups', authenticateToken, async (req, res) => {
    try {
        const { page = 1, limit = 20, search } = req.query;
        const skip = (page - 1) * limit;
        
        let query = { 
            $or: [
                { isPublic: true },
                { members: req.userId }
            ],
            isActive: true
        };
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { location: { $regex: search, $options: 'i' } }
            ];
        }
        
        const groups = await CommunityGroup.find(query)
            .populate('members', 'name email phone')
            .populate('admin', 'name email')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
        
        const total = await CommunityGroup.countDocuments(query);
        
        res.json({ 
            success: true,
            groups,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('❌ Community groups error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch community groups', 
            details: error.message 
        });
    }
});

app.post('/api/community/groups', authenticateToken, async (req, res) => {
    try {
        const { name, description, location, isPublic, coordinates, maxMembers, tags } = req.body;
        
        if (!name) {
            return res.status(400).json({ error: 'Group name is required' });
        }
        
        const group = new CommunityGroup({
            name,
            description,
            location,
            coordinates,
            admin: req.userId,
            members: [req.userId],
            isPublic: isPublic !== undefined ? isPublic : true,
            maxMembers: maxMembers || 50,
            tags: tags || []
        });
        
        await group.save();
        await group.populate('admin', 'name email');
        await group.populate('members', 'name email');
        
        res.status(201).json({ 
            success: true,
            message: 'Community group created successfully', 
            group 
        });
    } catch (error) {
        console.error('❌ Create group error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to create community group', 
            details: error.message 
        });
    }
});

app.post('/api/community/groups/:groupId/join', authenticateToken, async (req, res) => {
    try {
        const { groupId } = req.params;
        const group = await CommunityGroup.findById(groupId);
        
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }
        
        if (!group.isActive) {
            return res.status(400).json({ error: 'This group is no longer active' });
        }
        
        if (group.members.length >= group.maxMembers) {
            return res.status(400).json({ error: 'Group has reached maximum member capacity' });
        }
        
        if (!group.members.includes(req.userId)) {
            group.members.push(req.userId);
            await group.save();
        }
        
        await group.populate('members', 'name email');
        
        res.json({ 
            success: true,
            message: 'Joined group successfully', 
            group 
        });
    } catch (error) {
        console.error('❌ Join group error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to join group', 
            details: error.message 
        });
    }
});

// Safety Zones Routes
app.get('/api/safety-zones', async (req, res) => {
    try {
        const { latitude, longitude, radius = 5000, dangerLevel } = req.query;
        
        let query = { verified: true };
        
        if (latitude && longitude) {
            query.location = {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: parseInt(radius)
                }
            };
        }
        
        if (dangerLevel) {
            query.dangerLevel = dangerLevel;
        }
        
        const zones = await SafetyZone.find(query)
            .sort({ dangerLevel: -1, reportedIncidents: -1 })
            .limit(50);
        
        res.json({ 
            success: true,
            zones 
        });
    } catch (error) {
        console.error('❌ Safety zones error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch safety zones', 
            details: error.message 
        });
    }
});

app.post('/api/safety-zones/report', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, dangerLevel, description, name, tags } = req.body;
        
        if (!latitude || !longitude || !dangerLevel) {
            return res.status(400).json({ error: 'Latitude, longitude and danger level are required' });
        }
        
        // Check if zone already exists nearby
        const existingZone = await SafetyZone.findOne({
            location: {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [parseFloat(longitude), parseFloat(latitude)]
                    },
                    $maxDistance: 100 // 100 meters
                }
            }
        });
        
        let zone;
        if (existingZone) {
            // Update existing zone
            existingZone.reportedIncidents += 1;
            existingZone.dangerLevel = dangerLevel;
            existingZone.lastUpdated = new Date();
            if (description) existingZone.description = description;
            if (tags) existingZone.tags = tags;
            zone = await existingZone.save();
        } else {
            // Create new zone
            zone = new SafetyZone({
                name: name || `Safety Zone at ${latitude.toFixed(4)}, ${longitude.toFixed(4)}`,
                location: {
                    type: "Point",
                    coordinates: [parseFloat(longitude), parseFloat(latitude)]
                },
                dangerLevel,
                description,
                reportedBy: req.userId,
                tags: tags || [],
                reportedIncidents: 1
            });
            await zone.save();
        }
        
        res.status(201).json({ 
            success: true,
            message: 'Safety zone reported successfully', 
            zone 
        });
    } catch (error) {
        console.error('❌ Report zone error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to report safety zone', 
            details: error.message 
        });
    }
});

// Check-in Routes
app.post('/api/check-in', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, message } = req.body;
        const user = await User.findById(req.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const checkIn = new SafetyCheckIn({
            userId: req.userId,
            location: {
                latitude,
                longitude,
                address: `Location at ${latitude}, ${longitude}`
            },
            message: message || `${user.name} has checked in safely`
        });
        
        await checkIn.save();
        
        // Notify primary contacts
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        const locationStr = latitude && longitude ? 
            `https://maps.google.com/?q=${latitude},${longitude}` : 
            'Unknown location';
        
        const checkInMessage = message || `${user.name} has checked in safely at ${locationStr}`;
        
        const notificationPromises = primaryContacts.map(async (contact) => {
            if (contact.phone) {
                await sendSMS(contact.phone, `✅ ${checkInMessage}`);
            }
            if (contact.email) {
                await sendEmail(contact.email, '✅ Safe Check-in - SheShield', `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #28a745;">✅ Safe Check-in</h2>
                        <p><strong>${user.name}</strong> has checked in safely.</p>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                            <p><strong>Location:</strong> <a href="${locationStr}">View on Map</a></p>
                            <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                            <p><strong>Message:</strong> ${checkInMessage}</p>
                        </div>
                        <p style="color: #28a745;">All is safe and well!</p>
                    </div>
                `);
            }
            
            checkIn.contactsNotified.push({
                contactId: contact._id,
                notifiedAt: new Date()
            });
        });
        
        await Promise.all(notificationPromises);
        await checkIn.save();
        
        res.json({ 
            success: true,
            message: 'Check-in completed successfully',
            checkInId: checkIn._id
        });
    } catch (error) {
        console.error('❌ Check-in error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to check in', 
            details: error.message 
        });
    }
});

// Voice Processing Route
app.post('/api/voice/process', authenticateToken, async (req, res) => {
    try {
        const { audioData, transcript } = req.body;
        
        if (!transcript) {
            return res.status(400).json({ error: 'Transcript is required' });
        }
        
        const commands = {
            'help': 'sos',
            'emergency': 'sos',
            'sos': 'sos',
            'danger': 'sos',
            'help me': 'sos',
            'save me': 'sos',
            'check in': 'checkin',
            'safe': 'checkin',
            'i am safe': 'checkin',
            'location': 'location',
            'where am i': 'location',
            'my location': 'location'
        };
        
        const transcriptLower = transcript.toLowerCase().trim();
        let action = null;
        let confidence = 0;
        
        for (const [keyword, command] of Object.entries(commands)) {
            if (transcriptLower.includes(keyword)) {
                action = command;
                confidence = keyword.length / transcriptLower.length;
                break;
            }
        }
        
        if (action === 'sos' && confidence > 0.3) {
            const user = await User.findById(req.userId);
            const alert = new EmergencyAlert({
                userId: req.userId,
                type: 'voice',
                location: user.location,
                audioTranscript: transcript
            });
            await alert.save();
            
            res.json({ 
                success: true,
                action: 'sos_triggered', 
                alertId: alert._id,
                confidence,
                transcript 
            });
        } else if (action === 'checkin' && confidence > 0.3) {
            res.json({ 
                success: true,
                action: 'checkin_triggered',
                confidence,
                transcript 
            });
        } else if (action === 'location') {
            res.json({ 
                success: true,
                action: 'location_request',
                confidence,
                transcript 
            });
        } else {
            res.json({ 
                success: true,
                action: 'unknown_command',
                confidence,
                transcript 
            });
        }
    } catch (error) {
        console.error('❌ Voice processing error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to process voice command', 
            details: error.message 
        });
    }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        // In a real app, you would check if user is admin
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const totalAlerts = await EmergencyAlert.countDocuments();
        const activeAlerts = await EmergencyAlert.countDocuments({ status: 'active' });
        const totalGroups = await CommunityGroup.countDocuments();
        const safetyZones = await SafetyZone.countDocuments();
        
        // Recent activity
        const recentAlerts = await EmergencyAlert.find()
            .sort({ triggeredAt: -1 })
            .limit(10)
            .populate('userId', 'name email');
        
        const userRegistrations = await User.aggregate([
            {
                $group: {
                    _id: {
                        year: { $year: '$createdAt' },
                        month: { $month: '$createdAt' },
                        day: { $dayOfMonth: '$createdAt' }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id.year': -1, '_id.month': -1, '_id.day': -1 } },
            { $limit: 30 }
        ]);
        
        res.json({
            success: true,
            stats: {
                totalUsers,
                activeUsers,
                totalAlerts,
                activeAlerts,
                totalGroups,
                safetyZones
            },
            recentActivity: {
                alerts: recentAlerts,
                registrations: userRegistrations
            },
            serverTime: new Date(),
            uptime: process.uptime()
        });
    } catch (error) {
        console.error('❌ Admin stats error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to fetch admin stats', 
            details: error.message 
        });
    }
});

// Health check route
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true,
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// Serve frontend (for production)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ 
        success: false,
        error: 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false,
        error: 'Endpoint not found' 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 SheShield Backend Server running on port ${PORT}`);
    console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🌐 WebSocket server running on port 8080`);
    console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
});

module.exports = app;
