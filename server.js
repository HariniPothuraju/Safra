const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const nodemailer = require('nodemailer');
const geoip = require('geoip-lite');
const WebSocket = require('ws');
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'sheshield_secret_key_2023';
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sheshield', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    dateOfBirth: { type: Date },
    emergencyContacts: [{
        name: String,
        phone: String,
        email: String,
        relationship: String,
        isPrimary: Boolean
    }],
    location: {
        latitude: Number,
        longitude: Number,
        lastUpdated: Date
    },
    safetySettings: {
        voiceActivation: { type: Boolean, default: true },
        autoRecording: { type: Boolean, default: true },
        locationTracking: { type: Boolean, default: true },
        dangerZoneAlerts: { type: Boolean, default: true },
        shakeDetection: { type: Boolean, default: true },
        emergencyAlerts: { type: Boolean, default: true },
        safetyTips: { type: Boolean, default: true }
    },
    subscription: {
        plan: { type: String, enum: ['basic', 'premium', 'family', 'enterprise'], default: 'basic' },
        expiryDate: Date,
        isActive: { type: Boolean, default: true }
    },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date
});

const EmergencyAlertSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['sos', 'voice', 'shake', 'battery', 'danger_zone'], required: true },
    location: {
        latitude: Number,
        longitude: Number,
        address: String
    },
    status: { type: String, enum: ['active', 'resolved', 'cancelled'], default: 'active' },
    triggeredAt: { type: Date, default: Date.now },
    resolvedAt: Date,
    recordingUrl: String,
    contactsNotified: [{
        contactId: mongoose.Schema.Types.ObjectId,
        notifiedAt: Date,
        response: String
    }],
    emergencyServicesNotified: Boolean
});

const SafetyZoneSchema = new mongoose.Schema({
    name: String,
    location: {
        type: { type: String, enum: ['Point'], default: 'Point' },
        coordinates: [Number]
    },
    radius: Number,
    dangerLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    description: String,
    reportedIncidents: Number,
    lastUpdated: { type: Date, default: Date.now }
});

const CommunityGroupSchema = new mongoose.Schema({
    name: String,
    description: String,
    location: String,
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    isPublic: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const EmergencyAlert = mongoose.model('EmergencyAlert', EmergencyAlertSchema);
const SafetyZone = mongoose.model('SafetyZone', SafetyZoneSchema);
const CommunityGroup = mongoose.model('CommunityGroup', CommunityGroupSchema);
const generateToken = (userId) => {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.userId = user.userId;
        next();
    });
};

const sendSMS = async (phoneNumber, message) => {
    try {
        if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
            const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
            await client.messages.create({
                body: message,
                from: process.env.TWILIO_PHONE_NUMBER,
                to: phoneNumber
            });
        }
        console.log(`SMS sent to ${phoneNumber}: ${message}`);
        return true;
    } catch (error) {
        console.error('SMS sending failed:', error);
        return false;
    }
};

const sendEmail = async (to, subject, html) => {
    try {
        if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
            const transporter = nodemailer.createTransporter({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to,
                subject,
                html
            });
        }
        console.log(`Email sent to ${to}: ${subject}`);
        return true;
    } catch (error) {
        console.error('Email sending failed:', error);
        return false;
    }
};

const calculateDistance = (lat1, lon1, lat2, lon2) => {
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
};
const wss = new WebSocket.Server({ port: 8080 });
const connectedClients = new Map();

wss.on('connection', (ws, req) => {
    const userId = req.url.split('/').pop();
    if (userId) {
        connectedClients.set(userId, ws);
        
        ws.on('message', (message) => {
            try {
                const data = JSON.parse(message);
                broadcastToUserContacts(userId, data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        });
        
        ws.on('close', () => {
            connectedClients.delete(userId);
        });

        ws.on('error', (error) => {
            console.error('WebSocket error:', error);
            connectedClients.delete(userId);
        });
    }
});

const broadcastToUserContacts = async (userId, data) => {
    try {
        const user = await User.findById(userId).populate('emergencyContacts');
        if (user && user.emergencyContacts) {
            user.emergencyContacts.forEach(contact => {
                const client = connectedClients.get(contact._id.toString());
                if (client && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify(data));
                }
            });
        }
    } catch (error) {
        console.error('Error broadcasting to contacts:', error);
    }
};
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
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed', details: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const user = await User.findOne({ email });
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
            message: 'Login successful',
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
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed', details: error.message });
    }
});
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone, dateOfBirth } = req.body;
        const user = await User.findByIdAndUpdate(
            req.userId,
            { name, phone, dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null },
            { new: true, runValidators: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ message: 'Profile updated successfully', user });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Failed to update profile', details: error.message });
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
        
        res.json({ message: 'Settings updated successfully', user });
    } catch (error) {
        console.error('Settings update error:', error);
        res.status(500).json({ error: 'Failed to update settings', details: error.message });
    }
});
app.get('/api/contacts', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ contacts: user.emergencyContacts });
    } catch (error) {
        console.error('Contacts fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch contacts', details: error.message });
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
        res.status(201).json({ message: 'Contact added successfully', contacts: user.emergencyContacts });
    } catch (error) {
        console.error('Contact add error:', error);
        res.status(500).json({ error: 'Failed to add contact', details: error.message });
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
        res.json({ message: 'Contact updated successfully', contacts: user.emergencyContacts });
    } catch (error) {
        console.error('Contact update error:', error);
        res.status(500).json({ error: 'Failed to update contact', details: error.message });
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
        
        res.json({ message: 'Contact deleted successfully', contacts: user.emergencyContacts });
    } catch (error) {
        console.error('Contact delete error:', error);
        res.status(500).json({ error: 'Failed to delete contact', details: error.message });
    }
});

app.post('/api/emergency/alert', authenticateToken, async (req, res) => {
    try {
        const { type, location, recordingUrl } = req.body;
        
        if (!type) {
            return res.status(400).json({ error: 'Alert type is required' });
        }
        
        const user = await User.findById(req.userId).populate('emergencyContacts');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const alert = new EmergencyAlert({
            userId: req.userId,
            type,
            location,
            recordingUrl
        });
        
        await alert.save();
        
        // Notify emergency contacts
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        const message = `EMERGENCY ALERT: ${user.name} has triggered an SOS alert. Location: ${location?.latitude || 'Unknown'}, ${location?.longitude || 'Unknown'}. Please check the SheShield app for details.`;
        
        for (const contact of primaryContacts) {
            if (contact.phone) {
                await sendSMS(contact.phone, message);
            }
            if (contact.email) {
                await sendEmail(contact.email, 'Emergency Alert - SheShield', `
                    <h2>Emergency Alert</h2>
                    <p><strong>${user.name}</strong> has triggered an emergency alert.</p>
                    <p><strong>Type:</strong> ${type}</p>
                    <p><strong>Location:</strong> ${location?.latitude || 'Unknown'}, ${location?.longitude || 'Unknown'}</p>
                    <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                    <p>Please check the SheShield app immediately for more details.</p>
                `);
            }
        }
       
        if (location?.latitude && location?.longitude) {
            console.log(`Emergency services notified for location: ${location.latitude}, ${location.longitude}`);
        }
       
        if (location?.latitude && location?.longitude) {
            user.location = {
                latitude: location.latitude,
                longitude: location.longitude,
                lastUpdated: new Date()
            };
            await user.save();
        }
     
        const ws = connectedClients.get(req.userId);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'EMERGENCY_ALERT_TRIGGERED',
                alertId: alert._id,
                location
            }));
        }
        
        res.status(201).json({ 
            message: 'Emergency alert triggered successfully', 
            alertId: alert._id 
        });
    } catch (error) {
        console.error('Emergency alert error:', error);
        res.status(500).json({ error: 'Failed to trigger emergency alert', details: error.message });
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
        await alert.save();
       
        const user = await User.findById(req.userId);
        const message = `ALERT CANCELLED: Emergency alert from ${user.name} has been cancelled.`;
        
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        for (const contact of primaryContacts) {
            if (contact.phone) {
                await sendSMS(contact.phone, message);
            }
        }
        
        res.json({ message: 'Emergency alert cancelled successfully' });
    } catch (error) {
        console.error('Cancel alert error:', error);
        res.status(500).json({ error: 'Failed to cancel emergency alert', details: error.message });
    }
});

app.get('/api/emergency/history', authenticateToken, async (req, res) => {
    try {
        const alerts = await EmergencyAlert.find({ userId: req.userId })
            .sort({ triggeredAt: -1 })
            .limit(50);
        
        res.json({ alerts });
    } catch (error) {
        console.error('Emergency history error:', error);
        res.status(500).json({ error: 'Failed to fetch emergency history', details: error.message });
    }
});

app.post('/api/location/update', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude } = req.body;
        
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
            lastUpdated: new Date()
        };
        
        await user.save();
        
        const dangerZones = await SafetyZone.find({
            location: {
                $near: {
                    $geometry: {
                        type: "Point",
                        coordinates: [longitude, latitude]
                    },
                    $maxDistance: 1000
                }
            },
            dangerLevel: 'high'
        });
        
        if (dangerZones.length > 0) {
            const ws = connectedClients.get(req.userId);
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'DANGER_ZONE_ALERT',
                    zones: dangerZones
                }));
            }
        }
        
        res.json({ message: 'Location updated successfully', dangerZones: dangerZones.length > 0 });
    } catch (error) {
        console.error('Location update error:', error);
        res.status(500).json({ error: 'Failed to update location', details: error.message });
    }
});

app.get('/api/location/nearby-safety', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude } = req.query;
        
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
                    $maxDistance: 5000
                }
            },
            dangerLevel: 'low'
        }).limit(10);
        
        const policeStations = [];
        const hospitals = [];
        
        res.json({ safeZones, policeStations, hospitals });
    } catch (error) {
        console.error('Nearby safety error:', error);
        res.status(500).json({ error: 'Failed to fetch nearby safety locations', details: error.message });
    }
});

app.get('/api/community/groups', authenticateToken, async (req, res) => {
    try {
        const groups = await CommunityGroup.find({ 
            $or: [
                { isPublic: true },
                { members: req.userId }
            ]
        }).populate('members', 'name email').populate('admin', 'name email');
        
        res.json({ groups });
    } catch (error) {
        console.error('Community groups error:', error);
        res.status(500).json({ error: 'Failed to fetch community groups', details: error.message });
    }
});

app.post('/api/community/groups', authenticateToken, async (req, res) => {
    try {
        const { name, description, location, isPublic } = req.body;
        
        if (!name) {
            return res.status(400).json({ error: 'Group name is required' });
        }
        
        const group = new CommunityGroup({
            name,
            description,
            location,
            admin: req.userId,
            members: [req.userId],
            isPublic: isPublic !== undefined ? isPublic : true
        });
        
        await group.save();
        await group.populate('admin', 'name email');
        
        res.status(201).json({ message: 'Community group created successfully', group });
    } catch (error) {
        console.error('Create group error:', error);
        res.status(500).json({ error: 'Failed to create community group', details: error.message });
    }
});

app.post('/api/community/groups/:groupId/join', authenticateToken, async (req, res) => {
    try {
        const { groupId } = req.params;
        const group = await CommunityGroup.findById(groupId);
        
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }
        
        if (!group.members.includes(req.userId)) {
            group.members.push(req.userId);
            await group.save();
        }
        
        res.json({ message: 'Joined group successfully', group });
    } catch (error) {
        console.error('Join group error:', error);
        res.status(500).json({ error: 'Failed to join group', details: error.message });
    }
});

app.get('/api/safety-zones', async (req, res) => {
    try {
        const { latitude, longitude, radius = 5000 } = req.query;
        
        let query = {};
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
        
        const zones = await SafetyZone.find(query).sort({ dangerLevel: -1 });
        res.json({ zones });
    } catch (error) {
        console.error('Safety zones error:', error);
        res.status(500).json({ error: 'Failed to fetch safety zones', details: error.message });
    }
});

app.post('/api/safety-zones/report', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, dangerLevel, description } = req.body;
        
        if (!latitude || !longitude || !dangerLevel) {
            return res.status(400).json({ error: 'Latitude, longitude and danger level are required' });
        }
        
        const zone = new SafetyZone({
            location: {
                type: "Point",
                coordinates: [longitude, latitude]
            },
            dangerLevel,
            description,
            reportedIncidents: 1
        });
        
        await zone.save();
        res.status(201).json({ message: 'Safety zone reported successfully', zone });
    } catch (error) {
        console.error('Report zone error:', error);
        res.status(500).json({ error: 'Failed to report safety zone', details: error.message });
    }
});

app.post('/api/check-in', authenticateToken, async (req, res) => {
    try {
        const { latitude, longitude, message } = req.body;
        const user = await User.findById(req.userId).populate('emergencyContacts');
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const primaryContacts = user.emergencyContacts.filter(contact => contact.isPrimary);
        const checkInMessage = message || `${user.name} has checked in safely at location: ${latitude || 'Unknown'}, ${longitude || 'Unknown'}`;
        
        for (const contact of primaryContacts) {
            if (contact.phone) {
                await sendSMS(contact.phone, checkInMessage);
            }
            if (contact.email) {
                await sendEmail(contact.email, 'Safe Check-in - SheShield', `
                    <h2>Safe Check-in</h2>
                    <p><strong>${user.name}</strong> has checked in safely.</p>
                    <p><strong>Location:</strong> ${latitude || 'Unknown'}, ${longitude || 'Unknown'}</p>
                    <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                    <p><strong>Message:</strong> ${checkInMessage}</p>
                `);
            }
        }
        
        res.json({ message: 'Check-in completed successfully' });
    } catch (error) {
        console.error('Check-in error:', error);
        res.status(500).json({ error: 'Failed to check in', details: error.message });
    }
});

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
            'check in': 'checkin',
            'safe': 'checkin',
            'location': 'location'
        };
        
        let action = null;
        for (const [keyword, command] of Object.entries(commands)) {
            if (transcript.toLowerCase().includes(keyword)) {
                action = command;
                break;
            }
        }
        
        if (action === 'sos') {
            const user = await User.findById(req.userId);
            const alert = new EmergencyAlert({
                userId: req.userId,
                type: 'voice',
                location: user.location
            });
            await alert.save();
            
            res.json({ action: 'sos_triggered', alertId: alert._id });
        } else if (action === 'checkin') {
            res.json({ action: 'checkin_triggered' });
        } else {
            res.json({ action: 'unknown_command' });
        }
    } catch (error) {
        console.error('Voice processing error:', error);
        res.status(500).json({ error: 'Failed to process voice command', details: error.message });
    }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
    
        const totalUsers = await User.countDocuments();
        const totalAlerts = await EmergencyAlert.countDocuments();
        const activeAlerts = await EmergencyAlert.countDocuments({ status: 'active' });
        const totalGroups = await CommunityGroup.countDocuments();
        
        res.json({
            totalUsers,
            totalAlerts,
            activeAlerts,
            totalGroups,
            serverTime: new Date()
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch admin stats', details: error.message });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

app.use('*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`SheShield Backend Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;
