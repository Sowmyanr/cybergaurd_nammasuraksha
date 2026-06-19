const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const { detectPhishing } = require('./phishingModel');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  console.log(`Request: ${req.method} ${req.url}`);
  next();
});
app.use(session({
  secret: process.env.SESSION_SECRET || 'defaultsecret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost/cyberguardian' })
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Schema and Connection
const scanSchema = new mongoose.Schema({
  link: String,
  encryptedLink: String,
  isPhishing: Boolean,
  message: String,
  platform: String,
  risk: String,
  source: String,
  timestamp: { type: Date, default: Date.now }
});
const Scan = mongoose.model('Scan', scanSchema);

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  googleId: String,
  githubId: String,
  provider: String,
  profilePicture: String
});
const User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/cyberguardian', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// AES Encryption
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0d2018fc04390383f0da06cd396a203c8b8aa192492eab3cf1ee512b27d20808';
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Whitelist for known safe domains
const safeDomains = ['google.com', 'youtube.com', 'wikipedia.org'];

// Google Safe Browsing
async function checkSafeBrowsing(link) {
  const apiKey = process.env.SAFE_BROWSING_API_KEY || 'your-safe-browsing-api-key';
  const url = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: 'cyberguardian', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url: link }]
    }
  };
  try {
    const response = await axios.post(url, body);
    return response.data.matches ? response.data.matches.length > 0 : false;
  } catch (error) {
    console.error('Safe Browsing error:', error.message);
    return false;
  }
}

// Source Tracing with IP-API
async function traceSource(link) {
  try {
    const url = new URL(link);
    const hostname = url.hostname;
    const ipResponse = await axios.get(`http://ip-api.com/json/${hostname}`);
    const { status, country, isp } = ipResponse.data;
    return status === 'success' ? `Server in ${country}, ISP: ${isp}` : 'Unknown source';
  } catch (error) {
    console.error('Source tracing error:', error.message);
    return 'Source tracing failed';
  }
}

// Threat Feed IOC Cache
let threatIOCs = new Set();
async function refreshThreatIOCs() {
  try {
    const response = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
      query: 'get_iocs',
      days: 1
    }, {
      headers: { 'API-KEY': process.env.THREATFOX_API_KEY }
    });
    if (response.data && Array.isArray(response.data.data)) {
      threatIOCs = new Set(response.data.data.map(item => item.ioc).filter(Boolean));
      console.log(`Threat feed IOCs refreshed: ${threatIOCs.size} entries.`);
    } else {
      console.warn('Threat feed refresh: No data array found.');
    }
  } catch (error) {
    console.error('Failed to refresh threat IOCs:', error.message);
  }
}
// Initial fetch and periodic refresh every 30 minutes
refreshThreatIOCs();
setInterval(refreshThreatIOCs, 30 * 60 * 1000);

// Passport Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    const user = await User.findOne({ email, provider: 'local' });
    if (!user || !user.password) return done(null, false);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false);
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'dummy',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'dummy',
  callbackURL: 'http://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = new User({
        username: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id,
        provider: 'google',
        profilePicture: profile.photos && profile.photos[0] ? profile.photos[0].value : (profile._json.picture || 'http://via.placeholder.com/72?text=No+Image')
      });
      await user.save();
    } else {
      user.profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : (profile._json.picture || 'http://via.placeholder.com/72?text=No+Image');
      await user.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Passport GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID || 'dummy',
  clientSecret: process.env.GITHUB_CLIENT_SECRET || 'dummy',
  callbackURL: 'http://localhost:3000/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    let email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
    if (!email) {
      const response = await axios.get('https://api.github.com/user', {
        headers: { Authorization: `token ${accessToken}` }
      });
      email = response.data.email || `github_${profile.id}@example.com`;
      const profilePicture = response.data.avatar_url;
      if (!user) {
        user = new User({
          username: profile.displayName || profile.login,
          email: email,
          githubId: profile.id,
          provider: 'github',
          profilePicture: profilePicture
        });
        await user.save();
      } else {
        user.username = profile.displayName || profile.login;
        user.profilePicture = profilePicture;
        await user.save();
      }
    } else {
      if (!user) {
        user = new User({
          username: profile.displayName || profile.login,
          email: email,
          githubId: profile.id,
          provider: 'github',
          profilePicture: 'https://avatars.githubusercontent.com/u/' + profile.id + '?v=4'
        });
        await user.save();
      } else {
        user.username = profile.displayName || profile.login;
        await user.save();
      }
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Scan API Endpoint
app.post('/api/scan', async (req, res) => {
  const { link } = req.body;
  if (!link) return res.status(400).json({ error: 'Link is required' });

  try {
    // Check against threat feed IOCs BEFORE URL parsing
    let isThreatFeedMatch = threatIOCs.has(link);
    if (!isThreatFeedMatch) {
      // Try matching without protocol
      const linkNoProto = link.replace(/^https?:\/\//, '');
      isThreatFeedMatch = threatIOCs.has(linkNoProto);
    }
    if (isThreatFeedMatch) {
      // For threat feed matches, skip URL parsing and flag as phishing
      const encryptedLink = encrypt(link);
      const result = {
        isPhishing: true,
        message: 'Phishing link detected from threat intelligence feed! Do not click.',
        platform: 'Web',
        risk: 'High',
        source: 'ThreatFox Feed'
      };
      const scan = new Scan({ ...result, link, encryptedLink });
      await scan.save();
      return res.json(result);
    }

    // Only parse as URL if not a threat feed match
    const url = new URL(link);
    const domain = url.hostname.toLowerCase();
    const encryptedLink = encrypt(link);

    const isWhitelisted = safeDomains.some(safe => domain === safe || domain.endsWith(`.${safe}`));
    if (isWhitelisted) {
      const result = {
        isPhishing: false,
        message: 'Link appears safe.',
        platform: 'Web',
        risk: 'Low',
        source: 'Whitelisted domain'
      };
      const scan = new Scan({ ...result, link, encryptedLink });
      await scan.save();
      return res.json(result);
    }

    const safeBrowsingResult = await checkSafeBrowsing(link);
    const detection = await detectPhishing(link);
    const isPhishing = safeBrowsingResult || detection.isPhishing;
    const source = await traceSource(link);

    const result = {
      isPhishing,
      message: isPhishing ? 'Phishing link detected! Do not click.' : 'Link appears safe.',
      platform: detection.platform,
      risk: isPhishing ? 'High' : 'Low',
      source
    };

    const scan = new Scan({ ...result, link, encryptedLink });
    await scan.save();

    res.json(result);
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(400).json({ error: 'Invalid URL or scan failed' });
  }
});

// Get Recent Scans
app.get('/api/scans', async (req, res) => {
  try {
    const scans = await Scan.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select('-encryptedLink -link');
    res.json(scans);
  } catch (error) {
    console.error('Fetch scans error:', error.message);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// Threat Intelligence Feed from ThreatFox
app.get('/api/threat-feed', async (req, res) => {
  try {
    // Always refresh the cache before responding
    await refreshThreatIOCs();
    const response = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
      query: 'get_iocs',
      days: 1 // Fetch IOCs from the last day
    }, {
      headers: { 'API-KEY': process.env.THREATFOX_API_KEY }
    });

    // Log the raw response and first item for debugging
    console.log('ThreatFox API raw response:', JSON.stringify(response.data, null, 2));
    console.log('First item for debugging:', response.data.data && response.data.data[0] ? JSON.stringify(response.data.data[0], null, 2) : 'No data available');

    // Check if response.data.data exists and map all fields
    if (!response.data.data || !Array.isArray(response.data.data)) {
      throw new Error('Invalid ThreatFox API response: No data array found');
    }

    const threats = response.data.data.map(item => ({
      id: item.id || 'Not available',
      ioc: item.ioc || 'Not available',
      threatType: item.threat_type || 'unknown',
      threatTypeDesc: item.threat_type_desc || 'This is a harmful activity, but specific details are missing.',
      iocType: item.ioc_type || 'Not specified',
      iocTypeDesc: item.ioc_type_desc || 'The type of this suspicious item is not specified.',
      malware: item.malware || 'unknown',
      malwarePrintable: item.malware_printable || 'Not identified',
      malwareAlias: item.malware_alias || 'None known',
      malwareMalpedia: item.malware_malpedia || 'Not available',
      confidenceLevel: item.confidence_level != null ? item.confidence_level : 0,
      firstSeen: item.first_seen || 'Not available',
      lastSeen: item.last_seen || 'Not tracked',
      reference: item.reference || 'Not available',
      reporter: item.reporter || 'Anonymous',
      tags: item.tags ? item.tags.join(', ') : 'None'
    }));

    res.json(threats.slice(0, 20)); // Limit to 20 entries for performance
  } catch (error) {
    console.error('Threat feed error:', error.message);
    res.status(500).json({ error: 'Failed to fetch threat feed' });
  }
});

// Registration/Login/User Endpoints (no protection)
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email, provider: 'local' });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered for standard login' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      provider: 'local',
      profilePicture: 'https://via.placeholder.com/72?text=No+Image'
    });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', passport.authenticate('local', { session: false }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email, provider: req.user.provider }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/user', async (req, res) => {
  try {
    const user = await User.findById(req.user?.id).select('username profilePicture');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email, provider: req.user.provider }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '1h' });
  res.redirect(`http://localhost:3000/dashboard.html?token=${token}`);
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { session: false }), (req, res) => {
  const token = jwt.sign({ id: req.user.id, email: req.user.email, provider: req.user.provider }, process.env.JWT_SECRET || 'jwtsecret', { expiresIn: '1h' });
  res.redirect(`http://localhost:3000/dashboard.html?token=${token}`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));