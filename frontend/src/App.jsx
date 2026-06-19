import React, { useState, useEffect, useRef } from 'react';
import SafeDial from './components/SafeDial';
import { deriveKey, encryptText, decryptText } from './lib/crypto';
import { encryptFile, decryptAndDownloadFile } from './lib/fileCrypto';
import './App.css';

const API_BASE = 'http://localhost:5000/api';

// Helper to map IP to simulated geolocation for premium audit depth
function getSimulatedLocation(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip.includes('localhost')) {
    return 'Local Host 🖥️';
  }
  const lastChar = ip.charAt(ip.length - 1);
  const locations = {
    '0': 'San Francisco, USA 🇺🇸',
    '1': 'New York, USA 🇺🇸',
    '2': 'London, UK 🇬🇧',
    '3': 'Tokyo, Japan 🇯🇵',
    '4': 'Frankfurt, Germany 🇩🇪',
    '5': 'Sydney, Australia 🇦🇺',
    '6': 'Singapore 🇸🇬',
    '7': 'Mumbai, India 🇮🇳',
    '8': 'Toronto, Canada 🇨🇦',
    '9': 'Paris, France 🇫🇷'
  };
  return locations[lastChar] || 'Berlin, Germany 🇩🇪';
}

export default function App() {
  // Navigation & Auth
  const [view, setView] = useState('auth'); // 'auth' or 'dashboard'
  const [activeTab, setActiveTab] = useState('dashboard'); // dashboard, vault, notes, files, analyzer, logs
  const [username, setUsername] = useState('');
  const [combination, setCombination] = useState([null, null, null]);
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'register'
  
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [dialResetTrigger, setDialResetTrigger] = useState(0);

  // Global Session State
  const [currentUser, setCurrentUser] = useState(null);
  const [toastMsg, setToastMsg] = useState('');
  const [dashboardLoading, setDashboardLoading] = useState(true);
  const cryptoKeyRef = useRef(null);

  // Module 1: Credentials Vault State
  const [vaultItems, setVaultItems] = useState([]);
  const [decryptedItems, setDecryptedItems] = useState({});
  const [revealedPasswords, setRevealedPasswords] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  
  // Credentials Form State
  const [formName, setFormName] = useState('');
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [formLoading, setFormLoading] = useState(false);
  const [editingId, setEditingId] = useState(null);

  // Module 2: Secure Notes State
  const [secureNotes, setSecureNotes] = useState([]);
  const [decryptedNotes, setDecryptedNotes] = useState({});
  const [activeNoteId, setActiveNoteId] = useState(null);
  const [noteFormTitle, setNoteFormTitle] = useState('');
  const [noteFormContent, setNoteFormContent] = useState('');
  const [noteSaving, setNoteSaving] = useState(false);

  // Module 3: Encrypted File Safe State
  const [fileItems, setFileItems] = useState([]);
  const [decryptedFileNames, setDecryptedFileNames] = useState({});
  const [fileUploading, setFileUploading] = useState(false);
  const [fileDownloadingId, setFileDownloadingId] = useState(null);
  const fileInputRef = useRef(null);

  // Module 4: Audit Logs State
  const [logs, setLogs] = useState([]);

  // Check login state on mount
  useEffect(() => {
    const token = sessionStorage.getItem('sg_token');
    const storedUser = sessionStorage.getItem('sg_user');
    const storedCombo = sessionStorage.getItem('sg_combo');
    const storedSalt = sessionStorage.getItem('sg_salt');

    if (token && storedUser && storedCombo && storedSalt) {
      setCurrentUser(storedUser);
      setView('dashboard');
      initDashboardCrypto(JSON.parse(storedCombo), storedSalt, token);
    } else {
      setDashboardLoading(false);
    }
  }, []);

  // Reset auth messages when switching tabs
  useEffect(() => {
    setError('');
    setSuccess('');
    setCombination([null, null, null]);
    setDialResetTrigger(prev => prev + 1);
  }, [authMode]);

  const showToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => {
      setToastMsg('');
    }, 3000);
  };

  // -------------------------------------------------------------
  // Cryptography Helpers
  // -------------------------------------------------------------
  const initDashboardCrypto = async (combo, salt, token) => {
    try {
      setDashboardLoading(true);
      const derivedKey = await deriveKey(combo, salt);
      cryptoKeyRef.current = derivedKey;

      // Load all data modules in parallel
      await Promise.all([
        fetchVaultItems(token, derivedKey),
        fetchNotes(token, derivedKey),
        fetchFiles(token, derivedKey),
        fetchLogs(token)
      ]);
    } catch (err) {
      console.error(err);
      showToast('Decryption key derivation failed');
      handleLockVault();
    } finally {
      setDashboardLoading(false);
    }
  };

  const decryptAllVaultItems = async (items, key) => {
    const decrypted = {};
    for (const item of items) {
      try {
        const decUser = await decryptText(item.username, key);
        const decPass = await decryptText(item.value, key);
        const decNotes = item.notes ? await decryptText(item.notes, key) : '';
        decrypted[item.id] = { username: decUser, value: decPass, notes: decNotes };
      } catch (e) {
        decrypted[item.id] = {
          username: '[Decryption Error]',
          value: '[Decryption Error]',
          notes: 'Incorrect combination key.'
        };
      }
    }
    setDecryptedItems(decrypted);
  };

  const decryptAllNotes = async (notes, key) => {
    const decrypted = {};
    for (const note of notes) {
      try {
        const decTitle = await decryptText(note.title, key);
        const decContent = await decryptText(note.content, key);
        decrypted[note.id] = { title: decTitle, content: decContent };
      } catch (e) {
        decrypted[note.id] = {
          title: '[Decryption Error]',
          content: '[Decryption Error]'
        };
      }
    }
    setDecryptedNotes(decrypted);
  };

  const decryptAllFileNames = async (files, key) => {
    const decrypted = {};
    for (const file of files) {
      try {
        const decName = await decryptText(file.fileName, key);
        decrypted[file.id] = decName;
      } catch (e) {
        decrypted[file.id] = '[Decrypted Name Error]';
      }
    }
    setDecryptedFileNames(decrypted);
  };

  // -------------------------------------------------------------
  // API Operations
  // -------------------------------------------------------------
  const fetchVaultItems = async (token, key) => {
    try {
      const res = await fetch(`${API_BASE}/vault`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Unauthorized');
      const data = await res.json();
      setVaultItems(data.items);
      if (key) {
        await decryptAllVaultItems(data.items, key);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchNotes = async (token, key) => {
    try {
      const res = await fetch(`${API_BASE}/notes`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setSecureNotes(data.notes);
        if (key) {
          await decryptAllNotes(data.notes, key);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchFiles = async (token, key) => {
    try {
      const res = await fetch(`${API_BASE}/files`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setFileItems(data.files);
        if (key) {
          await decryptAllFileNames(data.files, key);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchLogs = async (token) => {
    try {
      const res = await fetch(`${API_BASE}/logs`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setLogs(data.attempts);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!username.trim()) {
      setError('Please enter a username');
      return;
    }

    const isComboComplete = combination.every(v => v !== null);
    if (!isComboComplete) {
      setError('Please complete the 3-digit safe combination dial');
      return;
    }

    setLoading(true);

    try {
      if (authMode === 'register') {
        const salt = Array.from(crypto.getRandomValues(new Uint8Array(16)))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');

        const res = await fetch(`${API_BASE}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, combination, salt })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Registration failed');

        setSuccess('Vault successfully initialized! You can now unlock.');
        setAuthMode('login');
        setUsername('');
      } else {
        // Login
        const res = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, combination })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Unlock failed');

        sessionStorage.setItem('sg_token', data.token);
        sessionStorage.setItem('sg_user', data.username);
        sessionStorage.setItem('sg_combo', JSON.stringify(combination));
        sessionStorage.setItem('sg_salt', data.salt);

        setCurrentUser(data.username);
        setSuccess('Vault unlocked successfully!');
        
        setTimeout(() => {
          setView('dashboard');
          initDashboardCrypto(combination, data.salt, data.token);
        }, 1000);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // -------------------------------------------------------------
  // Vault Operations
  // -------------------------------------------------------------
  const handleAddOrUpdateItem = async (e) => {
    e.preventDefault();
    if (!formName.trim() || !formUsername.trim() || !formPassword.trim()) {
      showToast('All fields except notes are required');
      return;
    }

    const key = cryptoKeyRef.current;
    const token = sessionStorage.getItem('sg_token');
    if (!key || !token) {
      showToast('Key expired. Locking vault...');
      handleLockVault();
      return;
    }

    setFormLoading(true);

    try {
      const encryptedUsername = await encryptText(formUsername, key);
      const encryptedPassword = await encryptText(formPassword, key);
      const encryptedNotes = formNotes ? await encryptText(formNotes, key) : '';

      const isEditing = !!editingId;
      const url = `${API_BASE}/vault`;
      const method = isEditing ? 'PUT' : 'POST';
      const body = {
        name: formName.trim(),
        username: encryptedUsername,
        value: encryptedPassword,
        notes: encryptedNotes,
        ...(isEditing && { id: editingId })
      };

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(body)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save');

      showToast(isEditing ? 'Credential updated' : 'Credential encrypted & saved');
      resetForm();
      await fetchVaultItems(token, key);
    } catch (err) {
      showToast(`Error: ${err.message}`);
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteItem = async (id) => {
    if (!confirm('Are you sure you want to delete this credential?')) return;
    const token = sessionStorage.getItem('sg_token');
    const key = cryptoKeyRef.current;

    try {
      const res = await fetch(`${API_BASE}/vault?id=${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!res.ok) throw new Error('Delete failed');

      showToast('Credential removed');
      setVaultItems(prev => prev.filter(i => i.id !== id));
      
      const updated = { ...decryptedItems };
      delete updated[id];
      setDecryptedItems(updated);
    } catch (err) {
      showToast('Failed to delete secret');
    }
  };

  const handleEditClick = (item) => {
    const dec = decryptedItems[item.id] || {};
    setFormName(item.name);
    setFormUsername(dec.username || '');
    setFormPassword(dec.value || '');
    setFormNotes(dec.notes || '');
    setEditingId(item.id);
  };

  const resetForm = () => {
    setFormName('');
    setFormUsername('');
    setFormPassword('');
    setFormNotes('');
    setEditingId(null);
  };

  const generateRandomPassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let newPassword = '';
    const randomValues = new Uint32Array(16);
    window.crypto.getRandomValues(randomValues);
    for (let i = 0; i < 16; i++) {
      newPassword += chars[randomValues[i] % chars.length];
    }
    setFormPassword(newPassword);
    showToast('Secure password generated!');
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
      .then(() => showToast(`${label} copied!`))
      .catch(() => showToast('Failed to copy'));
  };

  const togglePasswordReveal = (id) => {
    setRevealedPasswords(prev => ({ ...prev, [id]: !prev[id] }));
  };

  // -------------------------------------------------------------
  // Secure Notes Operations
  // -------------------------------------------------------------
  const handleNoteSelect = (noteId) => {
    setActiveNoteId(noteId);
    if (noteId === 'new') {
      setNoteFormTitle('');
      setNoteFormContent('');
    } else {
      const dec = decryptedNotes[noteId] || { title: '', content: '' };
      setNoteFormTitle(dec.title);
      setNoteFormContent(dec.content);
    }
  };

  const handleSaveNote = async (e) => {
    e.preventDefault();
    if (!noteFormTitle.trim() || !noteFormContent.trim()) {
      showToast('Title and content are required');
      return;
    }

    const key = cryptoKeyRef.current;
    const token = sessionStorage.getItem('sg_token');
    if (!key || !token) return;

    setNoteSaving(true);
    try {
      const encTitle = await encryptText(noteFormTitle.trim(), key);
      const encContent = await encryptText(noteFormContent, key);

      const isEditing = activeNoteId && activeNoteId !== 'new';
      const url = `${API_BASE}/notes`;
      const method = isEditing ? 'PUT' : 'POST';
      const body = {
        title: encTitle,
        content: encContent,
        ...(isEditing && { id: activeNoteId })
      };

      const res = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(body)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to save note');

      showToast(isEditing ? 'Note updated' : 'New note encrypted & saved');
      
      await fetchNotes(token, key);
      
      if (!isEditing && data.note) {
        setActiveNoteId(data.note.id);
      }
    } catch (err) {
      showToast(`Error: ${err.message}`);
    } finally {
      setNoteSaving(false);
    }
  };

  const handleDeleteNote = async (id) => {
    if (!confirm('Are you sure you want to delete this encrypted note?')) return;
    const token = sessionStorage.getItem('sg_token');
    const key = cryptoKeyRef.current;
    if (!token) return;

    try {
      const res = await fetch(`${API_BASE}/notes?id=${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!res.ok) throw new Error('Delete failed');

      showToast('Note deleted');
      setSecureNotes(prev => prev.filter(n => n.id !== id));
      
      const updated = { ...decryptedNotes };
      delete updated[id];
      setDecryptedNotes(updated);
      
      if (activeNoteId === id) {
        setActiveNoteId(null);
        setNoteFormTitle('');
        setNoteFormContent('');
      }
    } catch (err) {
      showToast('Failed to delete note');
    }
  };

  // -------------------------------------------------------------
  // Encrypted File Safe Operations
  // -------------------------------------------------------------
  const handleTriggerFileSelect = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // 10MB limit
    const MAX_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      showToast('File size exceeds the 10MB limit');
      return;
    }

    const key = cryptoKeyRef.current;
    const token = sessionStorage.getItem('sg_token');
    if (!key || !token) return;

    setFileUploading(true);
    showToast(`Reading and encrypting "${file.name}" locally...`);

    try {
      // Local zero-knowledge encryption
      const encryptedPayload = await encryptFile(file, key);

      const res = await fetch(`${API_BASE}/files`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(encryptedPayload)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');

      showToast('File encrypted & uploaded successfully!');
      
      // Reset input
      e.target.value = '';
      
      await fetchFiles(token, key);
    } catch (err) {
      showToast(`Encryption upload failed: ${err.message}`);
    } finally {
      setFileUploading(false);
    }
  };

  const handleFileDownload = async (fileItem) => {
    const key = cryptoKeyRef.current;
    const token = sessionStorage.getItem('sg_token');
    if (!key || !token) return;

    setFileDownloadingId(fileItem.id);
    showToast('Fetching encrypted content from server...');

    try {
      const res = await fetch(`${API_BASE}/files/download?id=${fileItem.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Fetch failed');
      const data = await res.json();

      showToast('Decrypting file bytes locally in browser...');
      await decryptAndDownloadFile(data.file, key);
      showToast('File downloaded successfully!');
    } catch (err) {
      showToast(`Decryption download failed: ${err.message}`);
    } finally {
      setFileDownloadingId(null);
    }
  };

  const handleFileDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this file from the safe?')) return;
    const token = sessionStorage.getItem('sg_token');
    const key = cryptoKeyRef.current;
    if (!token) return;

    try {
      const res = await fetch(`${API_BASE}/files?id=${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!res.ok) throw new Error('Delete failed');

      showToast('File deleted from safe');
      setFileItems(prev => prev.filter(f => f.id !== id));
      
      const updated = { ...decryptedFileNames };
      delete updated[id];
      setDecryptedFileNames(updated);
    } catch (err) {
      showToast('Failed to delete file');
    }
  };

  // Helper for human-readable file sizes
  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // -------------------------------------------------------------
  // Password Analyzer Calculations
  // -------------------------------------------------------------
  const analyzeVaultHealth = () => {
    let totalCount = vaultItems.length;
    if (totalCount === 0) {
      return { score: 100, weakCount: 0, duplicateCount: 0, strongCount: 0, totalCount: 0, issues: [] };
    }

    let weakCount = 0;
    let duplicateCount = 0;
    let strongCount = 0;
    const issues = [];
    
    // Password registry map
    const passwordMap = {};
    
    vaultItems.forEach(item => {
      const dec = decryptedItems[item.id] || { value: '' };
      const pass = dec.value;
      if (!pass) return;

      passwordMap[pass] = (passwordMap[pass] || 0) + 1;
      
      // Calculate Entropy
      let poolSize = 0;
      if (/[a-z]/.test(pass)) poolSize += 26;
      if (/[A-Z]/.test(pass)) poolSize += 26;
      if (/[0-9]/.test(pass)) poolSize += 10;
      if (/[^a-zA-Z0-9]/.test(pass)) poolSize += 32;

      if (poolSize === 0) poolSize = 1;
      const entropy = pass.length * Math.log2(poolSize);

      let isWeak = false;
      if (entropy < 30 || pass.length < 8) {
        isWeak = true;
        weakCount++;
        issues.push({
          id: `${item.id}-weak`,
          itemId: item.id,
          service: item.name,
          type: 'danger',
          details: `Password is critically weak (Length: ${pass.length}, Low Entropy).`
        });
      } else if (entropy >= 50) {
        strongCount++;
      }

      // Check common patterns
      if (!isWeak && /^(123|password|qwerty|admin)/i.test(pass)) {
        issues.push({
          id: `${item.id}-common`,
          itemId: item.id,
          service: item.name,
          type: 'warning',
          details: 'Contains common dictionary words or patterns.'
        });
      }
    });

    // Check duplicate passwords
    vaultItems.forEach(item => {
      const dec = decryptedItems[item.id] || { value: '' };
      const pass = dec.value;
      if (pass && passwordMap[pass] > 1) {
        duplicateCount++;
        issues.push({
          id: `${item.id}-dup`,
          itemId: item.id,
          service: item.name,
          type: 'warning',
          details: `Shared reused password with ${passwordMap[pass] - 1} other credential(s).`
        });
      }
    });

    // Calculate score
    // Deduct 15 points per weak password (cap 50)
    // Deduct 10 points per duplicate password (cap 30)
    let score = 100;
    score -= Math.min(weakCount * 15, 50);
    score -= Math.min(duplicateCount * 10, 30);
    if (score < 0) score = 0;

    return {
      score: Math.round(score),
      weakCount,
      duplicateCount,
      strongCount,
      totalCount,
      issues
    };
  };

  const healthReport = analyzeVaultHealth();

  // -------------------------------------------------------------
  // Audit Logs Calculations
  // -------------------------------------------------------------
  const getAuditStats = () => {
    if (logs.length === 0) return { total: 0, successRate: 0, failRate: 0, successCount: 0, failCount: 0 };
    const successCount = logs.filter(l => l.success).length;
    const failCount = logs.length - successCount;
    const successRate = Math.round((successCount / logs.length) * 100);
    const failRate = 100 - successRate;
    return {
      total: logs.length,
      successCount,
      failCount,
      successRate,
      failRate
    };
  };

  const auditStats = getAuditStats();

  // Lock session clean up
  const handleLockVault = () => {
    sessionStorage.clear();
    setView('auth');
    setCurrentUser(null);
    setCombination([null, null, null]);
    setVaultItems([]);
    setDecryptedItems({});
    setRevealedPasswords({});
    setLogs([]);
    setSecureNotes([]);
    setDecryptedNotes({});
    setFileItems([]);
    setDecryptedFileNames({});
    setUsername('');
    setActiveNoteId(null);
    setNoteFormTitle('');
    setNoteFormContent('');
    setActiveTab('dashboard');
  };

  // Filter items
  const filteredVaultItems = vaultItems.filter(item => {
    const nameMatch = item.name.toLowerCase().includes(searchQuery.toLowerCase());
    const dec = decryptedItems[item.id] || {};
    const userMatch = dec.username?.toLowerCase().includes(searchQuery.toLowerCase());
    return nameMatch || userMatch;
  });

  const filteredNotes = secureNotes.filter(note => {
    const dec = decryptedNotes[note.id] || { title: '' };
    return dec.title.toLowerCase().includes(searchQuery.toLowerCase());
  });

  // Render Dashboard Contents
  if (view === 'dashboard') {
    if (dashboardLoading) {
      return (
        <div className="lock-overlay">
          <div className="lock-card glass-panel">
            <h2 className="text-glow" style={{ marginBottom: '15px' }}>Decrypting Security Suite...</h2>
            <p style={{ color: 'var(--text-secondary)' }}>Deriving cryptographic keys & loading encrypted models...</p>
          </div>
        </div>
      );
    }

    return (
      <div className="suite-layout">
        {/* Dynamic Glowing Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-header">
            <h1 className="sidebar-logo text-glow">Secure Gaze</h1>
            <div className="sidebar-logo-subtitle">Zero-Knowledge Suite</div>
          </div>
          
          <nav className="sidebar-nav">
            <button 
              className={`sidebar-link ${activeTab === 'dashboard' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('dashboard')}
            >
              <span className="sidebar-link-icon">📊</span>
              <span>Dashboard</span>
            </button>
            
            <button 
              className={`sidebar-link ${activeTab === 'vault' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('vault')}
            >
              <span className="sidebar-link-icon">🔑</span>
              <span>Credentials Vault</span>
            </button>
            
            <button 
              className={`sidebar-link ${activeTab === 'notes' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('notes')}
            >
              <span className="sidebar-link-icon">📝</span>
              <span>Secure Notes</span>
            </button>
            
            <button 
              className={`sidebar-link ${activeTab === 'files' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('files')}
            >
              <span className="sidebar-link-icon">📂</span>
              <span>Encrypted Files</span>
            </button>
            
            <button 
              className={`sidebar-link ${activeTab === 'analyzer' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('analyzer')}
            >
              <span className="sidebar-link-icon">📈</span>
              <span>Health Analyzer</span>
            </button>
            
            <button 
              className={`sidebar-link ${activeTab === 'logs' ? 'sidebar-link-active' : ''}`}
              onClick={() => setActiveTab('logs')}
            >
              <span className="sidebar-link-icon">🛡️</span>
              <span>Audit Access Logs</span>
            </button>
          </nav>
          
          <div className="sidebar-footer">
            <div className="sidebar-user">
              <span className="sidebar-user-status"></span>
              <span className="sidebar-username">{currentUser}</span>
            </div>
            <button className="btn-secondary" onClick={handleLockVault} style={{ width: '100%', padding: '8px 12px', fontSize: '0.8rem' }}>
              Lock Vault
            </button>
          </div>
        </aside>

        {/* Main Dashboard Panel */}
        <main className="main-content">
          <header className="nav-header">
            <div className="module-title">
              {activeTab === 'dashboard' && 'Dashboard Overview'}
              {activeTab === 'vault' && 'Credentials Vault'}
              {activeTab === 'notes' && 'Encrypted Notes'}
              {activeTab === 'files' && 'Encrypted File Safe'}
              {activeTab === 'analyzer' && 'Vault Health Auditor'}
              {activeTab === 'logs' && 'Audit Access Trail'}
            </div>
            
            {/* Context Search */}
            {(activeTab === 'vault' || activeTab === 'notes') && (
              <input 
                type="text" 
                className="input-field search-bar" 
                placeholder={activeTab === 'vault' ? "Search credentials..." : "Search notes..."}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            )}
          </header>

          <div className="module-container">
            
            {/* ---------------------------------------------------------
             * TAB 1: DASHBOARD
             * --------------------------------------------------------- */}
            {activeTab === 'dashboard' && (
              <>
                <div className="stats-grid">
                  <div className="stat-card glass-panel">
                    <div className="stat-header">
                      <span className="stat-label">Vault Secrets</span>
                      <span className="stat-icon">🔑</span>
                    </div>
                    <div className="stat-value">{vaultItems.length}</div>
                    <div className="stat-desc">Encrypted accounts stored</div>
                  </div>

                  <div className="stat-card glass-panel">
                    <div className="stat-header">
                      <span className="stat-label">Secure Notes</span>
                      <span className="stat-icon">📝</span>
                    </div>
                    <div className="stat-value">{secureNotes.length}</div>
                    <div className="stat-desc">Encrypted local notepad documents</div>
                  </div>

                  <div className="stat-card glass-panel">
                    <div className="stat-header">
                      <span className="stat-label">File Safe</span>
                      <span className="stat-icon">📂</span>
                    </div>
                    <div className="stat-value">{fileItems.length}</div>
                    <div className="stat-desc">Zero-knowledge local files</div>
                  </div>

                  <div className="stat-card glass-panel">
                    <div className="stat-header">
                      <span className="stat-label">Security Health</span>
                      <span className="stat-icon">🛡️</span>
                    </div>
                    <div className="health-score-container">
                      <svg viewBox="0 0 36 36" className="circular-chart">
                        <path className="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                        <path 
                          className={`circle ${healthReport.score >= 80 ? 'circle-green' : healthReport.score >= 50 ? 'circle-orange' : 'circle-red'}`} 
                          strokeDasharray={`${healthReport.score}, 100`} 
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                        />
                        <text x="18" y="20.35" className="percentage">{healthReport.score}%</text>
                      </svg>
                      <div>
                        <div style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                          {healthReport.score >= 80 ? 'EXCELLENT' : healthReport.score >= 50 ? 'WARNING' : 'COMPROMISED'}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {healthReport.issues.length} concerns detected
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="dashboard-sections">
                  {/* Quick Actions */}
                  <div className="quick-actions-card glass-panel">
                    <h3 className="text-glow" style={{ fontSize: '1.2rem', marginBottom: '15px' }}>Security Suite Quick Actions</h3>
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Encrypt and add data to specific secure cryptographic modules in real-time.</p>
                    
                    <div className="action-buttons">
                      <button className="btn-action" onClick={() => setActiveTab('vault')}>
                        <span className="btn-action-icon">🔑</span>
                        <span>New Credential</span>
                      </button>
                      
                      <button className="btn-action" onClick={() => { setActiveTab('notes'); handleNoteSelect('new'); }}>
                        <span className="btn-action-icon">📝</span>
                        <span>New Secure Note</span>
                      </button>
                      
                      <button className="btn-action" onClick={() => setActiveTab('files')}>
                        <span className="btn-action-icon">📂</span>
                        <span>Encrypt & Upload File</span>
                      </button>
                      
                      <button className="btn-action" onClick={() => setActiveTab('analyzer')}>
                        <span className="btn-action-icon">📈</span>
                        <span>Run Health Check</span>
                      </button>
                    </div>
                  </div>

                  {/* Audit highlights */}
                  <div className="logs-card glass-panel">
                    <h3 className="text-glow" style={{ fontSize: '1.2rem', marginBottom: '15px' }}>Recent Audit trail</h3>
                    {logs.length === 0 ? (
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No recent audit activity logs.</p>
                    ) : (
                      <div className="log-list">
                        {logs.slice(0, 5).map(log => (
                          <div key={log.id} className={`log-item ${log.success ? 'log-success' : 'log-failure'}`}>
                            <span className="log-icon">{log.success ? '🟢' : '🔴'}</span>
                            <div className="log-content">
                              <span className="log-title">{log.success ? 'Lock Session OK' : 'Auth Attack Stopped'}</span>
                              <span className="log-time">{new Date(log.attemptTime).toLocaleString()}</span>
                              <span className="log-details">IP: {log.ipAddress} ({getSimulatedLocation(log.ipAddress)})</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}

            {/* ---------------------------------------------------------
             * TAB 2: CREDENTIALS VAULT
             * --------------------------------------------------------- */}
            {activeTab === 'vault' && (
              <div className="vault-layout">
                {/* Form */}
                <div className="form-card glass-panel">
                  <h3 className="text-glow" style={{ marginBottom: '20px' }}>
                    {editingId ? 'Edit Credential Details' : 'Encrypt & Store New Secret'}
                  </h3>
                  
                  <form onSubmit={handleAddOrUpdateItem}>
                    <div className="form-grid">
                      <div className="input-group">
                        <label className="input-label" htmlFor="serviceName">Website Name</label>
                        <input 
                          type="text" 
                          id="serviceName" 
                          className="input-field" 
                          placeholder="e.g., Google, GitHub, Proton..."
                          value={formName}
                          onChange={(e) => setFormName(e.target.value)}
                          required
                        />
                      </div>
                      
                      <div className="input-group">
                        <label className="input-label" htmlFor="vaultUser">Username / Account Email</label>
                        <input 
                          type="text" 
                          id="vaultUser" 
                          className="input-field" 
                          placeholder="e.g., mail@protonmail.com"
                          value={formUsername}
                          onChange={(e) => setFormUsername(e.target.value)}
                          required
                        />
                      </div>
                      
                      <div className="input-group">
                        <label className="input-label" htmlFor="vaultPassword">Password String</label>
                        <div className="password-field-group">
                          <input 
                            type="text" 
                            id="vaultPassword" 
                            className="input-field" 
                            placeholder="Password payload"
                            value={formPassword}
                            onChange={(e) => setFormPassword(e.target.value)}
                            required
                          />
                          <button 
                            type="button" 
                            className="btn-gen"
                            onClick={generateRandomPassword}
                          >
                            Generate
                          </button>
                        </div>
                      </div>

                      <div className="input-group">
                        <label className="input-label" htmlFor="vaultNotes">Encrypted Notes</label>
                        <input 
                          type="text" 
                          id="vaultNotes" 
                          className="input-field" 
                          placeholder="Optional pin code or backup keys"
                          value={formNotes}
                          onChange={(e) => setFormNotes(e.target.value)}
                        />
                      </div>
                    </div>

                    <div className="form-action-group">
                      {editingId && (
                        <button type="button" className="btn-secondary" onClick={resetForm} style={{ padding: '8px 16px' }}>
                          Cancel
                        </button>
                      )}
                      <button type="submit" className="btn-neon" disabled={formLoading} style={{ padding: '8px 20px', fontSize: '0.85rem' }}>
                        {formLoading ? 'Working...' : editingId ? 'Update Secret' : 'Encrypt & Save'}
                      </button>
                    </div>
                  </form>
                </div>

                {/* List */}
                <div>
                  <div className="section-header" style={{ marginBottom: '16px' }}>
                    <h3 className="section-title">Decrypted Credentials</h3>
                  </div>

                  {filteredVaultItems.length === 0 ? (
                    <div className="empty-vault">
                      <span className="empty-icon">🔒</span>
                      <p>No credentials stored or matches found.</p>
                    </div>
                  ) : (
                    <div className="vault-list">
                      {filteredVaultItems.map(item => {
                        const dec = decryptedItems[item.id] || { username: '...', value: '...', notes: '' };
                        const isRevealed = !!revealedPasswords[item.id];
                        return (
                          <div key={item.id} className="vault-card glass-panel">
                            <div className="card-header">
                              <h4 className="card-title">{item.name}</h4>
                              <div className="card-controls">
                                <button className="card-btn" onClick={() => handleEditClick(item)} title="Edit">✏️</button>
                                <button className="card-btn card-btn-delete" onClick={() => handleDeleteItem(item.id)} title="Delete">🗑️</button>
                              </div>
                            </div>

                            <div className="card-details">
                              <div className="detail-row">
                                <span className="detail-label">Username</span>
                                <div className="detail-value-group">
                                  <span className="detail-value" title={dec.username}>{dec.username}</span>
                                  <button className="card-btn" onClick={() => copyToClipboard(dec.username, 'Username')}>📋</button>
                                </div>
                              </div>

                              <div className="detail-row">
                                <span className="detail-label">Password</span>
                                <div className="detail-value-group">
                                  <span className={`detail-value ${!isRevealed ? 'detail-value-hidden' : ''}`}>
                                    {isRevealed ? dec.value : '••••••••••••'}
                                  </span>
                                  <div style={{ display: 'flex', gap: '4px' }}>
                                    <button className="card-btn" onClick={() => togglePasswordReveal(item.id)}>
                                      {isRevealed ? '👁️' : '🕶️'}
                                    </button>
                                    <button className="card-btn" onClick={() => copyToClipboard(dec.value, 'Password')}>📋</button>
                                  </div>
                                </div>
                              </div>

                              {dec.notes && (
                                <div className="detail-row">
                                  <span className="detail-label">Private Notes</span>
                                  <div className="detail-value-group" style={{ fontFamily: 'var(--font-sans)', fontStyle: 'italic' }}>
                                    <span className="detail-value" title={dec.notes}>{dec.notes}</span>
                                    <button className="card-btn" onClick={() => copyToClipboard(dec.notes, 'Notes')}>📋</button>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ---------------------------------------------------------
             * TAB 3: SECURE NOTES
             * --------------------------------------------------------- */}
            {activeTab === 'notes' && (
              <div className="notes-layout">
                {/* Note Selector Sidebar */}
                <div className="notes-sidebar">
                  <button className="btn-neon" style={{ width: '100%' }} onClick={() => handleNoteSelect('new')}>
                    📝 New Secure Note
                  </button>

                  <div className="notes-list">
                    {filteredNotes.length === 0 ? (
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', textAlign: 'center', marginTop: '20px' }}>No notes found.</p>
                    ) : (
                      filteredNotes.map(note => {
                        const dec = decryptedNotes[note.id] || { title: '[Decrypted Note Title]' };
                        const isActive = activeNoteId === note.id;
                        return (
                          <div 
                            key={note.id} 
                            className={`note-item-card glass-panel ${isActive ? 'note-item-card-active' : ''}`}
                            onClick={() => handleNoteSelect(note.id)}
                          >
                            <div className="note-item-title">{dec.title}</div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span className="note-item-date">{new Date(note.updatedAt).toLocaleDateString()}</span>
                              <button 
                                className="card-btn card-btn-delete" 
                                style={{ padding: '0px' }}
                                onClick={(e) => { e.stopPropagation(); handleDeleteNote(note.id); }}
                                title="Delete note"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Note Editor Area */}
                <div className="note-editor-card glass-panel">
                  {activeNoteId ? (
                    <form className="note-editor-form" onSubmit={handleSaveNote}>
                      <input 
                        type="text" 
                        className="input-field" 
                        placeholder="Encrypted Note Title" 
                        style={{ fontSize: '1.2rem', fontWeight: 'bold' }}
                        value={noteFormTitle}
                        onChange={(e) => setNoteFormTitle(e.target.value)}
                        required
                      />
                      
                      <textarea 
                        className="note-textarea" 
                        placeholder="Write note contents here... Everything typed here is encrypted locally in your browser via AES-GCM before sent to the database."
                        value={noteFormContent}
                        onChange={(e) => setNoteFormContent(e.target.value)}
                        required
                      ></textarea>

                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
                        <button type="submit" className="btn-neon" disabled={noteSaving} style={{ padding: '8px 24px' }}>
                          {noteSaving ? 'Encrypting & Saving...' : 'Save Note'}
                        </button>
                      </div>
                    </form>
                  ) : (
                    <div className="empty-note-editor">
                      <span>📝</span>
                      <p style={{ marginTop: '10px' }}>Select a secure note or create a new one to begin editing.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ---------------------------------------------------------
             * TAB 4: ENCRYPTED FILE SAFE
             * --------------------------------------------------------- */}
            {activeTab === 'files' && (
              <div className="file-safe-layout">
                {/* File Upload Dropzone */}
                <div className="dropzone-container" onClick={handleTriggerFileSelect}>
                  <input 
                    type="file" 
                    ref={fileInputRef} 
                    style={{ display: 'none' }} 
                    onChange={handleFileUpload} 
                    disabled={fileUploading}
                  />
                  <div className="dropzone-icon">📂</div>
                  <div className="dropzone-text">
                    {fileUploading ? 'Encrypting & Transmitting...' : 'Choose File to Local Encrypt'}
                  </div>
                  <div className="dropzone-sub">Supports images, pdfs, txt, zip files (Max size: 10MB)</div>
                  <div style={{ color: 'var(--glow-cyan)', fontSize: '0.75rem', marginTop: '10px', fontWeight: 'bold' }}>
                    Zero-Knowledge: Raw file contents and filename are fully encrypted client-side using AES-GCM.
                  </div>
                </div>

                {/* Encrypted Files List */}
                <div>
                  <h3 className="section-title" style={{ marginBottom: '16px' }}>Encrypted Vault File Safe</h3>
                  
                  {fileItems.length === 0 ? (
                    <div className="empty-vault">
                      <span className="empty-icon">📁</span>
                      <p>File Safe is empty. Upload and encrypt files above.</p>
                    </div>
                  ) : (
                    <div className="file-cards-grid">
                      {fileItems.map(file => {
                        const decryptedName = decryptedFileNames[file.id] || 'Decrypted Filename...';
                        const isDownloading = fileDownloadingId === file.id;
                        
                        // Decide icon based on MIME type
                        let fileIcon = '📄';
                        if (file.fileType.startsWith('image/')) fileIcon = '🖼️';
                        else if (file.fileType === 'application/pdf') fileIcon = '📕';
                        else if (file.fileType.includes('zip') || file.fileType.includes('rar')) fileIcon = '📦';

                        return (
                          <div key={file.id} className="file-card glass-panel">
                            <div className="file-icon-box">{fileIcon}</div>
                            <div className="file-meta">
                              <div className="file-name" title={decryptedName}>{decryptedName}</div>
                              <div className="file-size-date">
                                {formatBytes(file.fileSize)} | {new Date(file.createdAt).toLocaleDateString()}
                              </div>
                            </div>
                            
                            <div style={{ display: 'flex', gap: '4px' }}>
                              <button 
                                className="card-btn" 
                                onClick={() => handleFileDownload(file)} 
                                disabled={isDownloading}
                                title="Decrypt & Download"
                              >
                                {isDownloading ? '⏳' : '📥'}
                              </button>
                              
                              <button 
                                className="card-btn card-btn-delete" 
                                onClick={() => handleFileDelete(file.id)}
                                title="Delete file"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* ---------------------------------------------------------
             * TAB 5: PASSWORD HEALTH ANALYZER
             * --------------------------------------------------------- */}
            {activeTab === 'analyzer' && (
              <div className="analyzer-grid">
                {/* Score Gauge */}
                <div className="score-panel glass-panel">
                  <h3 className="text-glow" style={{ fontSize: '1.2rem' }}>Vault Health Rating</h3>
                  
                  <div className="health-large-gauge">
                    <svg viewBox="0 0 36 36" className="circular-chart">
                      <path className="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                      <path 
                        className={`circle ${healthReport.score >= 80 ? 'circle-green' : healthReport.score >= 50 ? 'circle-orange' : 'circle-red'}`} 
                        strokeDasharray={`${healthReport.score}, 100`} 
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      />
                      <text x="18" y="20.35" className="percentage">{healthReport.score}%</text>
                    </svg>
                  </div>

                  <div>
                    <h2 style={{ color: '#fff', fontSize: '1.5rem', fontWeight: '800' }}>
                      {healthReport.score >= 80 ? 'EXCELLENT' : healthReport.score >= 50 ? 'NEEDS ATTENTION' : 'SECURITY ALERT'}
                    </h2>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      Audit compiled locally inside your browser. No plaintext password is ever sent or processed.
                    </p>
                  </div>
                </div>

                {/* Audit details */}
                <div className="analysis-details-panel">
                  <div className="metrics-row">
                    <div className="metric-box glass-panel">
                      <div className="detail-label">Total Accounts</div>
                      <div className="metric-num" style={{ color: '#fff' }}>{healthReport.totalCount}</div>
                    </div>
                    
                    <div className="metric-box glass-panel">
                      <div className="detail-label">Strong Passwords</div>
                      <div className="metric-num metric-num-green">{healthReport.strongCount}</div>
                    </div>

                    <div className="metric-box glass-panel">
                      <div className="detail-label">Weak Passwords</div>
                      <div className="metric-num metric-num-red">{healthReport.weakCount}</div>
                    </div>

                    <div className="metric-box glass-panel">
                      <div className="detail-label">Reused Credentials</div>
                      <div className="metric-num metric-num-orange">{healthReport.duplicateCount}</div>
                    </div>
                  </div>

                  <div className="issue-list-card glass-panel">
                    <h3 className="text-glow" style={{ fontSize: '1.15rem' }}>Identified Vulnerability Alerts</h3>
                    
                    {healthReport.issues.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                        <span style={{ fontSize: '2rem' }}>🎉</span>
                        <p style={{ marginTop: '10px' }}>Zero security issues identified in your vault credentials! Keep up the good hygiene.</p>
                      </div>
                    ) : (
                      <div className="issues-container">
                        {healthReport.issues.map(issue => (
                          <div 
                            key={issue.id} 
                            className={`issue-item ${issue.type === 'warning' ? 'issue-item-warning' : ''}`}
                          >
                            <span className="issue-item-icon">{issue.type === 'danger' ? '⚠️' : '🚨'}</span>
                            <div className="issue-text">
                              <span className="issue-service">[{issue.service}]</span>
                              {issue.details}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ---------------------------------------------------------
             * TAB 6: AUDIT ACCESS LOGS
             * --------------------------------------------------------- */}
            {activeTab === 'logs' && (
              <div className="audit-layout">
                {/* Analytics card */}
                <div className="analytics-cards">
                  <div className="analytics-card glass-panel">
                    <h3 className="text-glow" style={{ fontSize: '1.1rem' }}>Success / Failure Ratio</h3>
                    <div className="ratio-bar-container">
                      <div className="ratio-bar">
                        <div className="ratio-bar-success" style={{ width: `${auditStats.successRate}%` }}></div>
                      </div>
                      <div className="ratio-labels">
                        <span>🟢 Access Approved: {auditStats.successRate}% ({auditStats.successCount})</span>
                        <span>🔴 Attack / Fail Blocked: {auditStats.failRate}% ({auditStats.failCount})</span>
                      </div>
                    </div>
                  </div>

                  <div className="analytics-card glass-panel">
                    <h3 className="text-glow" style={{ fontSize: '1.1rem' }}>Audit Summary</h3>
                    <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '16px' }}>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Total Sessions</div>
                        <div style={{ fontSize: '1.8rem', fontWeight: '800', color: '#fff' }}>{auditStats.total}</div>
                      </div>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Unique Geolocation Nodes</div>
                        <div style={{ fontSize: '1.8rem', fontWeight: '800', color: 'var(--glow-cyan)' }}>
                          {new Set(logs.map(l => getSimulatedLocation(l.ipAddress))).size}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Audit trail list */}
                <div className="logs-card-full glass-panel">
                  <h3 className="text-glow" style={{ fontSize: '1.2rem', marginBottom: '20px' }}>Comprehensive Access Trail</h3>
                  
                  {logs.length === 0 ? (
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No audit history registered.</p>
                  ) : (
                    <div className="log-list-full">
                      {logs.map(log => (
                        <div key={log.id} className={`log-item ${log.success ? 'log-success' : 'log-failure'}`}>
                          <span className="log-icon">{log.success ? '🟢' : '🔴'}</span>
                          <div className="log-content" style={{ width: '100%' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                              <span className="log-title">{log.success ? 'Session Authenticated' : 'Unauthorized Lock Attack Detected'}</span>
                              <span className="log-time">{new Date(log.attemptTime).toLocaleString()}</span>
                            </div>
                            <span className="log-details" style={{ marginTop: '4px', display: 'block' }}>
                              <strong>IP Address:</strong> {log.ipAddress} | <strong>Mapped Geolocation:</strong> {getSimulatedLocation(log.ipAddress)}
                            </span>
                            <span className="log-details" style={{ color: 'var(--text-muted)' }}>
                              <strong>Audit details:</strong> {log.details}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

          </div>
        </main>

        {/* Global Toast */}
        {toastMsg && <div className="toast"><strong>System:</strong> {toastMsg}</div>}
      </div>
    );
  }

  // Auth View (Login / Initialize Vault Screen)
  return (
    <main className="main-container">
      <header className="header">
        <h1 className="logo-glow">Secure Gaze</h1>
        <p className="subtitle">Separated Client & Server Vault</p>
      </header>

      <div className="auth-card glass-panel">
        <div className="tab-group">
          <button 
            type="button" 
            className={`tab-btn ${authMode === 'login' ? 'tab-btn-active' : ''}`}
            onClick={() => setAuthMode('login')}
            disabled={loading}
          >
            Vault Unlock
          </button>
          <button 
            type="button" 
            className={`tab-btn ${authMode === 'register' ? 'tab-btn-active' : ''}`}
            onClick={() => setAuthMode('register')}
            disabled={loading}
          >
            Initialize Vault
          </button>
        </div>

        {error && <div className="alert alert-error"><strong>Alert:</strong> {error}</div>}
        {success && <div className="alert alert-success"><strong>System:</strong> {success}</div>}

        <form onSubmit={handleAuthSubmit}>
          <div className="input-group">
            <label className="input-label" htmlFor="username">Username / Identity</label>
            <input 
              type="text" 
              id="username" 
              className="input-field" 
              placeholder="Enter your security handle"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
              autoComplete="username"
              required
            />
          </div>

          <div className="input-group" style={{ marginBottom: '10px' }}>
            <label className="input-label">Graphical Combination Key</label>
            <SafeDial 
              key={`${authMode}-${dialResetTrigger}`}
              combination={combination}
              onChange={setCombination}
              isRegistering={authMode === 'register'}
            />
          </div>

          <button 
            type="submit" 
            className="btn-neon" 
            style={{ width: '100%', marginTop: '20px' }}
            disabled={loading || !combination.every(v => v !== null)}
          >
            {loading ? 'Decrypting...' : authMode === 'login' ? 'Unlock Vault' : 'Initialize Vault'}
          </button>
        </form>
      </div>

      <footer className="footer-text">
        <span>Restricted Access Module. Relative angular verification in force.</span>
        <br />
        <span style={{ fontSize: '10px', opacity: 0.6 }}>Secure Gaze Encryption (PBKDF2/AES-GCM-256)</span>
      </footer>
    </main>
  );
}
