import React, { useState, useEffect, useRef } from 'react';
import SafeDial from './components/SafeDial';
import { deriveKey, encryptText, decryptText } from './lib/crypto';
import './App.css';

const API_BASE = 'http://localhost:5000/api';

export default function App() {
  const [view, setView] = useState('auth'); // 'auth' or 'dashboard'
  const [username, setUsername] = useState('');
  const [combination, setCombination] = useState([null, null, null]);
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'register'
  
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [dialResetTrigger, setDialResetTrigger] = useState(0);

  // Dashboard state
  const [currentUser, setCurrentUser] = useState(null);
  const [vaultItems, setVaultItems] = useState([]);
  const [decryptedItems, setDecryptedItems] = useState({});
  const [revealedPasswords, setRevealedPasswords] = useState({});
  const [logs, setLogs] = useState([]);
  const [toastMsg, setToastMsg] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [dashboardLoading, setDashboardLoading] = useState(true);

  // Form state
  const [formName, setFormName] = useState('');
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [formLoading, setFormLoading] = useState(false);
  const [editingId, setEditingId] = useState(null);

  const cryptoKeyRef = useRef(null);

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

      // Fetch vault items and logs
      await Promise.all([
        fetchVaultItems(token),
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

  const decryptAllItems = async (items, key) => {
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

  // -------------------------------------------------------------
  // API Operations
  // -------------------------------------------------------------
  const fetchVaultItems = async (token) => {
    try {
      const res = await fetch(`${API_BASE}/vault`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) throw new Error('Unauthorized');
      const data = await res.json();
      setVaultItems(data.items);
      if (cryptoKeyRef.current) {
        await decryptAllItems(data.items, cryptoKeyRef.current);
      }
    } catch (err) {
      handleLockVault();
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
      await fetchVaultItems(token);
    } catch (err) {
      showToast(`Error: ${err.message}`);
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteItem = async (id) => {
    if (!confirm('Are you sure you want to delete this credential?')) return;
    const token = sessionStorage.getItem('sg_token');

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

  const handleLockVault = () => {
    sessionStorage.clear();
    setView('auth');
    setCurrentUser(null);
    setCombination([null, null, null]);
    setVaultItems([]);
    setDecryptedItems({});
    setRevealedPasswords({});
    setLogs([]);
    setUsername('');
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

  const filteredItems = vaultItems.filter(item => {
    const nameMatch = item.name.toLowerCase().includes(searchQuery.toLowerCase());
    const dec = decryptedItems[item.id] || {};
    const userMatch = dec.username?.toLowerCase().includes(searchQuery.toLowerCase());
    return nameMatch || userMatch;
  });

  // -------------------------------------------------------------
  // Render Views
  // -------------------------------------------------------------
  if (view === 'dashboard') {
    if (dashboardLoading) {
      return (
        <div className="lock-overlay">
          <div className="lock-card glass-panel">
            <h2 className="text-glow" style={{ marginBottom: '15px' }}>Decrypting Vault...</h2>
            <p style={{ color: 'var(--text-secondary)' }}>Deriving cryptographic keys & loading safe items...</p>
          </div>
        </div>
      );
    }

    return (
      <div className="dashboard-container">
        <header className="nav-header">
          <div className="brand">
            <h1 className="brand-title text-glow">Secure Gaze</h1>
            <span className="brand-status">Separate Architecture Vault</span>
          </div>
          
          <div className="nav-controls">
            <div className="user-info">
              <span className="status-indicator"></span>
              <span className="username-display">{currentUser}</span>
            </div>
            <button className="btn-secondary" onClick={handleLockVault} style={{ padding: '8px 16px', fontSize: '0.8rem' }}>
              Lock Vault
            </button>
          </div>
        </header>

        <div className="dashboard-grid">
          {/* Vault CRUD */}
          <div className="main-col">
            
            <div className="form-card glass-panel">
              <h3 className="text-glow" style={{ marginBottom: '20px' }}>
                {editingId ? 'Edit Secret' : 'Encrypt New Secret'}
              </h3>
              
              <form onSubmit={handleAddOrUpdateItem}>
                <div className="form-grid">
                  <div className="input-group">
                    <label className="input-label" htmlFor="serviceName">Service / Website</label>
                    <input 
                      type="text" 
                      id="serviceName" 
                      className="input-field" 
                      placeholder="Google, GitHub, Bank..."
                      value={formName}
                      onChange={(e) => setFormName(e.target.value)}
                      required
                    />
                  </div>
                  
                  <div className="input-group">
                    <label className="input-label" htmlFor="vaultUser">Username / Email</label>
                    <input 
                      type="text" 
                      id="vaultUser" 
                      className="input-field" 
                      placeholder="Username for service"
                      value={formUsername}
                      onChange={(e) => setFormUsername(e.target.value)}
                      required
                    />
                  </div>
                  
                  <div className="input-group">
                    <label className="input-label" htmlFor="vaultPassword">Password</label>
                    <div className="password-field-group">
                      <input 
                        type="text" 
                        id="vaultPassword" 
                        className="input-field" 
                        placeholder="Password or Secret key"
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
                    <label className="input-label" htmlFor="vaultNotes">Notes (Optional)</label>
                    <input 
                      type="text" 
                      id="vaultNotes" 
                      className="input-field" 
                      placeholder="Encrypted notes or pin"
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
                    {formLoading ? 'Saving...' : editingId ? 'Update' : 'Encrypt & Save'}
                  </button>
                </div>
              </form>
            </div>

            {/* List */}
            <div>
              <div className="section-header">
                <h3 className="section-title">Decrypted Credentials</h3>
                <input 
                  type="text" 
                  className="input-field search-bar" 
                  placeholder="Search secrets..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              {filteredItems.length === 0 ? (
                <div className="empty-vault">
                  <span className="empty-icon">🔒</span>
                  <p>No secrets stored matching search queries.</p>
                </div>
              ) : (
                <div className="vault-list">
                  {filteredItems.map(item => {
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
                              <span className="detail-label">Notes</span>
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

          {/* Audit Logs */}
          <div className="logs-col">
            <div className="logs-card glass-panel">
              <h3 className="text-glow" style={{ marginBottom: '20px' }}>Audit Access Logs</h3>
              {logs.length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No access logs registered.</p>
              ) : (
                <div className="log-list">
                  {logs.map(log => (
                    <div key={log.id} className={`log-item ${log.success ? 'log-success' : 'log-failure'}`}>
                      <span className="log-icon">{log.success ? '🟢' : '🔴'}</span>
                      <div className="log-content">
                        <span className="log-title">{log.success ? 'Access Granted' : 'Failed Lock Attempt'}</span>
                        <span className="log-time">{new Date(log.attemptTime).toLocaleString()}</span>
                        <span className="log-details">IP: {log.ipAddress} | {log.details}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {toastMsg && <div className="toast"><strong>System:</strong> {toastMsg}</div>}
      </div>
    );
  }

  // Auth View
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
