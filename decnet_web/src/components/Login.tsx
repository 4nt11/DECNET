// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useState } from 'react';
import api from '../utils/api';
import './Login.css';
import { Activity } from '../icons';

interface LoginProps {
  onLogin: (token: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [needsPasswordChange, setNeedsPasswordChange] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [tempToken, setTempToken] = useState('');

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await api.post('/auth/login', { username, password });
      const { access_token, must_change_password } = response.data;
      
      if (must_change_password) {
        setTempToken(access_token);
        setNeedsPasswordChange(true);
      } else {
        localStorage.setItem('token', access_token);
        onLogin(access_token);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    setLoading(true);
    setError('');

    try {
      await api.post('/auth/change-password', 
        { old_password: password, new_password: newPassword },
        { headers: { Authorization: `Bearer ${tempToken}` } }
      );
      
      // Re-authenticate to get a fresh token with must_change_password=false
      const response = await api.post('/auth/login', { username, password: newPassword });
      const { access_token } = response.data;
      
      localStorage.setItem('token', access_token);
      onLogin(access_token);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Password change failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <div className="login-header">
          <Activity size={48} className="violet-accent neon-blink" />
          <h1>DECNET</h1>
          <p>AUTHORIZED PERSONNEL ONLY</p>
        </div>
        
        {!needsPasswordChange ? (
          <form onSubmit={handleLoginSubmit} className="login-form">
            <div className="form-group">
              <label>IDENTIFIER</label>
              <input 
                type="text" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
              />
            </div>
            
            <div className="form-group">
              <label>ACCESS KEY</label>
              <input 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                required 
              />
            </div>

            {error && <div className="error-msg">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'VERIFYING...' : 'ESTABLISH CONNECTION'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleChangePasswordSubmit} className="login-form">
            <div className="form-group" style={{ textAlign: 'center', marginBottom: '10px' }}>
              <p className="violet-accent">MANDATORY SECURITY UPDATE</p>
              <p style={{ fontSize: '0.8rem', opacity: 0.7 }}>Please establish a new access key</p>
            </div>
            
            <div className="form-group">
              <label>NEW ACCESS KEY</label>
              <input 
                type="password" 
                value={newPassword} 
                onChange={(e) => setNewPassword(e.target.value)} 
                required 
                minLength={8}
              />
            </div>

            <div className="form-group">
              <label>CONFIRM KEY</label>
              <input 
                type="password" 
                value={confirmPassword} 
                onChange={(e) => setConfirmPassword(e.target.value)} 
                required 
                minLength={8}
              />
            </div>

            {error && <div className="error-msg">{error}</div>}

            <button type="submit" disabled={loading}>
              {loading ? 'UPDATING...' : 'UPDATE SECURE KEY'}
            </button>
          </form>
        )}
        
        <div className="login-footer">
          <span>SECURE PROTOCOL v1.0</span>
        </div>
      </div>
    </div>
  );
};

export default Login;
