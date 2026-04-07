import React, { useState } from 'react';
import api from '../utils/api';
import './Login.css';
import { Activity } from 'lucide-react';

interface LoginProps {
  onLogin: (token: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await api.post('/auth/login', { username, password });
      const { access_token } = response.data;
      localStorage.setItem('token', access_token);
      onLogin(access_token);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed');
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
        
        <form onSubmit={handleSubmit} className="login-form">
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
        
        <div className="login-footer">
          <span>SECURE PROTOCOL v1.0</span>
        </div>
      </div>
    </div>
  );
};

export default Login;
