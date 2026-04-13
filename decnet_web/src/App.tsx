import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import DeckyFleet from './components/DeckyFleet';
import LiveLogs from './components/LiveLogs';
import Attackers from './components/Attackers';
import Config from './components/Config';
import Bounty from './components/Bounty';

function isTokenValid(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' && payload.exp * 1000 > Date.now();
  } catch {
    return false;
  }
}

function getValidToken(): string | null {
  const stored = localStorage.getItem('token');
  if (stored && isTokenValid(stored)) return stored;
  if (stored) localStorage.removeItem('token');
  return null;
}

function App() {
  const [token, setToken] = useState<string | null>(getValidToken);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const onAuthLogout = () => setToken(null);
    window.addEventListener('auth:logout', onAuthLogout);
    return () => window.removeEventListener('auth:logout', onAuthLogout);
  }, []);

  const handleLogin = (newToken: string) => {
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Router>
      <Layout onLogout={handleLogout} onSearch={handleSearch}>
        <Routes>
          <Route path="/" element={<Dashboard searchQuery={searchQuery} />} />
          <Route path="/fleet" element={<DeckyFleet />} />
          <Route path="/live-logs" element={<LiveLogs />} />
          <Route path="/bounty" element={<Bounty />} />
          <Route path="/attackers" element={<Attackers />} />
          <Route path="/config" element={<Config />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
