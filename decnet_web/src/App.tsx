import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import LiveLogs from './components/LiveLogs';
import Attackers from './components/Attackers';
import Config from './components/Config';

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const savedToken = localStorage.getItem('token');
    if (savedToken) {
      setToken(savedToken);
    }
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
          <Route path="/live-logs" element={<LiveLogs />} />
          <Route path="/attackers" element={<Attackers />} />
          <Route path="/config" element={<Config />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;
