import { useState, useEffect } from 'react';
import Login from './components/Login';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';

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
    <Layout onLogout={handleLogout} onSearch={handleSearch}>
      <Dashboard searchQuery={searchQuery} />
    </Layout>
  );
}

export default App;
