import React, { useState, useEffect } from 'react';
import './App.css';
import axios from 'axios';

function App() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Tester la connexion à l'API
    axios.get('http://localhost:8000/health')
      .then(response => {
        setHealth(response.data);
        setLoading(false);
      })
      .catch(error => {
        console.error('Erreur de connexion à l\'API:', error);
        setLoading(false);
      });
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>🚀 Full-Stack Application</h1>
        <p>FastAPI + React + Docker</p>
        
        <div className="status-card">
          <h2>Status de l'API</h2>
          {loading ? (
            <p>Connexion en cours...</p>
          ) : health ? (
            <div className="success">
              <p>✅ API connectée</p>
              <p>Environment: {health.environment}</p>
              <p>Status: {health.status}</p>
            </div>
          ) : (
            <div className="error">
              <p>❌ Impossible de se connecter à l'API</p>
              <p>Vérifiez que le backend tourne sur http://localhost:8000</p>
            </div>
          )}
        </div>

        <div className="links">
          <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer">
            📚 Documentation API
          </a>
          <a href="http://localhost:3001" target="_blank" rel="noopener noreferrer">
            📊 Grafana
          </a>
          <a href="http://localhost:9090" target="_blank" rel="noopener noreferrer">
            📈 Prometheus
          </a>
        </div>
      </header>
    </div>
  );
}

export default App;