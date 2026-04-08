import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

// Global shim to catch "h is not a function" errors from legacy dependencies
if (typeof window !== 'undefined') {
  (window as any).h = React.createElement;
  (window as any).React = React;
}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);