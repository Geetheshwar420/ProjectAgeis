import React from 'react';
import ReactDOM from 'react-dom/client';

// Production Compatibility: Expose React globally for the "h" shim
// This resolves "h is not a function" in late-loaded dependencies
(window as any).React = React;

import './index.css';
import App from './App';


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