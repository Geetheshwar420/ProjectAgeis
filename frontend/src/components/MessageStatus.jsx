import React from 'react';

// Simple tick icons: single for 'sent', double for 'delivered', double blue for 'read'
const TickIcon = ({ filled = false, color = '#8c8c8c', style = {} }) => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style={style}>
    <path d="M20 6L9 17L4 12" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
);

const DoubleTickIcon = ({ color = '#8c8c8c' }) => (
  <div style={{ display: 'inline-flex', alignItems: 'center' }}>
    <TickIcon color={color} style={{ marginRight: -6, transform: 'scale(0.95)' }} />
    <TickIcon color={color} />
  </div>
);

// status: 'encrypting' | 'sent' | 'delivered' | 'read'
export default function MessageStatus({ status, timestamp }) {
  let content = null;
  let label = '';

  switch (status) {
    case 'encrypting':
      content = <TickIcon color="#bfbfbf" />; // single gray ticking indicates preparing
      label = 'Encrypting…';
      break;
    case 'sent':
      content = <DoubleTickIcon color="#8c8c8c" />; // double gray
      label = 'Sent';
      break;
    case 'delivered':
      content = <DoubleTickIcon color="#8c8c8c" />; // still gray
      label = 'Delivered';
      break;
    case 'read':
      content = <DoubleTickIcon color="#1890ff" />; // blue
      label = 'Read';
      break;
    default:
      content = null;
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#8c8c8c' }}>
      {content}
      {timestamp ? <span>{timestamp}</span> : null}
      <span style={{ display: 'none' }}>{label}</span>
    </span>
  );
}
