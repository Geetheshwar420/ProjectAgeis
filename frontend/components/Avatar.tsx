import React from 'react';

interface AvatarProps {
  src: string;
  alt: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  status?: 'online' | 'offline' | 'away' | 'busy';
  className?: string;
  showStatus?: boolean;
}

const Avatar: React.FC<AvatarProps> = ({ 
  src, 
  alt, 
  size = 'md', 
  status, 
  className = '', 
  showStatus = true 
}) => {
  const sizeClasses = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12',
    lg: 'w-14 h-14',
    xl: 'w-24 h-24'
  };

  const statusColor = {
    online: 'bg-green-500',
    offline: 'bg-gray-400',
    away: 'bg-orange-400',
    busy: 'bg-red-500'
  };

  return (
    <div className={`relative inline-block ${className}`}>
      <img
        src={src}
        alt={alt}
        className={`${sizeClasses[size]} rounded-full object-cover border-2 border-white dark:border-slate-800 shadow-sm`}
      />
      {showStatus && status && (
        <span
          className={`absolute bottom-0 right-0 block w-3.5 h-3.5 rounded-full ring-2 ring-white dark:ring-slate-800 ${statusColor[status]} ${status === 'online' ? 'animate-pulse' : ''}`}
        />
      )}
    </div>
  );
};

export default Avatar;