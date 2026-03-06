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
        className={`${sizeClasses[size]} rounded-none object-cover border-2 border-black dark:border-white bg-white dark:bg-black p-0.5`}
      />
      {showStatus && status && (
        <span
          className={`absolute -bottom-1 -right-1 block w-4 h-4 rounded-none border-2 border-black dark:border-white shadow-[2px_2px_0px_#000] dark:shadow-[2px_2px_0px_#fff] ${statusColor[status]} ${status === 'online' ? 'animate-pulse' : ''}`}
        />
      )}
    </div>
  );
};

export default Avatar;