export enum MessageType {
  TEXT = 'text',
  IMAGE = 'image',
  VIDEO = 'video',
  AUDIO = 'audio',
  FILE = 'file',
  SYSTEM = 'system'
}

export enum MessageStatus {
  SENT = 'sent',
  DELIVERED = 'delivered',
  READ = 'read',
  FAILED = 'failed',
  SENDING = 'sending'
}

export interface User {
  id: string;
  name: string;
  username: string;
  avatar: string;
  status: 'online' | 'offline' | 'away' | 'busy';
  bio?: string;
  lastSeen?: string;
  email?: string;
  joinedDate?: string;
  mutualFriends?: number;
}

export interface Reaction {
  emoji: string;
  count: number;
  userReacted: boolean;
}

export interface Message {
  id: string;
  senderId: string;
  content: string;
  type: MessageType;
  timestamp: Date;
  status: MessageStatus;
  mediaUrl?: string;
  fileName?: string;
  fileSize?: string;
  reactions?: Reaction[];
  isEdited?: boolean;
  replyToId?: string;
}

export interface Chat {
  id: string;
  participants: User[];
  messages: Message[];
  unreadCount: number;
  isPinned: boolean;
  isArchived: boolean;
  isMuted: boolean;
  draft?: string;
  typingUsers?: string[]; // IDs of users currently typing
}

export type TabType = 'messages' | 'friends' | 'requests' | 'archived';