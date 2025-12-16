import { User, Chat, Message, MessageType, MessageStatus } from './types';

export const CURRENT_USER: User = {
  id: 'me',
  name: 'Alex Rivera',
  username: '@arivera',
  avatar: 'https://picsum.photos/200/200?random=99',
  status: 'online',
  bio: 'Digital nomad & UI Engineer',
  joinedDate: 'Nov 2023',
  email: 'alex@ages.app'
};

export const MOCK_USERS: User[] = [
  {
    id: 'u1',
    name: 'Sarah Chen',
    username: '@sarahc',
    avatar: 'https://picsum.photos/200/200?random=1',
    status: 'online',
    bio: 'Photography enthusiast 📸',
    lastSeen: 'Now',
    mutualFriends: 12
  },
  {
    id: 'u2',
    name: 'Marcus Johnson',
    username: '@mjohnson',
    avatar: 'https://picsum.photos/200/200?random=2',
    status: 'away',
    bio: 'Building the future.',
    lastSeen: '15m ago',
    mutualFriends: 5
  },
  {
    id: 'u3',
    name: 'Elena Rodriguez',
    username: '@elena_rod',
    avatar: 'https://picsum.photos/200/200?random=3',
    status: 'offline',
    bio: 'Coffee and Code ☕️',
    lastSeen: '2h ago',
    mutualFriends: 8
  },
  {
    id: 'u4',
    name: 'David Kim',
    username: '@dkim_dev',
    avatar: 'https://picsum.photos/200/200?random=4',
    status: 'busy',
    bio: 'Do not disturb, coding mode.',
    lastSeen: '1d ago',
    mutualFriends: 3
  },
];

const generateMessages = (count: number, participants: User[]): Message[] => {
  const messages: Message[] = [];
  const now = new Date();
  for (let i = 0; i < count; i++) {
    const isMe = Math.random() > 0.5;
    const sender = isMe ? CURRENT_USER : participants[0];
    messages.push({
      id: `m${i}`,
      senderId: sender.id,
      content: isMe ? `Hey, how are you doing? This is message ${i}` : `I'm good! Just working on the new project. Message ${i}`,
      type: MessageType.TEXT,
      timestamp: new Date(now.getTime() - (count - i) * 1000 * 60 * 60), // Past hours
      status: MessageStatus.READ,
      reactions: Math.random() > 0.8 ? [{ emoji: '👍', count: 1, userReacted: false }] : []
    });
  }
  return messages;
};

export const MOCK_CHATS: Chat[] = MOCK_USERS.map(user => ({
  id: `c_${user.id}`,
  participants: [user],
  messages: generateMessages(15, [user]),
  unreadCount: user.id === 'u1' ? 2 : 0,
  isPinned: user.id === 'u2',
  isArchived: false,
  isMuted: false,
}));

// Add an image message
MOCK_CHATS[0].messages.push({
  id: 'm_img_1',
  senderId: 'u1',
  content: 'Check out this view!',
  type: MessageType.IMAGE,
  mediaUrl: 'https://picsum.photos/600/400?random=10',
  timestamp: new Date(),
  status: MessageStatus.READ
});

// Add a file message
MOCK_CHATS[1].messages.push({
  id: 'm_file_1',
  senderId: 'me',
  content: 'Project Specs',
  type: MessageType.FILE,
  fileName: 'specs_v2.pdf',
  fileSize: '2.4 MB',
  timestamp: new Date(),
  status: MessageStatus.DELIVERED
});
