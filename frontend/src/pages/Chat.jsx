import React, { useState, useEffect, useRef } from 'react';
import { Layout, Menu, Input, Button, message, Avatar, List } from 'antd';
import { SendOutlined, LockOutlined, InfoCircleOutlined } from '@ant-design/icons';
import { Modal } from 'antd';
import api, { getApiBaseUrl } from '../utils/api';
import io from 'socket.io-client';
import styled from 'styled-components';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import FriendRequests from '../components/FriendRequests';

const { Sider, Content, Footer } = Layout;

// Module-level dev flag to avoid hook dependency warnings
const IS_DEV = process.env.NODE_ENV === 'development';

const ChatLayout = styled(Layout)`
    height: 100vh;
    background: #f0f2f5;
`;

const ChatSider = styled(Sider)`
    background: #fff;
    border-right: 1px solid #e8e8e8;
    display: flex;
    flex-direction: column;
`;

const SiderHeader = styled.div`
    padding: 16px;
    border-bottom: 1px solid #e8e8e8;
    display: flex;
    align-items: center;
    justify-content: space-between;
`;

const UserMenu = styled(Menu)`
    flex: 1;
    overflow-y: auto;
`;

const SiderFooter = styled.div`
    padding: 16px;
    border-top: 1px solid #e8e8e8;
`;

const ChatContent = styled(Content)`
    display: flex;
    flex-direction: column;
    background: #fff;
`;

const ChatHeader = styled.div`
    padding: 16px 24px;
    border-bottom: 1px solid #e8e8e8;
    display: flex;
    align-items: center;
    justify-content: space-between;
`;

const MessageList = styled.div`
    flex: 1;
    overflow-y: auto;
    padding: 24px;
`;

const MessageItem = styled.div`
    margin-bottom: 20px;
    display: flex;
    flex-direction: ${props => props.isCurrentUser ? 'row-reverse' : 'row'};
    align-items: flex-end;
`;

const MessageBubble = styled.div`
    background: ${props => props.isCurrentUser ? 'linear-gradient(135deg, #6e8efb, #a777e3)' : '#f0f2f5'};
    color: ${props => props.isCurrentUser ? 'white' : 'black'};
    padding: 12px 16px;
    border-radius: 20px;
    max-width: 70%;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
`;

const MessageTimestamp = styled.div`
    font-size: 12px;
    color: gray;
    margin: 0 10px;
`;

const MessageNotice = styled.div`
    background: #fff7e6;
    border: 1px solid #ffd591;
    padding: 12px 16px;
    margin: 16px 24px 0;
    border-radius: 8px;
    display: flex;
    align-items: center;
    font-size: 13px;
    color: #d48806;
    
    svg {
        margin-right: 8px;
        flex-shrink: 0;
    }
`;

const ChatFooter = styled(Footer)`
    background: #fff;
    padding: 16px 24px;
    border-top: 1px solid #e8e8e8;
`;

const Chat = () => {
    
    const [users, setUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [socket, setSocket] = useState(null);
    const [currentUser, setCurrentUser] = useState(null);
    const [session, setSession] = useState(null);
    const [searchResults, setSearchResults] = useState([]);
    const messageListRef = useRef(null);

    const handleSearch = async (value) => {
        if (!value) return;
        try {
            const response = await api.get('/users');
            const filteredUsers = response.data.filter(user => 
                user.username.toLowerCase().includes(value.toLowerCase()) && 
                user.username !== currentUser.username && 
                !users.some(friend => friend.username === user.username)
            );
            setSearchResults(filteredUsers);
        } catch (error) {
            message.error('Failed to search for users');
        }
    };

    const handleSendFriendRequest = async (recipient) => {
        try {
            await api.post('/friend-request', { recipient });
            message.success('Friend request sent');
            setSearchResults([]);
        } catch (error) {
            message.error('Failed to send friend request');
        }
    };

    useEffect(() => {
        const user = localStorage.getItem('user');
        if (user) {
            setCurrentUser(JSON.parse(user));
        } else {
            window.location.href = '/login';
        }
    }, []);

    useEffect(() => {
        if (currentUser) {
            const fetchFriends = async () => {
                try {
                    const response = await api.get(`/friends/${currentUser.username}`);
                    setUsers(response.data.map(friend => ({ username: friend })));
                } catch (error) {
                    message.error('Failed to fetch friends');
                }
            };
            fetchFriends();

            window.addEventListener('friend-request-accepted', fetchFriends);

            return () => {
                window.removeEventListener('friend-request-accepted', fetchFriends);
            };
        }
    }, [currentUser]);

    useEffect(() => {
        
        // Use the same base URL as Axios for consistency
        const socketUrl = getApiBaseUrl();

        const newSocket = io(socketUrl, {
            withCredentials: true,  // Enables session cookies
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000
        });

        // Track if we've shown the initial connection toast
        let hasShownInitialConnect = false;

        // Define event handlers with stable references for cleanup
        const connectHandler = () => {
            if (!hasShownInitialConnect) {
                // Only show toast on first connection
                if (IS_DEV) {
                    console.log('✅ Socket.IO connected successfully (initial)');
                }
                message.success('Connected to server');
                hasShownInitialConnect = true;
            } else {
                // Subsequent reconnections - log only, no toast
                if (IS_DEV) {
                    console.debug('🔄 Socket.IO reconnected');
                }
            }
        };

        const errorHandler = (error) => {
            console.error('❌ Socket.IO connection error:', error);
            message.error('Failed to connect to server. Please check your connection.');
        };

        const disconnectHandler = (reason) => {
            if (IS_DEV) {
                console.log('Socket.IO disconnected:', reason);
            }
            if (reason === 'io server disconnect' && newSocket.connected === false) {
                // Server disconnected the socket, try to reconnect manually
                message.warning('Disconnected from server. Reconnecting...');
                // Only reconnect if socket instance is still valid
                if (newSocket && !newSocket.connected) {
                    newSocket.connect();
                }
            }
        };

        const friendRequestHandler = (data) => {
            message.info(`You have a new friend request from ${data.requester}`);
        };

        // Register event handlers
        newSocket.on('connect', connectHandler);
        newSocket.on('connect_error', errorHandler);
        newSocket.on('disconnect', disconnectHandler);
        newSocket.on('new_friend_request', friendRequestHandler);

        setSocket(newSocket);

        return () => {
            // Remove all event listeners to prevent memory leaks
            newSocket.off('connect', connectHandler);
            newSocket.off('connect_error', errorHandler);
            newSocket.off('disconnect', disconnectHandler);
            newSocket.off('new_friend_request', friendRequestHandler);
            newSocket.disconnect();
        };
    }, []);

    useEffect(() => {
        if (socket) {
            socket.on('new_message', async (data) => {
                // If this is a message echo for the current user, try to reconcile with optimistic entry
                if (data.sender_id === currentUser?.username) {
                    if (IS_DEV) {
                        console.debug('🔁 Received server echo for own message, attempting reconciliation');
                    }

                    let matched = false;
                    setMessages((prev) => {
                        const idx = prev.findIndex((m) =>
                            m.sender_id === currentUser?.username &&
                            typeof m._id === 'string' && m._id.startsWith('pending-') &&
                            // Correlate by unique crypto fields (signature preferred)
                            (
                                (m.signature && m.signature === data.signature) ||
                                ((m.nonce === data.nonce) && (m.tag === data.tag)) ||
                                (m.encrypted_message === data.encrypted_message)
                            )
                        );

                        if (idx !== -1) {
                            matched = true;
                            const optimistic = prev[idx];
                            const updated = {
                                ...optimistic,
                                // Preserve plaintext already shown; update server-provided ids/metadata
                                _id: data._id,
                                formatted_timestamp: data.formatted_timestamp || optimistic.formatted_timestamp,
                                timestamp: data.timestamp || optimistic.timestamp,
                                // Ensure we keep authoritative crypto metadata from server
                                nonce: data.nonce ?? optimistic.nonce,
                                tag: data.tag ?? optimistic.tag,
                                signature: data.signature ?? optimistic.signature,
                            };
                            const copy = prev.slice();
                            copy[idx] = updated;
                            if (IS_DEV) {
                                console.debug('✅ Reconciled optimistic message with server id:', { temp: optimistic._id, server: data._id });
                            }
                            return copy;
                        }
                        return prev;
                    });

                    // Fallback insert if no matching optimistic message was found (e.g., page reload)
                    if (!matched && (data.sender_id === selectedUser?.username || data.recipient_id === selectedUser?.username)) {
                        try {
                            // Decrypt to keep UI consistent (show plaintext)
                            const decryptResponse = await api.post('/decrypt', {
                                session_id: session.session_id,
                                ciphertext: data.encrypted_message,
                                nonce: data.nonce,
                                tag: data.tag
                            });
                            const decryptedMessage = decryptResponse.data.plaintext;
                            setMessages((prev) => [...prev, { ...data, encrypted_message: decryptedMessage }]);
                        } catch (e) {
                            // As a last resort, append as-is
                            setMessages((prev) => [...prev, data]);
                        }
                    }
                    return; // Done handling own message echo
                }

                // Messages from the other participant in the selected chat
                if (data.sender_id === selectedUser?.username || data.recipient_id === selectedUser?.username) {
                    try {
                        const verifyResponse = await api.post('/verify', {
                            user_id: data.sender_id,
                            message: data.encrypted_message,
                            signature: data.signature
                        });

                        if (verifyResponse.data.signature_valid) {
                            const decryptResponse = await api.post('/decrypt', {
                                session_id: session.session_id,
                                ciphertext: data.encrypted_message,
                                nonce: data.nonce,
                                tag: data.tag
                            });

                            const decryptedMessage = decryptResponse.data.plaintext;

                            setMessages((prevMessages) => [...prevMessages, { ...data, encrypted_message: decryptedMessage }]);
                        } else {
                            message.error('Signature verification failed');
                        }
                    } catch (error) {
                        message.error('Failed to process message');
                    }
                }
            });

            // Listen for message send confirmation
            socket.on('message_sent', (data) => {
                if (IS_DEV) {
                    console.log('✅ Message sent successfully:', data);
                }
                message.success('Message delivered');
            });

            // Listen for message errors from server
            socket.on('message_error', (error) => {
                console.error('❌ Message error from server:', error);
                message.error(error.message || 'Failed to send message');
            });

            return () => {
                socket.off('new_message');
                socket.off('message_sent');
                socket.off('message_error');
            };
        }
    }, [socket, selectedUser, session, currentUser]);

    useEffect(() => {
        if (messageListRef.current) {
            messageListRef.current.scrollTop = messageListRef.current.scrollHeight;
        }
    }, [messages]);

    const handleUserSelect = async (user) => {
        setSelectedUser(user);
        setMessages([]);
        try {
            // Initiate QKE automatically
            const qkeResponse = await api.post('/initiate_qke', {
                user_a: currentUser.username,
                user_b: user.username
            });
            setSession(qkeResponse.data);
            
            if (qkeResponse.data.status === 'ready') {
                message.success('Secure session established');
                // As per product decision, do not fetch or show history; start fresh each session
                setMessages([]);
            } else {
                message.error('Failed to establish secure session');
            }

        } catch (error) {
            console.error('Error:', error);
            message.error('Failed to fetch message history or establish secure session');
        }
    };

    const handleSendMessage = async () => {
        if (IS_DEV) {
            console.log('🔄 Attempting to send message...');
            console.log('   Socket connected:', socket?.connected);
            console.log('   Selected user:', selectedUser?.username);
            console.log('   Session:', session?.session_id);
        }
        
        if (!newMessage.trim() || !selectedUser || !session) {
            if (!newMessage.trim()) {
                message.warning('Please enter a message');
            } else if (!selectedUser) {
                message.warning('Please select a user to chat with');
            } else if (!session) {
                message.error('No secure session established. Please try selecting the user again.');
            }
            return;
        }

        // Check socket connection
        if (!socket || !socket.connected) {
            console.error('❌ Socket not connected');
            message.error('Not connected to server. Please refresh the page and try again.');
            return;
        }

        const messageToSend = newMessage;
        setNewMessage(''); // Clear input immediately for better UX

        try {
            if (IS_DEV) console.log('🧩 Preparing message (encrypt+sign+Kyber package)...');

            // New unified pipeline endpoint: encrypt -> sign -> Kyber package
            const prepared = await api.post('/prepare_message', {
                session_id: session.session_id,
                sender_id: currentUser.username,
                recipient_id: selectedUser.username,
                message: messageToSend
            }).catch(err => {
                console.error('❌ Prepare failed:', err.response?.data || err.message);
                throw new Error(`Prepare failed: ${err.response?.data?.error || err.message}`);
            });

            const messageData = {
                sender_id: currentUser.username,
                recipient_id: selectedUser.username,
                // Kyber envelope fields
                kyber_ct: prepared.data.kyber_ct,
                outer_ciphertext: prepared.data.outer_ciphertext,
                outer_nonce: prepared.data.outer_nonce,
                outer_tag: prepared.data.outer_tag,
                formatted_timestamp: prepared.data.formatted_timestamp
            };

            if (IS_DEV) {
                console.log('📤 Emitting packaged message via Socket.IO...');
            }
            socket.emit('send_message', messageData);
            if (IS_DEV) console.log('✅ Message emitted to server');

            // Optimistically add to local messages (will be confirmed by server)
            // Optimistically add plaintext to UI (server will reconcile id on echo)
            setMessages((prevMessages) => [
                ...prevMessages,
                {
                    _id: 'pending-' + Date.now(),
                    sender_id: currentUser.username,
                    recipient_id: selectedUser.username,
                    encrypted_message: messageToSend,
                    formatted_timestamp: new Date().toLocaleString()
                }
            ]);

        } catch (error) {
            console.error('❌ Failed to send message:', error);
            // Restore the message to input on failure
            setNewMessage(messageToSend);
            message.error(error.message || 'Failed to send message. Please try again.');
        }
    };

    return (
        <ChatLayout>
            <ChatSider width={300}>
                <SiderHeader>
                    <Avatar size="large" src={`https://i.pravatar.cc/150?u=${currentUser?.username}`} />
                    <span style={{ marginLeft: '12px', fontWeight: 'bold' }}>{currentUser?.username}</span>
                    <Link to="/profile">
                        <Button type="text">Profile</Button>
                    </Link>
                </SiderHeader>
                <UserMenu theme="light" mode="inline" onSelect={({ key }) => handleUserSelect(users.find(u => u.username === key))}>
                    {users.map((user) => (
                        <Menu.Item key={user.username}>
                            <Avatar size="small" src={`https://i.pravatar.cc/150?u=${user.username}`} />
                            <span style={{ marginLeft: '8px' }}>{user.username}</span>
                        </Menu.Item>
                    ))}
                </UserMenu>
                <SiderFooter>
                    <Input.Search placeholder="Find users" onSearch={handleSearch} />
                    <FriendRequests currentUser={currentUser} />
                </SiderFooter>
            </ChatSider>
            <Layout>
                {selectedUser ? (
                    <>
                        <ChatHeader>
                            <h2>{selectedUser.username}</h2>
                            {session && <span style={{ color: 'green' }}><LockOutlined /> Secure</span>}
                        </ChatHeader>
                        <MessageNotice>
                            <InfoCircleOutlined />
                            Messages are ephemeral and not stored. Closing or refreshing the chat will clear the conversation history.
                        </MessageNotice>
                        <ChatContent>
                            <MessageList ref={messageListRef}>
                                {messages.map((msg, index) => (
                                    <motion.div
                                        key={msg._id || `${msg.sender_id}-${msg.timestamp || msg.formatted_timestamp}-${index}`}
                                        initial={{ opacity: 0, y: 20 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        transition={{ duration: 0.5 }}
                                    >
                                        <MessageItem isCurrentUser={msg.sender_id === currentUser.username}>
                                            <Avatar src={`https://i.pravatar.cc/150?u=${msg.sender_id}`} />
                                            <MessageBubble isCurrentUser={msg.sender_id === currentUser.username}>
                                                {msg.encrypted_message}
                                            </MessageBubble>
                                            <MessageTimestamp isCurrentUser={msg.sender_id === currentUser.username}>
                                                {msg.formatted_timestamp}
                                            </MessageTimestamp>
                                        </MessageItem>
                                    </motion.div>
                                ))}
                            </MessageList>
                        </ChatContent>
                        <ChatFooter>
                            <div style={{ display: 'flex', gap: '8px' }}>
                                <Input
                                    style={{ flex: 1 }}
                                    value={newMessage}
                                    onChange={(e) => setNewMessage(e.target.value)}
                                    onPressEnter={handleSendMessage}
                                    placeholder="Type a message..."
                                />
                                <Button type="primary" icon={<SendOutlined />} onClick={handleSendMessage} />
                            </div>
                        </ChatFooter>
                    </>
                ) : (
                    <Content style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                        <h2>Select a user to start chatting</h2>
                    </Content>
                )}
            </Layout>
            <Modal
                title="Search Results"
                visible={searchResults.length > 0}
                onCancel={() => setSearchResults([])}
                footer={null}
            >
                <List
                    dataSource={searchResults}
                    renderItem={item => (
                        <List.Item
                            actions={[
                                <Button type="primary" onClick={() => handleSendFriendRequest(item.username)}>Send Request</Button>
                            ]}
                            onClick={() => handleUserSelect(item)}
                        >
                            <List.Item.Meta
                                avatar={<Avatar src={`https://i.pravatar.cc/150?u=${item.username}`} />}
                                title={item.username}
                            />
                        </List.Item>
                    )}
                />
            </Modal>
        </ChatLayout>
    );
};

export default Chat;
