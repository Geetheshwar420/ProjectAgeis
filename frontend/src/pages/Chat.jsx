import React, { useState, useEffect, useRef } from 'react';
import { Layout, Menu, Input, Button, message, Avatar, List } from 'antd';
import { SendOutlined, LockOutlined } from '@ant-design/icons';
import { Modal } from 'antd';
import api from '../utils/api';
import io from 'socket.io-client';
import styled from 'styled-components';
import { MotiView } from 'moti';
import { Link } from 'react-router-dom';
import FriendRequests from '../components/FriendRequests';

const { Sider, Content, Footer } = Layout;

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
        const token = localStorage.getItem('access_token');
        
        // Dynamically determine the socket URL based on current hostname
        // Uses page's protocol to prevent mixed-content blocking
        const getSocketUrl = () => {
            if (process.env.REACT_APP_API_URL) {
                return process.env.REACT_APP_API_URL;
            }
            
            // Use the page's current protocol to prevent mixed-content blocking
            const protocol = window.location.protocol; // 'http:' or 'https:'
            const hostname = window.location.hostname || 'localhost';
            const port = process.env.REACT_APP_API_PORT || '5000';
            
            // Construct URL avoiding duplicate slashes
            return `${protocol}//${hostname}:${port}`;
        };
        
        const newSocket = io(getSocketUrl(), {
            query: { token }
        });
        setSocket(newSocket);

        newSocket.on('new_friend_request', (data) => {
            message.info(`You have a new friend request from ${data.requester}`);
        });

        return () => {
            newSocket.disconnect();
        };
    }, []);

    useEffect(() => {
        if (socket) {
            socket.on('new_message', async (data) => {
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
        }
    }, [socket, selectedUser, session]);

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
                
                // Fetch message history after session is ready
                const response = await api.get(`/messages?user_a=${currentUser.username}&user_b=${user.username}`);
                
                // Decrypt messages if they have encryption data
                const decryptedMessages = await Promise.all(response.data.map(async (msg) => {
                    if (msg.nonce && msg.tag) {
                        try {
                            const decryptResponse = await api.post('/decrypt', {
                                session_id: qkeResponse.data.session_id,
                                ciphertext: msg.encrypted_message,
                                nonce: msg.nonce,
                                tag: msg.tag
                            });
                            return { ...msg, encrypted_message: decryptResponse.data.plaintext };
                        } catch (err) {
                            console.error('Failed to decrypt message:', err);
                            return { ...msg, encrypted_message: '[Encrypted]' };
                        }
                    }
                    return msg;
                }));
                
                setMessages(decryptedMessages);
            } else {
                message.error('Failed to establish secure session');
            }

        } catch (error) {
            console.error('Error:', error);
            message.error('Failed to fetch message history or establish secure session');
        }
    };

    const handleSendMessage = async () => {
        if (!newMessage.trim() || !selectedUser || !session) return;

        try {
            const encryptResponse = await api.post('/encrypt', {
                session_id: session.session_id,
                message: newMessage
            });

            const signResponse = await api.post('/sign', {
                user_id: currentUser.username,
                message: encryptResponse.data.ciphertext
            });

            const messageData = {
                sender_id: currentUser.username,
                recipient_id: selectedUser.username,
                encrypted_message: encryptResponse.data.ciphertext,
                nonce: encryptResponse.data.nonce,
                tag: encryptResponse.data.tag,
                signature: signResponse.data.signature,
                formatted_timestamp: new Date().toLocaleString()
            };

            socket.emit('send_message', messageData);
            setMessages((prevMessages) => [...prevMessages, { ...messageData, encrypted_message: newMessage }]);
            setNewMessage('');
        } catch (error) {
            message.error('Failed to send message');
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
                        <ChatContent>
                            <MessageList ref={messageListRef}>
                                {messages.map((msg, index) => (
                                    <MotiView
                                        key={msg._id || `${msg.sender_id}-${msg.timestamp || msg.formatted_timestamp}-${index}`}
                                        from={{ opacity: 0, y: 20 }}
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
                                    </MotiView>
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
