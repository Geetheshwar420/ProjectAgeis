import React, { useState, useEffect, useRef } from 'react';
import { Layout, Menu, Input, Button, message, Avatar, List } from 'antd';
import { SendOutlined, LockOutlined } from '@ant-design/icons';
import { Modal } from 'antd';
import api from '../utils/api';
import io from 'socket.io-client';
import styled from 'styled-components';
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
`;

const ChatContent = styled(Content)`
    display: flex;
    flex-direction: column;
    padding: 24px;
`;

const MessageList = styled.div`
    flex: 1;
    overflow-y: auto;
    padding: 12px;
`;

const MessageItem = styled.div`
    margin-bottom: 16px;
    display: flex;
    flex-direction: ${props => props.isCurrentUser ? 'row-reverse' : 'row'};
`;

const MessageBubble = styled.div`
    background: ${props => props.isCurrentUser ? '#1890ff' : '#e4e6eb'};
    color: ${props => props.isCurrentUser ? 'white' : 'black'};
    padding: 8px 12px;
    border-radius: 18px;
    max-width: 70%;
`;

const MessageTimestamp = styled.div`
    font-size: 12px;
    color: gray;
    margin-top: 4px;
    text-align: ${props => props.isCurrentUser ? 'right' : 'left'};
`;

const ChatFooter = styled(Footer)`
    background: #fff;
    padding: 12px 24px;
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
        const newSocket = io('http://localhost:5000', {
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
            <ChatSider width={250}>
                <div style={{ padding: '16px', borderBottom: '1px solid #e8e8e8' }}>
                    <Avatar size="large" src={`https://i.pravatar.cc/150?u=${currentUser?.username}`} />
                    <span style={{ marginLeft: '12px', fontWeight: 'bold' }}>{currentUser?.username}</span>
                    <Link to="/profile" style={{ float: 'right' }}>Profile</Link>
                </div>
                <Menu theme="light" mode="inline" onSelect={({ key }) => handleUserSelect(users.find(u => u.username === key))}>
                    {users.map((user) => (
                        <Menu.Item key={user.username}>
                            <Avatar size="small" src={`https://i.pravatar.cc/150?u=${user.username}`} />
                            <span style={{ marginLeft: '8px' }}>{user.username}</span>
                        </Menu.Item>
                    ))}
                </Menu>
                <div style={{ padding: '16px' }}>
                    <Input.Search placeholder="Find users" onSearch={handleSearch} />
                </div>
                <FriendRequests currentUser={currentUser} />
            </ChatSider>
            <Layout>
                {selectedUser ? (
                    <>
                        <Content style={{ display: 'flex', flexDirection: 'column', padding: '24px' }}>
                            <div style={{ borderBottom: '1px solid #e8e8e8', paddingBottom: '12px', marginBottom: '12px' }}>
                                <h2>{selectedUser.username}</h2>
                                {session && <span style={{ color: 'green' }}><LockOutlined /> Secure</span>}
                            </div>
                            <MessageList ref={messageListRef}>
                                {messages.map((msg, index) => (
                                    <MessageItem key={index} isCurrentUser={msg.sender_id === currentUser.username}>
                                        <MessageBubble isCurrentUser={msg.sender_id === currentUser.username}>
                                            {msg.encrypted_message}
                                        </MessageBubble>
                                        <MessageTimestamp isCurrentUser={msg.sender_id === currentUser.username}>
                                            {msg.formatted_timestamp}
                                        </MessageTimestamp>
                                    </MessageItem>
                                ))}
                            </MessageList>
                        </Content>
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
