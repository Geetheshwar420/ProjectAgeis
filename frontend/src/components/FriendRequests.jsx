import React, { useState, useEffect } from 'react';
import { List, Button, message, Typography } from 'antd';
import api from '../utils/api';

const { Title } = Typography;

const FriendRequests = ({ currentUser }) => {
    const [requests, setRequests] = useState([]);

    useEffect(() => {
        if (currentUser) {
            api.get(`/friend-requests/${currentUser.username}`)
                .then(response => {
                    setRequests(response.data);
                })
                .catch(error => {
                    message.error('Failed to fetch friend requests');
                });
        }
    }, [currentUser]);

    const handleUpdateRequest = async (requestId, status) => {
        try {
            await api.put(`/friend-request/${requestId}`, { status });
            message.success(`Friend request ${status}`);
            setRequests(requests.filter(req => req._id !== requestId));
            if (status === 'accepted') {
                window.dispatchEvent(new Event('friend-request-accepted'));
            }
        } catch (error) {
            message.error('Failed to update friend request');
        }
    };

    return (
        <div style={{ marginTop: '24px' }}>
            <Title level={4}>Friend Requests</Title>
            <List
                dataSource={requests}
                renderItem={item => (
                    <List.Item
                        actions={[
                            <Button type="primary" onClick={() => handleUpdateRequest(item._id, 'accepted')}>Accept</Button>,
                            <Button type="danger" onClick={() => handleUpdateRequest(item._id, 'rejected')}>Reject</Button>
                        ]}
                    >
                        <List.Item.Meta
                            title={item.requester}
                        />
                    </List.Item>
                )}
            />
        </div>
    );
};

export default FriendRequests;
