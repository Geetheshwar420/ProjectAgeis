
import React, { useState, useEffect } from 'react';
import { List, Button, message, Typography, Avatar } from 'antd';
import api from '../utils/api';
import styled, { keyframes } from 'styled-components';

const { Title } = Typography;

const fadeIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const FriendRequestContainer = styled.div`
  margin-top: 24px;
  animation: ${fadeIn} 0.5s ease-in-out;
`;

const FriendRequestItem = styled(List.Item)`
  background: #fff;
  border-radius: 8px;
  margin-bottom: 10px;
  padding: 16px;
  box-shadow: 0 2px 5px rgba(0,0,0,0.1);
`;

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
        <FriendRequestContainer>
            <Title level={4}>Friend Requests</Title>
            <List
                dataSource={requests}
                renderItem={item => (
                    <FriendRequestItem
                        actions={[
                            <Button type="primary" onClick={() => handleUpdateRequest(item._id, 'accepted')}>Accept</Button>,
                            <Button type="danger" onClick={() => handleUpdateRequest(item._id, 'rejected')}>Reject</Button>
                        ]}
                    >
                        <List.Item.Meta
                            avatar={<Avatar src={`https://i.pravatar.cc/150?u=${item.requester}`} />}
                            title={item.requester}
                        />
                    </FriendRequestItem>
                )}
            />
        </FriendRequestContainer>
    );
};

export default FriendRequests;

