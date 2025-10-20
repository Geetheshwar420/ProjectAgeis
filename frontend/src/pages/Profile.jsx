
import React, { useState, useEffect } from 'react';
import { Form, Input, Button, message, Typography, Popconfirm, Modal } from 'antd';
import { UserOutlined, MailOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';
import FriendRequests from '../components/FriendRequests';
import styled from 'styled-components';
import { motion } from 'framer-motion';

const { Title } = Typography;

const ProfileContainer = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: center;
  min-height: 100vh;
  padding: 40px 20px;
  background: linear-gradient(135deg, #6e8efb, #a777e3);
`;

const ProfileForm = styled.div`
  padding: 40px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
  width: 500px;
  text-align: center;
`;

const FriendRequestsWrapper = styled.div`
  margin-top: 30px;
  width: 500px;
  max-width: 100%;
`;

const Profile = () => {
    const [loading, setLoading] = useState(false);
    const [user, setUser] = useState(null);
    const [isPasswordModalVisible, setIsPasswordModalVisible] = useState(false);
    const [form] = Form.useForm();
    const navigate = useNavigate();

    useEffect(() => {
        const currentUser = JSON.parse(localStorage.getItem('user'));
        if (currentUser) {
            api.get(`/user/${currentUser.username}`)
                .then(response => {
                    setUser(response.data);
                    form.setFieldsValue(response.data);
                })
                .catch(error => {
                    message.error('Failed to fetch user data');
                });
        } else {
            navigate('/login');
        }
    }, [form, navigate]);

    const onFinish = async (values) => {
        setLoading(true);
        try {
            const response = await api.put(`/user/${user.username}`, values);
            message.success(response.data.message);
            localStorage.setItem('user', JSON.stringify(values));
            setUser(values);
        } catch (error) {
            if (error.response && error.response.data && error.response.data.error) {
                message.error(error.response.data.error);
            } else {
                message.error('Failed to update profile');
            }
        }
        setLoading(false);
    };

    const handleLogout = () => {
        localStorage.removeItem('user');
        localStorage.removeItem('token');
        navigate('/login');
    };

    const handleDelete = async () => {
        try {
            await api.delete(`/user/${user.username}`);
            message.success('Account deleted successfully');
            localStorage.removeItem('user');
            localStorage.removeItem('access_token');
            navigate('/login');
        } catch (error) {
            message.error('Failed to delete account');
        }
    };

    const handlePasswordChange = async (values) => {
        try {
            await api.put(`/user/${user.username}/password`, values);
            message.success('Password updated successfully');
            setIsPasswordModalVisible(false);
        } catch (error) {
            if (error.response && error.response.data && error.response.data.error) {
                message.error(error.response.data.error);
            } else {
                message.error('Failed to update password');
            }
        }
    };

    return (
        <ProfileContainer>
            <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5 }}
            >
                <ProfileForm>
                    <Title level={2} style={{ marginBottom: '24px' }}>User Profile</Title>
                    {user && (
                        <Form
                            form={form}
                            name="profile"
                            onFinish={onFinish}
                            initialValues={user}
                        >
                            <Form.Item
                                name="username"
                                rules={[{ required: true, message: 'Please input your username!' }]}
                            >
                                <Input prefix={<UserOutlined />} placeholder="Username" autoComplete="username" />
                            </Form.Item>

                            <Form.Item
                                name="email"
                                rules={[{ required: true, type: 'email', message: 'Please input a valid email!' }]}
                            >
                                <Input prefix={<MailOutlined />} placeholder="Email" autoComplete="email" />
                            </Form.Item>

                            <Form.Item>
                                <Button type="primary" htmlType="submit" loading={loading} style={{ width: '100%' }}>
                                    Update Profile
                                </Button>
                            </Form.Item>

                            <Form.Item>
                                <Button type="default" onClick={() => setIsPasswordModalVisible(true)} style={{ width: '100%' }}>
                                    Change Password
                                </Button>
                            </Form.Item>

                            <Form.Item>
                                <Button type="default" onClick={handleLogout} style={{ width: '100%' }}>
                                    Logout
                                </Button>
                            </Form.Item>

                            <Form.Item>
                                <Popconfirm
                                    title="Are you sure you want to delete your account?"
                                    onConfirm={handleDelete}
                                    okText="Yes"
                                    cancelText="No"
                                >
                                    <Button type="danger" style={{ width: '100%' }}>
                                        Delete Account
                                    </Button>
                                </Popconfirm>
                            </Form.Item>
                        </Form>
                    )}
                </ProfileForm>
            </motion.div>
            <FriendRequestsWrapper>
                <FriendRequests currentUser={user} />
            </FriendRequestsWrapper>
            <Modal
                title="Change Password"
                visible={isPasswordModalVisible}
                onCancel={() => setIsPasswordModalVisible(false)}
                footer={null}
            >
                <Form onFinish={handlePasswordChange}>
                    <Form.Item
                        name="old_password"
                        rules={[{ required: true, message: 'Please input your old password!' }]}
                    >
                        <Input.Password placeholder="Old Password" autoComplete="current-password" />
                    </Form.Item>
                    <Form.Item
                        name="new_password"
                        rules={[{ required: true, message: 'Please input your new password!' }]}
                    >
                        <Input.Password placeholder="New Password" autoComplete="new-password" />
                    </Form.Item>
                    <Form.Item
                        name="confirm_new_password"
                        dependencies={['new_password']}
                        hasFeedback
                        rules={[
                            { required: true, message: 'Please confirm your new password!' },
                            ({ getFieldValue }) => ({
                                validator(_, value) {
                                    if (!value || getFieldValue('new_password') === value) {
                                        return Promise.resolve();
                                    }
                                    return Promise.reject(new Error('The two passwords that you entered do not match!'));
                                },
                            }),
                        ]}
                    >
                        <Input.Password placeholder="Confirm New Password" autoComplete="new-password" />
                    </Form.Item>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" style={{ width: '100%' }}>
                            Update Password
                        </Button>
                    </Form.Item>
                </Form>
            </Modal>
        </ProfileContainer>
    );
};

export default Profile;

