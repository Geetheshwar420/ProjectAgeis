import React, { useState } from 'react';
import { Form, Input, Button, message, Card, Typography } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import api from '../utils/api';
import styled from 'styled-components';

const { Title } = Typography;

const AuthWrapper = styled.div`
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    background: #f0f2f5;
`;

const AuthCard = styled(Card)`
    width: 400px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
`;

const Login = () => {
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const onFinish = async (values) => {
        setLoading(true);
        try {
            const response = await api.post('/login', values);
            message.success(response.data.message);
            localStorage.setItem('user', JSON.stringify(response.data.user));
            localStorage.setItem('access_token', response.data.access_token);
            navigate('/chat');
        } catch (error) {
            if (error.response) {
                message.error(error.response.data.error);
            } else {
                message.error('An unexpected error occurred. Please try again later.');
            }
        }
        setLoading(false);
    };

    return (
        <AuthWrapper>
            <AuthCard>
                <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                    <Title level={2}>Login</Title>
                </div>
                <Form
                    name="login"
                    onFinish={onFinish}
                >
                    <Form.Item
                        name="username"
                        rules={[{ required: true, message: 'Please input your username!' }]}
                    >
                        <Input prefix={<UserOutlined />} placeholder="Username" autoComplete="username" />
                    </Form.Item>

                    <Form.Item
                        name="password"
                        rules={[{ required: true, message: 'Please input your password!' }]}
                    >
                        <Input.Password prefix={<LockOutlined />} placeholder="Password" autoComplete="current-password" />
                    </Form.Item>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={loading} style={{ width: '100%' }}>
                            Log in
                        </Button>
                    </Form.Item>
                    <div style={{ textAlign: 'center' }}>
                        Or <Link to="/register">register now!</Link>
                    </div>
                </Form>
            </AuthCard>
        </AuthWrapper>
    );
};

export default Login;