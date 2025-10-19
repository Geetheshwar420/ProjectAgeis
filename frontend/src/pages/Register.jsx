import React, { useState } from 'react';
import { Form, Input, Button, message, Card, Typography } from 'antd';
import { UserOutlined, LockOutlined, MailOutlined } from '@ant-design/icons';
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

const Register = () => {
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const onFinish = async (values) => {
        setLoading(true);
        try {
            const response = await api.post('/register', values);
            message.success(response.data.message);
            navigate('/login');
        } catch (error) {
            if (error.response && error.response.data && error.response.data.error) {
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
                    <Title level={2}>Register</Title>
                </div>
                <Form
                    name="register"
                    onFinish={onFinish}
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

                    <Form.Item
                        name="password"
                        rules={[{ required: true, message: 'Please input your password!' }]}
                    >
                        <Input.Password prefix={<LockOutlined />} placeholder="Password" autoComplete="new-password" />
                    </Form.Item>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={loading} style={{ width: '100%' }}>
                            Register
                        </Button>
                    </Form.Item>
                    <div style={{ textAlign: 'center' }}>
                        Already have an account? <Link to="/login">Log in</Link>
                    </div>
                </Form>
            </AuthCard>
        </AuthWrapper>
    );
};

export default Register;