
import React, { useState } from 'react';
import { Form, Input, Button, message, Typography } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import api from '../utils/api';
import styled, { keyframes } from 'styled-components';

const { Title } = Typography;

const fadeIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.9);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const LoginContainer = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background: linear-gradient(135deg, #6e8efb, #a777e3);
`;

const LoginForm = styled.div`
  padding: 40px;
  background: white;
  border-radius: 10px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
  width: 400px;
  animation: ${fadeIn} 0.5s ease-in-out;
  text-align: center;
`;

const Login = () => {
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const onFinish = async (values) => {
        setLoading(true);
        try {
            const response = await api.post('/login', values);
            message.success(response.data.message);
            // Store user info in localStorage for convenience
            // The session cookie is automatically handled by the browser
            localStorage.setItem('user', JSON.stringify(response.data.user));
            navigate('/chat');
        } catch (error) {
            if (error.response?.data?.error) {
                message.error(error.response.data.error);
            } else {
                message.error('An unexpected error occurred. Please try again later.');
            }        }
        setLoading(false);
    };

    return (
        <LoginContainer>
            <LoginForm>
                <Title level={2} style={{ marginBottom: '24px' }}>Login</Title>
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
            </LoginForm>
        </LoginContainer>
    );
};

export default Login;
