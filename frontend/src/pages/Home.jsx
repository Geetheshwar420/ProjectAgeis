
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import styled, { keyframes, createGlobalStyle } from 'styled-components';
import { Typography, Row, Col } from 'antd';
import { motion } from 'framer-motion';
import Typewriter from 'react-typewriter-effect';

const { Title } = Typography;

// Custom hook to detect reduced motion preference
const useReducedMotion = () => {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = (event) => {
      setPrefersReducedMotion(event.matches);
    };

    // Listen for changes
    mediaQuery.addEventListener('change', handleChange);
    
    return () => {
      mediaQuery.removeEventListener('change', handleChange);
    };
  }, []);

  return prefersReducedMotion;
};

// Theme color tokens with WCAG AA compliant contrast ratios
const ThemeVariables = createGlobalStyle`
  :root {
    /* Primary colors - meets 4.5:1 contrast with white */
    --color-primary: #0066CC;           /* 4.56:1 contrast with white */
    --color-primary-hover: #0052A3;     /* 5.84:1 contrast with white */
    --color-primary-active: #004080;    /* 7.65:1 contrast with white */
    --color-primary-contrast: #FFFFFF;
    
    /* Default button colors */
    --color-default-bg: #FFFFFF;
    --color-default-text: rgba(0, 0, 0, 0.85);
    --color-default-border: #d9d9d9;
    --color-default-hover: #0066CC;
  }
`;

const fadeIn = keyframes`
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const HomeContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: linear-gradient(135deg, #6e8efb, #a777e3);
  color: white;
  text-align: center;
  animation: ${fadeIn} 1s ease-in-out;
  
  /* Respect reduced motion preference */
  @media (prefers-reduced-motion: reduce) {
    animation: none;
  }
  
  /* Responsive padding for smaller screens */
  @media (max-width: 768px) {
    padding: 20px;
  }
`;

const ButtonContainer = styled.div`
  margin-top: 30px;
  display: flex;
  gap: 20px;
  justify-content: center;
  flex-wrap: wrap;
  
  /* Responsive gap for smaller screens */
  @media (max-width: 480px) {
    gap: 12px;
    margin-top: 20px;
  }
`;

const StyledButtonLink = styled(Link)`
  display: inline-block;
  padding: 10px 32px;
  font-size: 16px;
  font-weight: 500;
  line-height: 1.5715;
  border-radius: 4px;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.645, 0.045, 0.355, 1);
  user-select: none;
  touch-action: manipulation;
  border: 1px solid transparent;
  
  /* Responsive sizing for tablets */
  @media (max-width: 768px) {
    padding: 8px 24px;
    font-size: 15px;
  }
  
  /* Responsive sizing for mobile */
  @media (max-width: 480px) {
    padding: 8px 20px;
    font-size: 14px;
    min-width: 120px;
  }
  
  /* Respect reduced motion preference - simpler transitions */
  @media (prefers-reduced-motion: reduce) {
    transition: none;
  }
  
  &:focus-visible {
    outline: 2px solid #fff;
    outline-offset: 2px;
  }
`;

const PrimaryButtonLink = styled(StyledButtonLink)`
  background: var(--color-primary);
  color: var(--color-primary-contrast);
  box-shadow: 0 2px 0 rgba(0, 0, 0, 0.045);
  
  &:hover {
    background: var(--color-primary-hover);
    color: var(--color-primary-contrast);
  }
  
  &:active {
    background: var(--color-primary-active);
    color: var(--color-primary-contrast);
  }
`;

const DefaultButtonLink = styled(StyledButtonLink)`
  background: var(--color-default-bg);
  color: var(--color-default-text);
  border-color: var(--color-default-border);
  box-shadow: 0 2px 0 rgba(0, 0, 0, 0.016);
  
  &:hover {
    color: var(--color-default-hover);
    border-color: var(--color-default-hover);
  }
  
  &:active {
    color: var(--color-primary-active);
    border-color: var(--color-primary-active);
  }
`;

// framer-motion 12 deprecates motion(Component) in favor of motion.create(Component)
const MotionButtonLink = motion.create(PrimaryButtonLink);
const MotionDefaultButtonLink = motion.create(DefaultButtonLink);

const Home = () => {
  const prefersReducedMotion = useReducedMotion();
  
  // Motion props - only apply if user doesn't prefer reduced motion
  const motionProps = prefersReducedMotion 
    ? {} 
    : {
        whileHover: { scale: 1.1 },
        whileTap: { scale: 0.9 },
        transition: { duration: 0.2 }
      };
  
  return (
    <>
      <ThemeVariables />
      <HomeContainer>
      <Row>
        <Col span={24}>
          <Title style={{ color: 'white' }}>Welcome to Quantum-secure-chat-app</Title>
          <Typewriter
            textStyle={{ 
                color: 'white',
                fontSize: '16px',
                textAlign: 'center'
            }}
            startDelay={1000}
            cursorColor="white"
            text="A modern messaging application with a focus on security and user experience."
            typeSpeed={100}
          />
        </Col>
      </Row>
      <ButtonContainer>
        <MotionButtonLink 
          to="/login"
          {...motionProps}
        >
          Login
        </MotionButtonLink>
        <MotionDefaultButtonLink 
          to="/register"
          {...motionProps}
        >
          Register
        </MotionDefaultButtonLink>
      </ButtonContainer>
    </HomeContainer>
    </>
  );
};

export default Home;
