/**
 * 登录组件
 * 处理用户认证界面
 */

import React from 'react';
import authService from '../services/auth';

function Login({ currentUser, onAuthChange }) {
  const [isLoading, setIsLoading] = React.useState(false);

  const handleLogin = async () => {
    setIsLoading(true);
    
    await authService.login(
      (principal) => {
        onAuthChange(principal);
        setIsLoading(false);
      },
      (error) => {
        console.error("Login error:", error);
        alert("登录失败，请重试");
        setIsLoading(false);
      }
    );
  };

  const handleLogout = async () => {
    setIsLoading(true);
    await authService.logout();
    onAuthChange(null);
    setIsLoading(false);
  };

  return (
    <div className="section auth-section">
      <h2>身份验证</h2>
      {currentUser ? (
        <div className="user-info">
          <p>已登录用户: <strong>{currentUser}</strong></p>
          <button 
            onClick={handleLogout} 
            className="logout-btn"
            disabled={isLoading}
          >
            {isLoading ? '处理中...' : '🚪 登出'}
          </button>
        </div>
      ) : (
        <div className="login-area">
          <p>请先登录以使用加密功能</p>
          <button 
            onClick={handleLogin} 
            className="login-btn"
            disabled={isLoading}
          >
            {isLoading ? '登录中...' : '🔐 使用 Internet Identity 登录'}
          </button>
        </div>
      )}
    </div>
  );
}

export default Login; 