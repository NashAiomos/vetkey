/**
 * VetKey IBE 文件加密系统
 * 主应用组件
 */

import { useState, useEffect } from 'react';
import authService from './services/auth';
import Login from './components/Login';
import FileEncrypt from './components/FileEncrypt';
import FileDecrypt from './components/FileDecrypt';
import Status from './components/Status';
import { clearVetKeyCache } from './crypto';

function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [status, setStatus] = useState('');
  const [isInitializing, setIsInitializing] = useState(true);

  // 初始化身份验证
  useEffect(() => {
    const initAuth = async () => {
      try {
        const isAuthenticated = await authService.init();
        if (isAuthenticated) {
          const principal = authService.getPrincipal();
          setCurrentUser(principal);
          setStatus(`已自动登录，用户身份: ${principal}`);
        } else {
          setStatus('欢迎使用 VetKey IBE 文件加密系统');
        }
      } catch (error) {
        console.error('初始化错误:', error);
        setStatus('初始化失败，请刷新页面重试');
      } finally {
        setIsInitializing(false);
      }
    };
    
    initAuth();
  }, []);

  // 处理认证状态变化
  const handleAuthChange = (principal) => {
    setCurrentUser(principal);
    if (principal) {
      setStatus(`登录成功！用户身份: ${principal}`);
    } else {
      clearVetKeyCache();
      setStatus('已登出');
    }
  };

  // 安全清理函数
  const handleSecureCleanup = () => {
    // 清除密钥缓存
    clearVetKeyCache();
    
    // 更新状态
    setStatus('✅ 安全清理完成：所有密钥和缓存均已清除。');
  };

  if (isInitializing) {
    return (
      <main>
        <h1>VetKey IBE 文件加密系统</h1>
        <p className="subtitle">正在初始化...</p>
      </main>
    );
  }

  return (
    <main>
      <h1>VetKey IBE 文件加密系统</h1>
      <p className="subtitle">使用身份基加密（IBE）保护您的文件 - 模块化重构版</p>
      
      {/* 身份验证区域 */}
      <Login 
        currentUser={currentUser} 
        onAuthChange={handleAuthChange} 
      />
      
      {/* 文件加密区域 */}
      <FileEncrypt 
        onStatusChange={setStatus} 
      />

      {/* 文件解密区域 */}
      <FileDecrypt 
        onStatusChange={setStatus} 
      />

      {/* 状态显示区域 */}
      <Status status={status} />

      {/* 安全操作区域 */}
      <div className="section cleanup-section">
        <h2>安全操作</h2>
        <button onClick={handleSecureCleanup} className="cleanup-btn">
          🧹 安全清理
        </button>
        <p className="cleanup-info">
          此操作将彻底清除所有缓存的密钥，最大程度确保您的会话安全。
        </p>
      </div>
    </main>
  );
}

export default App;
