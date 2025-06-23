/**
 * 文件加密组件
 */

import React, { useState, useRef } from 'react';
import apiService from '../services/api';
import authService from '../services/auth';
import { generateDataHash } from '../crypto';
import { MAX_FILE_SIZE, ENCRYPTED_FILE_EXTENSION } from '../utils/constants';

function FileEncrypt({ onStatusChange }) {
  const [targetUserId, setTargetUserId] = useState('');
  const [file, setFile] = useState(null);
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [fileMetadata, setFileMetadata] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [integrityVerified, setIntegrityVerified] = useState(false);
  const fileInputRef = useRef(null);

  const currentUser = authService.getPrincipal();

  const handleFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      if (selectedFile.size > MAX_FILE_SIZE) {
        onStatusChange('文件太大，请选择小于 100MB 的文件');
        return;
      }
      setFile(selectedFile);
      // 清理之前的状态
      setEncryptedFile(null);
      setFileMetadata(null);
      setIntegrityVerified(false);
      onStatusChange(`已选择文件: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`);
    }
  };

  const useCurrentUserAsTarget = () => {
    if (currentUser) {
      setTargetUserId(currentUser);
      onStatusChange(`已设置加密目标为当前用户: ${currentUser}`);
    }
  };

  const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  };

  /**
   * 生成原始文件哈希
   */
  const generateOriginalFileHash = async (fileData) => {
    try {
      onStatusChange('正在生成文件完整性哈希...');
      const hash = await generateDataHash(fileData);
      setIntegrityVerified(true);
      onStatusChange('✅ 文件完整性哈希已生成');
      return hash;
    } catch (error) {
      setIntegrityVerified(false);
      throw new Error(`生成文件哈希失败: ${error.message}`);
    }
  };

  /**
   * 验证加密文件完整性
   */
  const verifyEncryptedIntegrity = async (encryptedData, metadata) => {
    try {
      onStatusChange('正在验证加密文件完整性...');
      
      // 检查最终加密文件大小
      const expectedSize = metadata.finalEncryptedSize || encryptedData.length;
      if (encryptedData.length !== expectedSize) {
        throw new Error(`加密文件大小异常：期望 ${expectedSize} 字节，实际 ${encryptedData.length} 字节`);
      }
      
      onStatusChange('✅ 加密文件完整性验证通过');
      return true;
    } catch (error) {
      throw new Error(`加密文件验证失败: ${error.message}`);
    }
  };

  const encryptFile = async () => {
    if (!file || !targetUserId) {
      onStatusChange('请输入目标用户ID并选择文件');
      return;
    }

    if (!currentUser) {
      onStatusChange('请先登录');
      return;
    }

    setIsProcessing(true);
    setIntegrityVerified(false);
    onStatusChange('正在准备加密...');

    try {
      // 读取文件内容
      const fileContent = await readFileAsArrayBuffer(file);
      const fileData = new Uint8Array(fileContent);

      // 生成原始文件哈希
      const originalHash = await generateOriginalFileHash(fileData);

      onStatusChange('正在加密文件...');

      // 加密文件，传递原始文件哈希
      const result = await apiService.encryptFile(fileData, targetUserId, {
        name: file.name,
        size: file.size,
        originalHash: originalHash
      });

      // 保存元数据
      setFileMetadata(result.metadata);

      // 验证加密文件完整性
      await verifyEncryptedIntegrity(result.data, result.metadata);

      // 创建加密文件对象
      const encryptedBlob = new Blob([result.data], { type: 'application/octet-stream' });
      setEncryptedFile({
        blob: encryptedBlob,
        name: `${file.name}${ENCRYPTED_FILE_EXTENSION}`,
        metadata: result.metadata
      });

      onStatusChange(`✅ 文件加密成功！加密后大小: ${(result.data.length / 1024).toFixed(2)} KB`);
    } catch (error) {
      console.error('加密错误:', error);
      if (error.message.includes('完整性') || error.message.includes('哈希')) {
        onStatusChange(`🚨 安全警告: ${error.message}`);
      } else {
        onStatusChange(`加密失败: ${error.message}`);
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const downloadEncryptedFile = () => {
    if (!encryptedFile) {
      onStatusChange('没有可下载的加密文件');
      return;
    }

    const url = URL.createObjectURL(encryptedFile.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = encryptedFile.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    onStatusChange(`加密文件已下载: ${encryptedFile.name}`);
  };

  const clearState = () => {
    setTargetUserId('');
    setFile(null);
    setEncryptedFile(null);
    setFileMetadata(null);
    setIntegrityVerified(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // 格式化文件大小
  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // 格式化时间戳
  const formatTimestamp = (timestamp) => {
    if (!timestamp) return '未知';
    return new Date(Number(timestamp) / 1000000).toLocaleString('zh-CN');
  };

  // 当组件卸载或用户登出时清理状态
  React.useEffect(() => {
    if (!currentUser) {
      clearState();
    }
  }, [currentUser]);

  return (
    <div className="section">
      <h2>文件加密</h2>
      <div className="info-box">
        <p>🔐 <strong>IBE 加密原理</strong>：使用接收者的身份ID进行加密，只有接收者本人可以解密文件。您可以为任何用户加密文件，但只有目标用户才能解密。</p>
        <p>🛡️ <strong>完整性保护</strong>：系统会自动生成文件哈希，确保加密过程中文件完整性不被破坏。</p>
      </div>
      
      <div className="form-group">
        <label>加密目标用户 ID：</label>
        <input
          type="text"
          value={targetUserId}
          onChange={(e) => setTargetUserId(e.target.value)}
          placeholder="输入接收者的 Principal ID"
          disabled={!currentUser || isProcessing}
        />
        <button 
          onClick={useCurrentUserAsTarget} 
          disabled={!currentUser || isProcessing}
          className="helper-btn"
        >
          使用当前用户
        </button>
      </div>
      
      <div className="form-group">
        <label>选择文件：</label>
        <input 
          type="file" 
          onChange={handleFileSelect} 
          ref={fileInputRef} 
          disabled={!currentUser || isProcessing}
        />
        <small>最大文件大小: 100MB</small>
      </div>
      
      <button 
        onClick={encryptFile} 
        disabled={!file || !targetUserId || !currentUser || isProcessing}
      >
        {isProcessing ? '加密中...' : '🔒 加密文件'}
      </button>
      
      {/* 文件元数据显示 */}
      {fileMetadata && (
        <div className="metadata-section">
          <h3>📋 加密信息</h3>
          <div className="metadata-grid">
            <div className="metadata-item">
              <strong>原始文件名：</strong>
              <span>{fileMetadata.originalName}</span>
            </div>
            <div className="metadata-item">
              <strong>原始大小：</strong>
              <span>{formatFileSize(fileMetadata.originalSize)}</span>
            </div>
            <div className="metadata-item">
              <strong>纯加密数据大小：</strong>
              <span>{formatFileSize(fileMetadata.encryptedSize)}</span>
            </div>
            <div className="metadata-item">
              <strong>最终文件大小：</strong>
              <span>{formatFileSize(fileMetadata.finalEncryptedSize || fileMetadata.encryptedSize)}</span>
            </div>
            <div className="metadata-item">
              <strong>目标用户：</strong>
              <span>{fileMetadata.userId}</span>
            </div>
            <div className="metadata-item">
              <strong>加密时间：</strong>
              <span>{formatTimestamp(fileMetadata.timestamp)}</span>
            </div>
            <div className="metadata-item">
              <strong>加密版本：</strong>
              <span>{fileMetadata.encryptionVersion || 'IBE-v1'}</span>
            </div>
            <div className="metadata-item">
              <strong>完整性验证：</strong>
              <span className={integrityVerified ? 'status-success' : 'status-pending'}>
                {integrityVerified ? '✅ 已验证' : '⏳ 待验证'}
              </span>
            </div>
            {fileMetadata.hash && (
              <div className="metadata-item">
                <strong>文件哈希：</strong>
                <span className="hash-display">{fileMetadata.hash.substring(0, 16)}...</span>
              </div>
            )}
          </div>
        </div>
      )}
      
      {encryptedFile && (
        <button onClick={downloadEncryptedFile} className="download-btn">
          ⬇️ 下载加密文件
        </button>
      )}
    </div>
  );
}

export default FileEncrypt; 