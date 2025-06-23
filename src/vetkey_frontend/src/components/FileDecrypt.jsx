/**
 * 文件解密组件
 */

import React, { useState, useRef } from 'react';
import apiService from '../services/api';
import authService from '../services/auth';
import { generateDataHash } from '../crypto';
import { ENCRYPTED_FILE_EXTENSION } from '../utils/constants';

function FileDecrypt({ onStatusChange }) {
  const [encryptedFileToDecrypt, setEncryptedFileToDecrypt] = useState(null);
  const [decryptedFile, setDecryptedFile] = useState(null);
  const [fileMetadata, setFileMetadata] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [integrityVerified, setIntegrityVerified] = useState(false);
  const encryptedFileInputRef = useRef(null);

  const currentUser = authService.getPrincipal();

  const handleEncryptedFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      if (!selectedFile.name.endsWith(ENCRYPTED_FILE_EXTENSION)) {
        onStatusChange(`请选择 ${ENCRYPTED_FILE_EXTENSION} 格式的加密文件`);
        return;
      }
      setEncryptedFileToDecrypt(selectedFile);
      // 清理之前的状态
      setDecryptedFile(null);
      setFileMetadata(null);
      setIntegrityVerified(false);
      onStatusChange(`已选择加密文件: ${selectedFile.name}`);
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
   * 验证文件完整性
   */
  const verifyFileIntegrity = async (fileData, expectedHash) => {
    try {
      onStatusChange('正在验证文件完整性...');
      const actualHash = await generateDataHash(fileData);
      
      if (actualHash !== expectedHash) {
        setIntegrityVerified(false);
        return {
          verified: false,
          error: '文件完整性验证失败：文件可能已损坏或被篡改'
        };
      }
      
      setIntegrityVerified(true);
      onStatusChange('✅ 文件完整性验证通过');
      return { verified: true };
    } catch (error) {
      setIntegrityVerified(false);
      return {
        verified: false,
        error: `完整性验证失败: ${error.message}`
      };
    }
  };

  /**
   * 验证解密后文件完整性
   */
  const verifyDecryptedIntegrity = async (decryptedData, metadata) => {
    try {
      onStatusChange('正在验证解密文件完整性...');
      
      // 检查文件大小
      if (decryptedData.length !== metadata.originalSize) {
        throw new Error('解密文件大小与预期不符');
      }
      
      // 生成解密文件的哈希（如果元数据中有原始文件哈希）
      if (metadata.originalHash) {
        const decryptedHash = await generateDataHash(decryptedData);
        if (decryptedHash !== metadata.originalHash) {
          throw new Error('解密文件内容验证失败');
        }
      }
      
      onStatusChange('✅ 解密文件完整性验证通过');
      return true;
    } catch (error) {
      throw new Error(`解密文件验证失败: ${error.message}`);
    }
  };

  const decryptFile = async () => {
    if (!encryptedFileToDecrypt) {
      onStatusChange('请选择加密文件');
      return;
    }

    if (!currentUser) {
      onStatusChange('请先登录');
      return;
    }

    setIsProcessing(true);
    setIntegrityVerified(false);
    onStatusChange('正在读取加密文件...');

    try {
      // 读取加密文件内容
      const encryptedContent = await readFileAsArrayBuffer(encryptedFileToDecrypt);
      const encryptedBytes = new Uint8Array(encryptedContent);

      onStatusChange('正在解密文件...');

      // 解密文件
      const result = await apiService.decryptFile(encryptedBytes);
      
      // 保存元数据
      setFileMetadata(result.metadata);

      // 处理API返回的完整性验证结果
      if (result.metadata.integrityVerified === true) {
        setIntegrityVerified(true);
        onStatusChange('✅ 文件完整性验证通过');
      } else if (result.metadata.integrityError) {
        setIntegrityVerified(false);
        onStatusChange(`⚠️ 完整性验证警告: ${result.metadata.integrityError}`);
      }

      // 验证解密后文件完整性
      try {
        await verifyDecryptedIntegrity(result.data, result.metadata);
      } catch (error) {
        // 解密后验证失败时也记录警告但不阻止流程
        console.warn('解密后验证失败:', error);
        onStatusChange(`⚠️ 解密后验证警告: ${error.message}`);
      }

      // 创建解密文件对象
      const decryptedBlob = new Blob([result.data], { type: 'application/octet-stream' });
      setDecryptedFile({
        blob: decryptedBlob,
        name: result.metadata.originalName,
        metadata: result.metadata
      });

      // 根据完整性验证结果显示不同的成功消息
      if (result.metadata.integrityVerified === true) {
        onStatusChange(`✅ 文件解密成功！原始文件: ${result.metadata.originalName}`);
      } else {
        onStatusChange(`⚠️ 文件解密完成，但存在完整性验证警告。原始文件: ${result.metadata.originalName}`);
      }
    } catch (error) {
      console.error('解密错误:', error);
      
      // 提供更详细的错误信息
      if (error.message.includes('访问被拒绝')) {
        onStatusChange(error.message);
      } else if (error.message.includes('Access denied')) {
        onStatusChange(
          '解密失败: 访问被拒绝。\n\n' +
          '由于安全策略，您只能解密为自己加密的文件。\n' +
          '请确保：\n' +
          '1. 您使用正确的身份登录\n' +
          '2. 此文件确实是为您的身份加密的\n\n' +
          `当前登录身份: ${currentUser}`
        );
      } else if (error.message.includes('User not authenticated')) {
        onStatusChange('请先登录后再尝试解密');
      } else {
        onStatusChange(`解密失败: ${error.message}`);
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const downloadDecryptedFile = () => {
    if (!decryptedFile) {
      onStatusChange('没有可下载的解密文件');
      return;
    }

    const url = URL.createObjectURL(decryptedFile.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = decryptedFile.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    onStatusChange(`原文件已下载: ${decryptedFile.name}`);
  };

  const clearState = () => {
    setEncryptedFileToDecrypt(null);
    setDecryptedFile(null);
    setFileMetadata(null);
    setIntegrityVerified(false);
    if (encryptedFileInputRef.current) {
      encryptedFileInputRef.current.value = "";
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
      <h2>文件解密</h2>
      <div className="info-box">
        <p>🔒 <strong>安全提示</strong>：由于安全策略，您只能解密为自己加密的文件。系统会自动验证您的身份与文件目标用户是否匹配。</p>
        <p>🛡️ <strong>完整性保护</strong>：系统会自动验证文件完整性，确保文件未被篡改或损坏。</p>
      </div>
      
      <div className="form-group">
        <label>选择加密文件：</label>
        <input
          type="file"
          onChange={handleEncryptedFileSelect}
          accept={ENCRYPTED_FILE_EXTENSION}
          ref={encryptedFileInputRef}
          disabled={!currentUser || isProcessing}
        />
        <small>只能解密为您自己加密的 {ENCRYPTED_FILE_EXTENSION} 文件</small>
      </div>
      
      <button 
        onClick={decryptFile} 
        disabled={!encryptedFileToDecrypt || !currentUser || isProcessing}
      >
        {isProcessing ? '解密中...' : '🔓 解密文件'}
      </button>
      
      {/* 文件元数据显示 */}
      {fileMetadata && (
        <div className="metadata-section">
          <h3>📋 文件信息</h3>
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
            {fileMetadata.finalEncryptedSize && (
              <div className="metadata-item">
                <strong>最终文件大小：</strong>
                <span>{formatFileSize(fileMetadata.finalEncryptedSize)}</span>
              </div>
            )}
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
            {fileMetadata.integrityError && (
              <div className="metadata-item">
                <strong>完整性问题：</strong>
                <span className="status-error">{fileMetadata.integrityError}</span>
              </div>
            )}
          </div>
        </div>
      )}
      
      {decryptedFile && (
        <button onClick={downloadDecryptedFile} className="download-btn">
          ⬇️ 下载原文件
        </button>
      )}
    </div>
  );
}

export default FileDecrypt; 