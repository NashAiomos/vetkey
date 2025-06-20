import { useState, useEffect, useRef } from 'react';
import { vetkey_backend } from 'declarations/vetkey_backend';
import { DerivedPublicKey, TransportSecretKey, EncryptedVetKey } from '@dfinity/vetkeys';
import { 
  generateTransportKey, 
  getVetKey,
  encryptLargeData,
  decryptLargeData,
  generateDataHash,
  clearVetKeyCache
} from './crypto';

function App() {
  const [userId, setUserId] = useState('');
  const [file, setFile] = useState(null);
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [status, setStatus] = useState('');
  const [decryptUserId, setDecryptUserId] = useState('');
  const [encryptedFileToDecrypt, setEncryptedFileToDecrypt] = useState(null);
  const [decryptedFile, setDecryptedFile] = useState(null);

  // Refs for file input elements
  const fileInputRef = useRef(null);
  const encryptedFileInputRef = useRef(null);

  // 处理文件选择
  const handleFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      // 文件大小限制检查（例如：100MB）
      const maxSize = 100 * 1024 * 1024;
      if (selectedFile.size > maxSize) {
        setStatus('文件太大，请选择小于 100MB 的文件');
        return;
      }
      setFile(selectedFile);
      setStatus(`已选择文件: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)`);
    }
  };

  // 加密文件
  const encryptFile = async () => {
    if (!file || !userId) {
      setStatus('请输入用户ID并选择文件');
      return;
    }

    try {
      setStatus('正在准备加密...');

      // 读取文件内容
      const fileContent = await readFileAsArrayBuffer(file);
      
      // 获取或创建传输密钥（会自动缓存）
      const transportSecretKey = generateTransportKey();
      
      setStatus('正在从服务器获取加密密钥...');
      
      // 从后端获取加密的 vetKey
      const encryptedVetKeyBytes = await vetkey_backend.derive_vetkd_key(
        userId,
        Array.from(transportSecretKey.publicKeyBytes())
      );
      
      // 获取公钥用于验证和加密
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      const publicKey = DerivedPublicKey.deserialize(new Uint8Array(publicKeyBytes));
      
      setStatus('正在加密文件...');
      
      // 使用 IBE 混合加密方案加密文件
      const encrypted = await encryptLargeData(
        new Uint8Array(fileContent), 
        userId, 
        publicKey
      );
      
      // 生成文件哈希用于完整性验证
      const fileHash = await generateDataHash(encrypted);
      
      // 创建加密文件对象，包含元数据
      const metadata = {
        originalName: file.name,
        originalSize: file.size,
        encryptedSize: encrypted.length,
        userId: userId,
        timestamp: new Date().toISOString(),
        hash: fileHash,
        encryptionVersion: 'IBE-v1'
      };
      
      // 将元数据添加到加密文件
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const metadataLength = new Uint8Array(4);
      new DataView(metadataLength.buffer).setUint32(0, metadataBytes.length, false);
      
      const finalEncrypted = new Uint8Array(
        4 + metadataBytes.length + encrypted.length
      );
      finalEncrypted.set(metadataLength, 0);
      finalEncrypted.set(metadataBytes, 4);
      finalEncrypted.set(encrypted, 4 + metadataBytes.length);
      
      const encryptedBlob = new Blob([finalEncrypted], { type: 'application/octet-stream' });
      setEncryptedFile({
        blob: encryptedBlob,
        name: `${file.name}.vetkey`,
        metadata: metadata
      });

      setStatus(`文件加密成功！加密后大小: ${(finalEncrypted.length / 1024).toFixed(2)} KB`);
    } catch (error) {
      console.error('加密错误:', error);
      setStatus(`加密失败: ${error.message}`);
    }
  };

  // 下载加密文件
  const downloadEncryptedFile = () => {
    if (!encryptedFile) {
      setStatus('没有可下载的加密文件');
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
    setStatus(`加密文件已下载: ${encryptedFile.name}`);
  };

  // 处理加密文件选择（用于解密）
  const handleEncryptedFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      if (!selectedFile.name.endsWith('.vetkey')) {
        setStatus('请选择 .vetkey 格式的加密文件');
        return;
      }
      setEncryptedFileToDecrypt(selectedFile);
      setStatus(`已选择加密文件: ${selectedFile.name}`);
    }
  };

  // 解密文件
  const decryptFile = async () => {
    if (!encryptedFileToDecrypt || !decryptUserId) {
      setStatus('请输入用户ID并选择加密文件');
      return;
    }

    try {
      setStatus('正在读取加密文件...');

      // 读取加密文件内容
      const encryptedContent = await readFileAsArrayBuffer(encryptedFileToDecrypt);
      const encryptedBytes = new Uint8Array(encryptedContent);
      
      // 提取元数据
      const metadataLength = new DataView(encryptedBytes.buffer, 0, 4).getUint32(0, false);
      const metadataBytes = encryptedBytes.slice(4, 4 + metadataLength);
      const metadata = JSON.parse(new TextDecoder().decode(metadataBytes));
      
      // 验证用户ID
      if (metadata.userId !== decryptUserId) {
        setStatus(`用户ID不匹配。文件是为用户 "${metadata.userId}" 加密的`);
        return;
      }
      
      // 提取实际的加密数据
      const actualEncryptedData = encryptedBytes.slice(4 + metadataLength);
      
      // 验证数据完整性
      const fileHash = await generateDataHash(actualEncryptedData);
      if (fileHash !== metadata.hash) {
        setStatus('文件完整性验证失败，文件可能已损坏或被篡改');
        return;
      }
      
      setStatus('正在获取解密密钥...');
      
      // 获取或创建传输密钥
      const transportSecretKey = generateTransportKey();
      
      // 从后端获取加密的 vetKey
      const encryptedVetKeyBytes = await vetkey_backend.derive_vetkd_key(
        decryptUserId,
        Array.from(transportSecretKey.publicKeyBytes())
      );
      
      // 获取公钥用于验证
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      
      // 获取 VetKey
      const vetKey = getVetKey(
        decryptUserId,
        new Uint8Array(encryptedVetKeyBytes),
        new Uint8Array(publicKeyBytes),
        transportSecretKey
      );
      
      setStatus('正在解密文件...');
      
      // 使用 IBE 解密文件
      const decrypted = await decryptLargeData(actualEncryptedData, vetKey);
      
      // 验证解密后的文件大小
      if (decrypted.length !== metadata.originalSize) {
        console.warn('解密后文件大小不匹配，但继续处理');
      }
      
      // 创建解密文件对象
      const decryptedBlob = new Blob([decrypted], { type: 'application/octet-stream' });
      setDecryptedFile({
        blob: decryptedBlob,
        name: metadata.originalName,
        metadata: metadata
      });

      setStatus(`文件解密成功！原始文件: ${metadata.originalName}`);
    } catch (error) {
      console.error('解密错误:', error);
      
      // 提供更详细的错误信息
      if (error.message.includes('Invalid VetKey') || error.message.includes('VetKey 验证失败')) {
        setStatus(
          '解密失败: VetKey 验证失败。\n' +
          '可能的原因：\n' +
          '1. 用户 ID 不正确\n' +
          '2. 后端服务问题\n' +
          '3. 文件损坏或被篡改\n\n' +
          '请检查用户 ID 是否正确，并确保文件完整性。'
        );
      } else {
        setStatus(`解密失败: ${error.message}`);
      }
    }
  };

  // 下载解密文件
  const downloadDecryptedFile = () => {
    if (!decryptedFile) {
      setStatus('没有可下载的解密文件');
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
    setStatus(`原文件已下载: ${decryptedFile.name}`);
  };

  // 辅助函数：读取文件为 ArrayBuffer
  const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  };

  const handleSecureCleanup = () => {
    // 1. Reset all component state
    setUserId('');
    setFile(null);
    setEncryptedFile(null);
    setDecryptUserId('');
    setEncryptedFileToDecrypt(null);
    setDecryptedFile(null);

    // 2. Clear the in-memory key cache
    clearVetKeyCache();

    // 3. Force-clear the browser's file input controls
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    if (encryptedFileInputRef.current) {
      encryptedFileInputRef.current.value = "";
    }
    
    // 4. Update status to confirm cleanup
    setStatus('✅ 安全清理完成：所有密钥、文件引用和输入均已从浏览器中清除。');
  };

  return (
    <main>
      <h1>VetKey IBE 文件加密系统</h1>
      <p className="subtitle">使用身份基加密（IBE）保护您的文件</p>
      
      <div className="section">
        <h2>文件加密</h2>
        <div className="form-group">
          <label>用户 ID：</label>
          <input
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="输入接收者的用户ID"
          />
        </div>
        <div className="form-group">
          <label>选择文件：</label>
          <input type="file" onChange={handleFileSelect} ref={fileInputRef} />
          <small>最大文件大小: 100MB</small>
        </div>
        <button onClick={encryptFile} disabled={!file || !userId}>
          🔒 加密文件
        </button>
        {encryptedFile && (
          <button onClick={downloadEncryptedFile} className="download-btn">
            ⬇️ 下载加密文件
          </button>
        )}
      </div>

      <div className="section">
        <h2>文件解密</h2>
        <div className="form-group">
          <label>用户 ID：</label>
          <input
            type="text"
            value={decryptUserId}
            onChange={(e) => setDecryptUserId(e.target.value)}
            placeholder="输入您的用户ID"
          />
        </div>
        <div className="form-group">
          <label>选择加密文件：</label>
          <input
            type="file"
            onChange={handleEncryptedFileSelect}
            accept=".vetkey"
            ref={encryptedFileInputRef}
          />
        </div>
        <button onClick={decryptFile} disabled={!encryptedFileToDecrypt || !decryptUserId}>
          🔓 解密文件
        </button>
        {decryptedFile && (
          <button onClick={downloadDecryptedFile} className="download-btn">
            ⬇️ 下载原文件
          </button>
        )}
      </div>

      <div className="status-section">
        <h3>状态</h3>
        <pre className="status-text">{status}</pre>
      </div>

      <div className="section cleanup-section">
        <h2>安全操作</h2>
        <button onClick={handleSecureCleanup} className="cleanup-btn">
          🧹 安全清理
        </button>
        <p className="cleanup-info">
          此操作将彻底清除所有缓存的密钥、重置输入框、状态信息、并移除浏览器对本地文件的引用，最大程度确保您的会话安全。
        </p>
      </div>
    </main>
  );
}

export default App;
