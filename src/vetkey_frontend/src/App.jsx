import { useState, useEffect, useRef } from 'react';
import { vetkey_backend } from 'declarations/vetkey_backend';
import { DerivedPublicKey, TransportSecretKey, EncryptedVetKey } from '@dfinity/vetkeys';
import { AuthClient } from "@dfinity/auth-client";
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
  const [currentUser, setCurrentUser] = useState(null);
  const [authClient, setAuthClient] = useState(null);

  // Refs for file input elements
  const fileInputRef = useRef(null);
  const encryptedFileInputRef = useRef(null);

  // 初始化身份验证
  useEffect(() => {
    const initAuth = async () => {
      const client = await AuthClient.create();
      setAuthClient(client);
      
      // 检查是否已经登录
      const isAuthenticated = await client.isAuthenticated();
      if (isAuthenticated) {
        const identity = client.getIdentity();
        const principalId = identity.getPrincipal().toString();
        setCurrentUser(principalId);
        setStatus(`已登录，用户身份: ${principalId}`);
      } else {
        setStatus('请先登录以使用加密功能');
      }
    };
    
    initAuth();
  }, []);

  // 登录函数
  const login = async () => {
    if (!authClient) return;
    
    try {
      setStatus('正在登录...');
      await authClient.login({
        identityProvider: "https://identity.ic0.app",
        onSuccess: () => {
          const identity = authClient.getIdentity();
          const principalId = identity.getPrincipal().toString();
          setCurrentUser(principalId);
          setStatus(`登录成功！用户身份: ${principalId}`);
        },
        onError: (error) => {
          console.error('登录失败:', error);
          setStatus('登录失败，请重试');
        }
      });
    } catch (error) {
      console.error('登录错误:', error);
      setStatus('登录过程中出现错误');
    }
  };

  // 登出函数
  const logout = async () => {
    if (!authClient) return;
    
    await authClient.logout();
    setCurrentUser(null);
    clearVetKeyCache();
    setStatus('已登出');
  };

  // 获取当前用户身份作为加密目标
  const useCurrentUserAsTarget = () => {
    if (currentUser) {
      setUserId(currentUser);
      setStatus(`已设置加密目标为当前用户: ${currentUser}`);
    } else {
      setStatus('请先登录');
    }
  };

  // 获取当前用户身份作为解密身份
  const useCurrentUserForDecrypt = () => {
    if (currentUser) {
      setDecryptUserId(currentUser);
      setStatus(`已设置解密身份为当前用户: ${currentUser}`);
    } else {
      setStatus('请先登录');
    }
  };

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

    if (!currentUser) {
      setStatus('请先登录');
      return;
    }

    try {
      setStatus('正在准备加密...');

      // 读取文件内容
      const fileContent = await readFileAsArrayBuffer(file);
      
      setStatus('正在从服务器获取公钥...');
      
      // 获取系统公钥用于 IBE 加密
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      const publicKey = DerivedPublicKey.deserialize(new Uint8Array(publicKeyBytes));
      
      setStatus('正在加密文件...');
      
      // 使用 IBE 直接为目标用户加密文件
      // 只需要公钥和接收者的用户ID
      const encrypted = await encryptLargeData(
        new Uint8Array(fileContent), 
        userId,  // 接收者的用户ID 
        publicKey  // 系统公钥
      );
      
      // 生成文件哈希用于完整性验证
      const fileHash = await generateDataHash(encrypted);
      
      // 创建加密文件对象，包含元数据
      const metadata = {
        originalName: file.name,
        originalSize: file.size,
        encryptedSize: encrypted.length,
        userId: userId,  // 接收者ID
        encryptedBy: currentUser,  // 记录加密者身份
        timestamp: new Date().toISOString(),
        hash: fileHash,
        encryptionVersion: 'IBE-v2'
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
    if (!encryptedFileToDecrypt) {
      setStatus('请选择加密文件');
      return;
    }

    if (!currentUser) {
      setStatus('请先登录');
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
      
      // 安全检查：验证当前用户是否有权限解密此文件
      // 在新的安全模型中，只有文件的目标用户才能解密
      if (metadata.userId !== currentUser) {
        setStatus(`访问被拒绝：此文件是为用户 "${metadata.userId}" 加密的，您无法解密。`);
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
      
      // 在 IBE 系统中，只有目标用户可以获取解密所需的私钥
      const encryptedVetKeyBytes = await vetkey_backend.derive_vetkd_key(
        currentUser,  // 当前用户只能获取自己的 VetKey
        Array.from(transportSecretKey.publicKeyBytes())
      );
      
      // 获取公钥用于验证
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      
      // 获取当前用户的 VetKey（用于解密发给自己的文件）
      const vetKey = getVetKey(
        currentUser,  // 使用当前用户身份
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
      <p className="subtitle">使用身份基加密（IBE）保护您的文件 - 安全版本</p>
      
      {/* 身份验证区域 */}
      <div className="section auth-section">
        <h2>身份验证</h2>
        {currentUser ? (
          <div className="user-info">
            <p>已登录用户: <strong>{currentUser}</strong></p>
            <button onClick={logout} className="logout-btn">
              🚪 登出
            </button>
          </div>
        ) : (
          <div className="login-area">
            <p>请先登录以使用加密功能</p>
            <button onClick={login} className="login-btn">
              🔐 使用 Internet Identity 登录
            </button>
          </div>
        )}
      </div>
      
      <div className="section">
        <h2>文件加密</h2>
        <div className="info-box">
          <p>🔐 <strong>IBE 加密原理</strong>：使用接收者的身份ID进行加密，只有接收者本人可以解密文件。您可以为任何用户加密文件，但只有目标用户才能解密。</p>
        </div>
        <div className="form-group">
          <label>加密目标用户 ID：</label>
          <input
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="输入接收者的 Principal ID"
            disabled={!currentUser}
          />
          <button 
            onClick={useCurrentUserAsTarget} 
            disabled={!currentUser}
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
            disabled={!currentUser}
          />
          <small>最大文件大小: 100MB</small>
        </div>
        <button onClick={encryptFile} disabled={!file || !userId || !currentUser}>
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
        <div className="info-box">
          <p>🔒 安全提示：只有文件的目标用户才能解密文件。系统会自动验证您的身份。</p>
        </div>
        <div className="form-group">
          <label>选择加密文件：</label>
          <input
            type="file"
            onChange={handleEncryptedFileSelect}
            accept=".vetkey"
            ref={encryptedFileInputRef}
            disabled={!currentUser}
          />
        </div>
        <button onClick={decryptFile} disabled={!encryptedFileToDecrypt || !currentUser}>
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
