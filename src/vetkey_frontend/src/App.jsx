import { useState } from 'react';
import { vetkey_backend } from 'declarations/vetkey_backend';
import { DerivedPublicKey, TransportSecretKey, EncryptedVetKey } from '@dfinity/vetkeys';
import { encryptDataSecure, decryptDataSecure } from './crypto';

function App() {
  const [userId, setUserId] = useState('');
  const [file, setFile] = useState(null);
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [status, setStatus] = useState('');
  const [decryptUserId, setDecryptUserId] = useState('');
  const [encryptedFileToDecrypt, setEncryptedFileToDecrypt] = useState(null);
  const [decryptedFile, setDecryptedFile] = useState(null);

  // 处理文件选择
  const handleFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setStatus(`已选择文件: ${selectedFile.name}`);
    }
  };

  // 加密文件
  const encryptFile = async () => {
    if (!file || !userId) {
      setStatus('请输入用户ID并选择文件');
      return;
    }

    try {
      setStatus('正在加密文件...');

      // 读取文件内容
      const fileContent = await readFileAsArrayBuffer(file);
      
      // 生成传输密钥对
      const transportSecretKey = TransportSecretKey.random();
      
      // 从后端获取加密的 vetKey
      const encryptedVetKeyBytes = await vetkey_backend.derive_vetkd_key(
        userId,
        Array.from(transportSecretKey.publicKeyBytes())
      );
      const encryptedVetKey = new EncryptedVetKey(new Uint8Array(encryptedVetKeyBytes));

      // 获取公钥用于验证
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      const publicKey = DerivedPublicKey.deserialize(new Uint8Array(publicKeyBytes));

      // 解密并验证 vetKey
      const userIdBytes = new TextEncoder().encode(userId);
      const vetKey = encryptedVetKey.decryptAndVerify(
        transportSecretKey,
        publicKey,
        userIdBytes
      );

      // 使用 vetKey 加密文件内容（使用安全的 AES-GCM 加密）
      const encrypted = await encryptDataSecure(new Uint8Array(fileContent), vetKey);
      
      // 创建加密文件对象
      const encryptedBlob = new Blob([encrypted], { type: 'application/octet-stream' });
      setEncryptedFile({
        blob: encryptedBlob,
        name: `${file.name}.encrypted`,
        userId: userId
      });

      setStatus('文件加密成功！可以下载加密文件了。');
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
    setStatus('加密文件已下载');
  };

  // 处理加密文件选择（用于解密）
  const handleEncryptedFileSelect = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
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
      setStatus('正在解密文件...');

      // 读取加密文件内容
      const encryptedContent = await readFileAsArrayBuffer(encryptedFileToDecrypt);
      
      // 生成传输密钥对
      const transportSecretKey = TransportSecretKey.random();
      
      // 从后端获取加密的 vetKey
      const encryptedVetKeyBytes = await vetkey_backend.derive_vetkd_key(
        decryptUserId,
        Array.from(transportSecretKey.publicKeyBytes())
      );
      const encryptedVetKey = new EncryptedVetKey(new Uint8Array(encryptedVetKeyBytes));

      // 获取公钥用于验证
      const publicKeyBytes = await vetkey_backend.get_vetkd_public_key();
      const publicKey = DerivedPublicKey.deserialize(new Uint8Array(publicKeyBytes));

      // 解密并验证 vetKey
      const userIdBytes = new TextEncoder().encode(decryptUserId);
      const vetKey = encryptedVetKey.decryptAndVerify(
        transportSecretKey,
        publicKey,
        userIdBytes
      );

      // 使用 vetKey 解密文件内容（使用安全的 AES-GCM 解密）
      const decrypted = await decryptDataSecure(new Uint8Array(encryptedContent), vetKey);
      
      // 获取原始文件名
      let originalFileName = encryptedFileToDecrypt.name;
      if (originalFileName.endsWith('.encrypted')) {
        originalFileName = originalFileName.slice(0, -10); // 去掉 '.encrypted'
      }
      
      // 创建解密文件对象
      const decryptedBlob = new Blob([decrypted], { type: 'application/octet-stream' });
      setDecryptedFile({
        blob: decryptedBlob,
        name: originalFileName
      });

      setStatus('文件解密成功！可以下载原文件了。');
    } catch (error) {
      console.error('解密错误:', error);
      setStatus(`解密失败: ${error.message}`);
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
    setStatus('原文件已下载');
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

  return (
    <main>
      <h1>VetKey 文件加密系统</h1>
      
      <div className="section">
        <h2>文件加密</h2>
        <div className="form-group">
          <label>用户 ID：</label>
          <input
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="输入用户ID"
          />
        </div>
        <div className="form-group">
          <label>选择文件：</label>
          <input type="file" onChange={handleFileSelect} />
        </div>
        <button onClick={encryptFile}>加密文件</button>
        {encryptedFile && (
          <button onClick={downloadEncryptedFile}>下载加密文件</button>
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
            placeholder="输入用户ID"
          />
        </div>
        <div className="form-group">
          <label>选择加密文件：</label>
          <input type="file" onChange={handleEncryptedFileSelect} accept=".encrypted" />
        </div>
        <button onClick={decryptFile}>解密文件</button>
        {decryptedFile && (
          <button onClick={downloadDecryptedFile}>下载原文件</button>
        )}
      </div>

      <div className="status">
        <h3>状态：</h3>
        <p>{status}</p>
      </div>
    </main>
  );
}

export default App;
