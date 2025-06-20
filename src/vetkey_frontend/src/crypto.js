// 使用 Web Crypto API 实现更安全的加密

// 从 vetKey 派生 AES 密钥
export async function deriveAESKey(vetKey) {
  const keyBytes = vetKey.signatureBytes();
  
  // 使用前 32 字节作为 AES-256 密钥材料
  const keyMaterial = keyBytes.slice(0, 32);
  
  // 导入密钥材料
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  
  return cryptoKey;
}

// 加密数据
export async function encryptDataSecure(data, vetKey) {
  const aesKey = await deriveAESKey(vetKey);
  
  // 生成随机 IV (初始化向量)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // 使用 AES-GCM 加密
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    aesKey,
    data
  );
  
  // 将 IV 和加密数据合并（IV 在前，加密数据在后）
  const result = new Uint8Array(iv.length + encryptedData.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encryptedData), iv.length);
  
  return result;
}

// 解密数据
export async function decryptDataSecure(encryptedData, vetKey) {
  const aesKey = await deriveAESKey(vetKey);
  
  // 提取 IV（前 12 字节）
  const iv = encryptedData.slice(0, 12);
  
  // 提取实际的加密数据
  const ciphertext = encryptedData.slice(12);
  
  // 使用 AES-GCM 解密
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    aesKey,
    ciphertext
  );
  
  return new Uint8Array(decryptedData);
}

// 验证数据完整性
export async function verifyDataIntegrity(data, vetKey) {
  try {
    // 尝试使用 vetKey 解密数据
    await decryptDataSecure(data, vetKey);
    return true;
  } catch (error) {
    console.error('数据完整性验证失败:', error);
    return false;
  }
} 