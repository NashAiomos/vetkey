// 使用 Web Crypto API 实现更安全的加密

import {
  TransportSecretKey,
  DerivedPublicKey,
  EncryptedVetKey,
  VetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
} from "@dfinity/vetkeys";

/**
 * VetKeys IBE 加密模块 - 提供安全的身份基加密功能
 * 
 * 安全特性：
 * 1. 使用 IBE (Identity-Based Encryption) 进行端到端加密
 * 2. 自动处理密钥派生和验证
 * 3. 提供完整性验证
 * 4. 支持安全的密钥存储和管理
 */

// 密钥缓存 - 用于优化性能，避免重复解密
const keyCache = new Map();

// 域分离器 - 必须与后端保持一致
const BACKEND_DOMAIN_SEPARATOR = "zCloak-KYC-vetkey-app-zzx777593gcaatys7824k77g9ryxv78td5g6sh";

/**
 * 生成传输密钥
 * 传输密钥每次都重新生成，用于安全传输 VetKey
 */
export function generateTransportKey() {
  return TransportSecretKey.random();
}

/**
 * 清除 VetKey 缓存（用于登出或安全清理）
 */
export function clearVetKeyCache() {
  keyCache.clear();
}

/**
 * 获取派生的 VetKey
 * @param {string} userId - 用户标识符
 * @param {Uint8Array} encryptedVetKeyBytes - 从后端获取的加密 VetKey
 * @param {Uint8Array} publicKeyBytes - 公钥字节
 * @param {TransportSecretKey} transportSecretKey - 传输密钥（与获取encryptedVetKeyBytes时使用的相同）
 * @returns {VetKey} 解密并验证的 VetKey
 */
export function getVetKey(userId, encryptedVetKeyBytes, publicKeyBytes, transportSecretKey) {
  // 检查缓存
  const cacheKey = `${userId}-${btoa(String.fromCharCode(...encryptedVetKeyBytes.slice(0, 8)))}`;
  if (keyCache.has(cacheKey)) {
    return keyCache.get(cacheKey);
  }
  
  try {
    // 反序列化公钥和加密的VetKey
    const publicKey = DerivedPublicKey.deserialize(publicKeyBytes);
    const encryptedVetKey = new EncryptedVetKey(encryptedVetKeyBytes);
    
    // 使用与后端加密时一致的纯用户ID作为身份
    const userIdBytes = new TextEncoder().encode(userId);
    
    // 直接使用已知正确的身份格式进行解密
    const vetKey = encryptedVetKey.decryptAndVerify(
      transportSecretKey,
      publicKey,
      userIdBytes
    );
    
    // 缓存解密的密钥（限制缓存大小）
    if (keyCache.size > 100) {
      const firstKey = keyCache.keys().next().value;
      keyCache.delete(firstKey);
    }
    keyCache.set(cacheKey, vetKey);
    
    return vetKey;
    
  } catch (error) {
    console.error('VetKey 解密失败:', error.message);
    // 抛出更具体的错误信息
    throw new Error(`VetKey 验证失败: ${error.message}. 请确保用户ID正确.`);
  }
}

/**
 * 使用 IBE 加密数据
 * @param {Uint8Array} data - 要加密的数据
 * @param {string} userId - 接收者的用户ID
 * @param {DerivedPublicKey} publicKey - 派生公钥
 * @returns {Promise<Uint8Array>} 加密后的数据
 */
export async function encryptWithIBE(data, userId, publicKey) {
  try {
    // 使用纯用户 ID 作为身份（与后端 VetKey 生成时的 input 参数一致）
    const userIdBytes = new TextEncoder().encode(userId);
    
    // 创建 IBE 身份
    const identity = IbeIdentity.fromBytes(userIdBytes);
    
    // 生成随机种子
    const seed = IbeSeed.random();
    
    // 执行 IBE 加密
    const ciphertext = IbeCiphertext.encrypt(
      publicKey,
      identity,
      data,
      seed
    );
    
    // 序列化密文
    const serialized = ciphertext.serialize();
    
    // 添加版本和元数据头部（便于未来升级）
    const VERSION = 1;
    const header = new Uint8Array([VERSION]);
    const result = new Uint8Array(header.length + serialized.length);
    result.set(header, 0);
    result.set(serialized, header.length);
    
    return result;
  } catch (error) {
    console.error('IBE 加密失败:', error);
    throw new Error(`IBE 加密失败: ${error.message}`);
  }
}

/**
 * 使用 IBE 解密数据
 * @param {Uint8Array} encryptedData - 加密的数据
 * @param {VetKey} vetKey - 用于解密的 VetKey
 * @returns {Promise<Uint8Array>} 解密后的数据
 */
export async function decryptWithIBE(encryptedData, vetKey) {
  try {
    // 检查版本
    if (encryptedData[0] !== 1) {
      throw new Error('不支持的加密版本');
    }
    
    // 提取实际的密文（跳过版本字节）
    const ciphertextBytes = encryptedData.slice(1);
    
    // 反序列化密文
    const ciphertext = IbeCiphertext.deserialize(ciphertextBytes);
    
    // 执行 IBE 解密
    const decrypted = ciphertext.decrypt(vetKey);
    
    return new Uint8Array(decrypted);
  } catch (error) {
    console.error('IBE 解密失败:', error);
    throw new Error(`解密失败: ${error.message}`);
  }
}

/**
 * 生成数据哈希（用于完整性验证）
 */
export async function generateDataHash(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

