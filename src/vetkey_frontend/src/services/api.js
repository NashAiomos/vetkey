/**
 * API 服务模块: 处理与后端 canister 的所有交互
 * - 所有后端调用前都会验证用户认证状态
 * - 每次调用都创建新的 Actor 以确保使用最新身份
 * - 封装了加密和解密的复杂逻辑
 */

import { idlFactory, canisterId } from '../../../declarations/vetkey_backend';
import authService from './auth';
import { DerivedPublicKey } from '@dfinity/vetkeys';
import { 
  generateTransportKey, 
  getVetKey,
  encryptWithIBE,
  decryptWithIBE,
  generateDataHash
} from '../crypto';

class ApiService {
  constructor() {
    this.actor = null;
  }

  /**
   * 获取已认证的 Actor
   * 确保每次调用都使用最新的认证身份
   */
  async getActor() {
    if (!authService.checkAuthentication()) {
      throw new Error("User not authenticated. Please login first.");
    }

    // 总是创建新的 actor 以确保使用最新的身份
    this.actor = authService.createActor(canisterId, idlFactory);
    return this.actor;
  }

  /**
   * 获取 VetKD 公钥
   */
  async getVetKDPublicKey() {
    try {
      const actor = await this.getActor();
      const publicKeyBytes = await actor.get_vetkd_public_key();
      return new Uint8Array(publicKeyBytes);
    } catch (error) {
      console.error("Failed to get VetKD public key:", error);
      throw new Error(`获取公钥失败: ${error.message}`);
    }
  }

  /**
   * 派生 VetKD 密钥
   * @param {string} userId - 用户 ID（必须与当前登录用户匹配）
   * @param {Uint8Array} transportPublicKey - 传输公钥
   */
  async deriveVetKDKey(userId, transportPublicKey) {
    try {
      const actor = await this.getActor();
      
      // 验证请求的 userId 是否与当前用户匹配
      const currentPrincipal = authService.getPrincipal();
      if (userId !== currentPrincipal) {
        throw new Error(`访问被拒绝: 只能获取自己的 VetKey。当前用户: ${currentPrincipal}, 请求的用户: ${userId}`);
      }

      const encryptedVetKeyBytes = await actor.derive_vetkd_key(
        userId,
        Array.from(transportPublicKey)
      );
      
      return new Uint8Array(encryptedVetKeyBytes);
    } catch (error) {
      console.error("Failed to derive VetKD key:", error);
      
      if (error.message.includes("Access denied")) {
        throw new Error("访问被拒绝: 您只能获取自己的 VetKey。请确保使用正确的身份登录。");
      }
      
      throw new Error(`派生密钥失败: ${error.message}`);
    }
  }

  /**
   * 加密文件
   * @param {Uint8Array} fileData - 文件数据
   * @param {string} targetUserId - 目标用户 ID
   * @param {Object} fileInfo - 文件信息（包含 name, size, originalHash）
   */
  async encryptFile(fileData, targetUserId, fileInfo) {
    try {
      // 获取公钥
      const publicKeyBytes = await this.getVetKDPublicKey();
      const publicKey = DerivedPublicKey.deserialize(publicKeyBytes);
      
      // 使用 IBE 加密文件
      const encrypted = await encryptWithIBE(fileData, targetUserId, publicKey);
      
      // 生成加密文件哈希
      const encryptedFileHash = await generateDataHash(encrypted);
      
      // 创建元数据
      const metadata = {
        originalName: fileInfo.name,
        originalSize: fileInfo.size,
        encryptedSize: encrypted.length,
        userId: targetUserId,
        encryptedBy: authService.getPrincipal(),
        timestamp: Date.now() * 1000000, // 转换为纳秒时间戳
        hash: encryptedFileHash, // 加密文件的哈希
        originalHash: fileInfo.originalHash || null, // 原始文件的哈希
        encryptionVersion: 'IBE-v1'
      };
      
      // 序列化元数据（使用稳定的JSON序列化）
      const metadataStr = JSON.stringify(metadata, Object.keys(metadata).sort());
      const metadataBytes = new TextEncoder().encode(metadataStr);
      const metadataLength = new Uint8Array(4);
      new DataView(metadataLength.buffer).setUint32(0, metadataBytes.length, false);
      
      // 组合最终的加密文件
      const finalEncrypted = new Uint8Array(
        4 + metadataBytes.length + encrypted.length
      );
      finalEncrypted.set(metadataLength, 0);
      finalEncrypted.set(metadataBytes, 4);
      finalEncrypted.set(encrypted, 4 + metadataBytes.length);
      
      // 更新元数据中的最终文件大小
      metadata.finalEncryptedSize = finalEncrypted.length;
      
      console.log('Encryption debug info:', {
        originalSize: fileInfo.size,
        encryptedSize: encrypted.length,
        metadataSize: metadataBytes.length,
        finalSize: finalEncrypted.length,
        expectedHash: metadata.hash
      });
      
      return {
        data: finalEncrypted,
        metadata: metadata
      };
    } catch (error) {
      console.error("Encryption error:", error);
      throw new Error(`加密失败: ${error.message}`);
    }
  }

  /**
   * 解密文件
   * @param {Uint8Array} encryptedData - 加密的文件数据
   */
  async decryptFile(encryptedData) {
    let integrityVerified = false;
    let integrityError = null;
    
    try {
      // 提取元数据
      const metadataLength = new DataView(encryptedData.buffer, 0, 4).getUint32(0, false);
      const metadataBytes = encryptedData.slice(4, 4 + metadataLength);
      const metadata = JSON.parse(new TextDecoder().decode(metadataBytes));
      
      // 验证权限
      const currentPrincipal = authService.getPrincipal();
      if (metadata.userId !== currentPrincipal) {
        throw new Error(
          `访问被拒绝：此文件是为用户 "${metadata.userId}" 加密的，` +
          `而您当前的身份是 "${currentPrincipal}"。`
        );
      }
      
      // 提取加密数据
      const actualEncryptedData = encryptedData.slice(4 + metadataLength);
      
      // 验证完整性（不阻止解密过程）
      try {
        if (metadata.hash) {
          const fileHash = await generateDataHash(actualEncryptedData);
          if (fileHash !== metadata.hash) {
            integrityError = '文件完整性验证失败，文件可能已损坏或被篡改';
            console.warn('Integrity check failed:', {
              expected: metadata.hash,
              actual: fileHash,
              encryptedDataSize: actualEncryptedData.length
            });
          } else {
            integrityVerified = true;
          }
        } else {
          integrityError = '文件缺少完整性哈希，无法验证';
        }
      } catch (hashError) {
        integrityError = `完整性验证过程出错: ${hashError.message}`;
        console.warn('Integrity verification error:', hashError);
      }
      
      // 生成传输密钥
      const transportSecretKey = generateTransportKey();
      
      // 获取 VetKey
      const encryptedVetKeyBytes = await this.deriveVetKDKey(
        currentPrincipal,
        transportSecretKey.publicKeyBytes()
      );
      
      const publicKeyBytes = await this.getVetKDPublicKey();
      
      const vetKey = getVetKey(
        currentPrincipal,
        encryptedVetKeyBytes,
        publicKeyBytes,
        transportSecretKey
      );
      
      // 解密文件
      const decrypted = await decryptWithIBE(actualEncryptedData, vetKey);
      
      // 添加完整性验证结果到元数据
      metadata.integrityVerified = integrityVerified;
      metadata.integrityError = integrityError;
      
      return {
        data: decrypted,
        metadata: metadata
      };
    } catch (error) {
      console.error("Decryption error:", error);
      throw error;
    }
  }
}

// 导出单例实例
export default new ApiService(); 