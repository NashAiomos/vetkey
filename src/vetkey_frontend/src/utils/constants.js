/**
 * 应用常量定义
 */

// Internet Identity URL
export const IDENTITY_PROVIDER = process.env.DFX_NETWORK === "ic" 
  ? "https://identity.ic0.app"
  : `http://${process.env.CANISTER_ID_INTERNET_IDENTITY}.localhost:4943`;

// 文件大小限制
export const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// 前端ii登录会话超时时间（毫秒）
export const SESSION_TIMEOUT = 30 * 60 * 1000; // 30分钟

// 文件扩展名
export const ENCRYPTED_FILE_EXTENSION = '.vetkey';