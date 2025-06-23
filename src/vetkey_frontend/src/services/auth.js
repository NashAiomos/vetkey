/**
 * 身份认证服务模块
 * 处理 Internet Identity 登录和身份管理
 */

import { AuthClient } from "@dfinity/auth-client";
import { HttpAgent, Actor } from "@dfinity/agent";
import { IDENTITY_PROVIDER, SESSION_TIMEOUT } from "../utils/constants";

class AuthService {
  constructor() {
    this.authClient = null;
    this.identity = null;
    this.principal = null;
    this.isAuthenticated = false;
  }

  /**
   * 初始化认证客户端
   */
  async init() {
    this.authClient = await AuthClient.create({
      idleOptions: {
        idleTimeout: SESSION_TIMEOUT,
        onIdle: () => {
          console.log("Session expired due to inactivity");
          this.logout();
        }
      }
    });

    // 检查是否已经登录
    const isAuthenticated = await this.authClient.isAuthenticated();
    if (isAuthenticated) {
      this.identity = this.authClient.getIdentity();
      this.principal = this.identity.getPrincipal();
      this.isAuthenticated = true;
    }

    return this.isAuthenticated;
  }

  /**
   * 登录
   * @param {Function} onSuccess - 登录成功回调
   * @param {Function} onError - 登录失败回调
   */
  async login(onSuccess, onError) {
    if (!this.authClient) {
      await this.init();
    }

    try {
      await this.authClient.login({
        identityProvider: IDENTITY_PROVIDER,
        // 在constants.js里设置登录过期时间
        maxTimeToLive: BigInt(SESSION_TIMEOUT * 1000000), // 纳秒
        onSuccess: () => {
          this.identity = this.authClient.getIdentity();
          this.principal = this.identity.getPrincipal();
          this.isAuthenticated = true;
          
          console.log("Login successful, Principal:", this.principal.toString());
          
          if (onSuccess) {
            onSuccess(this.principal.toString());
          }
        },
        onError: (error) => {
          console.error("Login failed:", error);
          this.isAuthenticated = false;
          
          if (onError) {
            onError(error);
          }
        }
      });
    } catch (error) {
      console.error("Login error:", error);
      this.isAuthenticated = false;
      if (onError) {
        onError(error);
      }
    }
  }

  /**
   * 登出
   */
  async logout() {
    if (this.authClient) {
      await this.authClient.logout();
    }
    
    this.identity = null;
    this.principal = null;
    this.isAuthenticated = false;
  }

  /**
   * 获取当前用户的 Principal
   */
  getPrincipal() {
    if (!this.isAuthenticated || !this.principal) {
      return null;
    }
    return this.principal.toString();
  }

  /**
   * 获取身份对象
   */
  getIdentity() {
    return this.identity;
  }

  /**
   * 检查是否已认证
   */
  checkAuthentication() {
    return this.isAuthenticated;
  }

  /**
   * 创建已认证的 Actor
   * 这是关键，确保使用已认证的身份创建 Actor
   */
  createActor(canisterId, idlFactory) {
    if (!this.isAuthenticated || !this.identity) {
      throw new Error("User not authenticated. Please login first.");
    }

    // 创建代理时使用已认证的身份
    const agent = new HttpAgent({
      identity: this.identity,
      host: process.env.DFX_NETWORK === "ic" ? "https://ic0.app" : "http://localhost:4943"
    });

    // 在本地开发环境中获取根密钥
    if (process.env.DFX_NETWORK !== "ic") {
      agent.fetchRootKey().catch(err => {
        console.error("Unable to fetch root key:", err);
      });
    }

    // 创建并返回 Actor
    return Actor.createActor(idlFactory, {
      agent,
      canisterId,
    });
  }
}

// 导出单例实例
export default new AuthService(); 