# VetKey 文件加密系统

一个基于 Internet Computer 的 vetKey 实现的安全文件加密解密系统。集成了 Internet Identity 身份认证，用户可以使用经过验证的身份安全地加密和解密文件，所有文件处理都在浏览器本地完成。

## 功能特性

- **Internet Identity 认证**：集成 IC 官方身份认证系统，安全可靠
- **文件加密**：使用用户身份或指定目标用户ID生成唯一的加密密钥
- **文件解密**：使用相同的身份或用户ID解密文件
- **完整性验证**：内置文件完整性检查，确保加密过程的安全性
- **浏览器本地处理**：文件和密文都在浏览器本地处理，保护隐私
- **vetKey 技术**：利用 IC 的阈值密钥派生技术
- **实时状态反馈**：详细的操作状态提示和进度显示

## 技术架构

- **后端**：Rust + IC SDK
- **前端**：React + Vite
- **认证**：Internet Identity
- **加密技术**：vetKD (Verifiably Encrypted Threshold Key Derivation)
- **构建工具**：Vite + ESBuild

## 快速开始

### 前置要求

- 安装 [DFX](https://internetcomputer.org/docs/current/developer-docs/build/install-upgrade-remove/) (版本 0.14.0+)
- 安装 Node.js (版本 16+)
- 安装 Rust (最新稳定版)
- [Quick Start](https://internetcomputer.org/docs/current/developer-docs/setup/deploy-locally)
- [SDK Developer Tools](https://internetcomputer.org/docs/current/developer-docs/setup/install)
- [Rust Canister Development Guide](https://internetcomputer.org/docs/current/developer-docs/backend/rust/)
- [ic-cdk](https://docs.rs/ic-cdk)
- [ic-cdk-macros](https://docs.rs/ic-cdk-macros)
- [Candid Introduction](https://internetcomputer.org/docs/current/developer-docs/backend/candid/)

### 安装和运行

1. 克隆项目并进入项目目录：
```bash
cd vetkey
```

2. 安装依赖：
```bash
npm install
```

3. 启动本地 IC 网络：
```bash
dfx start --background --clean
```

4. 在新的终端窗口中本地部署 canister：
```bash
dfx deploy
```

5. 在浏览器中访问应用：
```bash
# 获取前端URL
echo "http://$(dfx canister id vetkey_frontend).localhost:4943"
```

## 项目结构

```
vetkey/
├── src/
│   ├── declarations/                      # 自动生成的类型声明
│   ├── ii/                                # Internet Identity 本地部署文件
│   │   ├── internet_identity.did
│   │   └── internet_identity_dev.wasm.gz
│   ├── vetkey_backend/                    # Rust 后端代码
│   │   ├── src/
│   │   │   └── lib.rs                     # vetKD API 实现
│   │   ├── Cargo.toml
│   │   └── vetkey_backend.did
│   └── vetkey_frontend/                   # React 前端代码
│       ├── src/
│       │   ├── components/                # React 组件
│       │   │   ├── FileDecrypt.jsx        # 文件解密组件
│       │   │   ├── FileEncrypt.jsx        # 文件加密组件
│       │   │   ├── Login.jsx              # 登录认证组件
│       │   │   └── Status.jsx             # 状态显示组件
│       │   ├── services/                  # 服务层
│       │   │   ├── api.js                 # API 服务
│       │   │   └── auth.js                # 认证服务
│       │   ├── utils/                     # 工具函数
│       │   │   └── constants.js           # 常量定义
│       │   ├── App.jsx                    # 主应用组件
│       │   ├── crypto.js                  # 加密工具函数
│       │   ├── index.scss                 # 样式文件
│       │   └── main.jsx                   # 应用入口
│       ├── package.json
│       └── vite.config.js
├── dfx.json                               # DFX 配置
├── package.json                           # 根项目配置
├── canister_ids.json                      # Canister ID 配置
├── MAINNET_DEPLOYMENT.md                  # 主网部署指南
└── README.md                              # 项目说明
```

## 部署到主网

### 快速部署步骤

1. 准备部署身份和钱包
2. 检查配置文件
3. 执行部署命令：

```bash
# 部署到主网
dfx deploy --network ic

# 获取应用访问地址
echo "https://$(dfx canister id vetkey_frontend --network ic).ic0.app"
```

## 配置说明

### 环境变量

- `DFX_NETWORK`：部署网络（`local` 或 `ic`）
- `CANISTER_ID_INTERNET_IDENTITY`：Internet Identity Canister ID

### 重要配置文件

- `src/vetkey_frontend/src/utils/constants.js`：应用常量配置
- `dfx.json`：DFX 网络和 Canister 配置
- `canister_ids.json`：Canister ID 映射

### 部署前检查清单

### 1. 身份和钱包准备
- [ ] 确保 dfx 身份有足够的 ICP 用于部署
- [ ] 已经创建或选择了部署身份

```bash
# 查看当前身份
dfx identity whoami

# 查看身份的 principal
dfx identity get-principal

# 检查余额
dfx wallet balance
```

### 2. 配置检查
- [ ] `dfx.json` 中已移除本地 Internet Identity 配置
- [ ] `constants.js` 中的 Identity Provider URL 配置正确
- [ ] 环境变量配置正确

## 主网部署步骤

### 步骤 准备部署环境
```bash
# 切换到主网
dfx ping ic

# 检查身份
dfx identity get-principal
```

### 步骤 验证部署
```bash
# 检查 canister 状态
dfx canister status --network ic --all

# 获取前端 URL
echo "https://$(dfx canister id vetkey_frontend --network ic).ic0.app"
```

## 监控和维护

### 监控命令
```bash
# 检查 canister 状态
dfx canister status --network ic vetkey_backend
dfx canister status --network ic vetkey_frontend

# 查看 cycles 余额
dfx canister status --network ic vetkey_backend | grep Balance
```

### 添加 Cycles
```bash
# 给 canister 添加 cycles
dfx canister deposit-cycles 1000000000000 --network ic vetkey_backend
```
