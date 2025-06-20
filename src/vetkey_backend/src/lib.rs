//! VetKey 后端服务
//! 
//! 实现了基于 Internet Computer (IC) 平台的 vetKD (verifiable threshold key derivation) 
//! 密钥派生服务。主要功能包括：
//! - 获取 vetKD 公钥
//! - 为特定用户派生加密密钥
//! - 支持 zCloak KYC 应用的身份验证

use ic_cdk::api::call::{call, call_with_payment128};
use ic_cdk::update;
use candid::{CandidType, Deserialize, Principal};

/// 域分隔符，用于特定应用上下文
/// 
/// 这个常量定义了应用的唯一标识符，用于确保密钥派生的上下文隔离
/// 不同的应用应该使用不同的域分隔符以避免密钥冲突
const DOMAIN_SEPARATOR: &[u8] = b"zCloak-KYC-vetkey-app-zzx777593gcaatys7824k77g9ryxv78td5g6sh";

// ==================== vetKD 系统相关类型定义 ====================

/// vetKD 支持的椭圆曲线类型
/// 
/// 目前支持 BLS12-381 G2 曲线，这是一种配对友好的椭圆曲线
/// 广泛用于零知识证明和阈值密码学应用
#[derive(CandidType, Deserialize)]
enum VetKDCurve {
    /// BLS12-381 G2 群上的椭圆曲线
    #[serde(rename = "bls12_381_g2")]
    Bls12381G2,
}

/// vetKD 密钥 id
/// 
/// 用于标识特定的密钥配置，包括使用的椭圆曲线类型和密钥名称
#[derive(CandidType, Deserialize)]
struct VetKDKeyId {
    /// 使用的椭圆曲线类型
    curve: VetKDCurve,
    /// 密钥的名称
    name: String,
}

/// 获取 vetKD 公钥的请求结构
/// 
/// 用于向 vetkey 管理 canister 请求 vetKD 系统的公钥
#[derive(CandidType, Deserialize)]
struct VetKDPublicKeyRequest {
    /// 可选的 canister ID，如果为 None 则使用调用者的 canister ID
    canister_id: Option<Principal>,
    /// 应用上下文，用于密钥派生的域分离
    context: Vec<u8>,
    /// 密钥 id
    key_id: VetKDKeyId,
}

/// 派生 vetKD 密钥的请求结构
/// 
/// 用于请求为特定输入派生一个加密的私钥
#[derive(CandidType, Deserialize)]
struct VetKDDeriveKeyRequest {
    /// 派生输入，通常是用户标识符或其他唯一标识
    input: Vec<u8>,
    /// 应用上下文，必须与公钥请求时使用的相同
    context: Vec<u8>,
    /// 传输公钥，用于加密返回的私钥
    transport_public_key: Vec<u8>,
    /// 密钥标识符，必须与公钥请求时使用的相同
    key_id: VetKDKeyId,
}

/// vetKD 公钥响应结构
/// 
/// 包含从 vetkey 管理 canister 返回的 vetKD 公钥
#[derive(CandidType, Deserialize)]
struct VetKDPublicKeyResponse {
    /// BLS12-381 G2 群上的公钥字节序列
    public_key: Vec<u8>,
}

/// vetKD 派生密钥响应结构
/// 
/// 包含加密的派生私钥，只有持有对应传输私钥的用户才能解密
#[derive(CandidType, Deserialize)]
struct VetKDDeriveKeyResponse {
    /// 使用传输公钥加密的派生私钥
    encrypted_key: Vec<u8>,
}

// ==================== 公开 API 函数 ====================

/// 获取 vetKD 系统公钥
/// 
/// 向 vetkey 管理 canister 请求 vetKD 系统公钥
/// 这个公钥将用于前端加密文件
/// 
/// # 返回值
/// - `Vec<u8>`: BLS12-381 G2 群上的公钥字节序列
/// 
/// # 错误处理
/// 如果无法获取公钥，函数会 panic 并显示错误信息
/// 
/// # 使用场景
/// - 前端加密文件时获取公钥
/// - 验证派生密钥的合法性
#[update]
async fn get_vetkd_public_key() -> Vec<u8> {
    // 构建获取公钥的请求
    let request = VetKDPublicKeyRequest {
        canister_id: None,  // 使用当前 canister 的 ID
        context: DOMAIN_SEPARATOR.to_vec(),  // 使用应用特定的域分隔符
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12381G2,  // 使用 BLS12-381 G2 曲线
            name: "dfx_test_key".to_string(),  // 测试密钥名称
        },
    };

    // 调用 vetkey 管理 canister 的 vetkd_public_key 方法
    let (response,): (VetKDPublicKeyResponse,) = call(
        Principal::management_canister(),   // vetkey 管理 canister 的 Principal id
        "vetkd_public_key",                 // 调用的方法名
        (request,),                         // 请求参数
    )
    .await
    .expect("Failed to get vetKD public key");  // 错误处理

    response.public_key
}

/// 为特定用户 ID 派生私钥，用于解密
/// 
/// 这个函数使用 vetKD 系统为指定的用户 ID 派生一个唯一的私钥。
/// 派生的私钥使用传输公钥加密，只有持有对应传输私钥的用户才能解密使用。
/// 
/// # 参数
/// - `user_id`: 用户的唯一标识符，用作密钥派生的输入
/// - `transport_public_key`: 用于加密返回私钥的传输公钥
/// 
/// # 返回值
/// - `Vec<u8>`: 加密的派生私钥字节序列
/// 
/// # 错误处理
/// 如果私钥派生失败，函数会 panic 并显示错误信息。
/// 
/// # 注意事项
/// - 相同的 user_id 总是会派生出相同的私钥
/// - 不同的用户 ID 会派生出完全不同的私钥
/// - 派生过程是确定性的但不可逆的
#[update]
async fn derive_vetkd_key(user_id: String, transport_public_key: Vec<u8>) -> Vec<u8> {
    // 用户ID作为派生输入，保持与前端解密时的身份一致
    let input = user_id.as_bytes().to_vec();
    
    // 构建私钥派生请求，使用域分隔符作为context确保应用隔离
    let request = VetKDDeriveKeyRequest {
        input,                                   // 用户 ID 作为派生输入
        context: DOMAIN_SEPARATOR.to_vec(),      // 应用域分隔符
        transport_public_key,                    // 传输公钥，用于加密返回的私钥
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12381G2,       // 使用与公钥相同的曲线
            name: "dfx_test_key".to_string(),    // 使用与公钥相同的密钥名称
        },
    };

    // 调用 vetkey 管理 canister 的 vetkd_derive_key 方法
    // 注意：这个调用需要支付 cycles 费用
    let (response,): (VetKDDeriveKeyResponse,) = call_with_payment128(
        Principal::management_canister(),   // vetkey 管理 canister 的 Principal
        "vetkd_derive_key",                 // 调用的方法名
        (request,),                         // 请求参数
        26_153_846_153_u128,                // 支付的 cycles 数量（私钥派生的费用）
    )
    .await
    .expect("Failed to derive vetKD key");  // 错误处理

    response.encrypted_key
}

// 导出 Candid 接口定义
// 这会自动生成 .did 文件，用于前端和其他 canister 的接口调用
ic_cdk::export_candid!();
