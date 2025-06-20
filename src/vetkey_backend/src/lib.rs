use ic_cdk::api::call::call;
use ic_cdk::update;
use candid::{CandidType, Deserialize, Principal};

// 域分隔符，用于特定应用上下文
const DOMAIN_SEPARATOR: &[u8] = b"file-encryption-app";

// vetKD 请求和响应类型
#[derive(CandidType, Deserialize)]
struct VetKDCurve {
    #[serde(rename = "bls12_381_g2")]
    Bls12_381_G2: (),
}

#[derive(CandidType, Deserialize)]
struct VetKDKeyId {
    curve: String,
    name: String,
}

#[derive(CandidType, Deserialize)]
struct VetKDPublicKeyRequest {
    canister_id: Option<Principal>,
    context: Vec<u8>,
    key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize)]
struct VetKDDeriveKeyRequest {
    input: Vec<u8>,
    context: Vec<u8>,
    transport_public_key: Vec<u8>,
    key_id: VetKDKeyId,
}

#[derive(CandidType, Deserialize)]
struct VetKDPublicKeyResponse {
    public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
struct VetKDDeriveKeyResponse {
    encrypted_key: Vec<u8>,
}

/// 获取 vetKD 公钥
#[update]
async fn get_vetkd_public_key() -> Vec<u8> {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        context: DOMAIN_SEPARATOR.to_vec(),
        key_id: VetKDKeyId {
            curve: "bls12_381_g2".to_string(),
            name: "dfx_test_key".to_string(),
        },
    };

    let (response,): (VetKDPublicKeyResponse,) = call(
        Principal::management_canister(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("Failed to get vetKD public key");

    response.public_key
}

/// 为特定用户 ID 派生加密密钥
#[update]
async fn derive_vetkd_key(user_id: String, transport_public_key: Vec<u8>) -> Vec<u8> {
    let input = user_id.as_bytes().to_vec();

    let request = VetKDDeriveKeyRequest {
        input,
        context: DOMAIN_SEPARATOR.to_vec(),
        transport_public_key,
        key_id: VetKDKeyId {
            curve: "bls12_381_g2".to_string(),
            name: "dfx_test_key".to_string(),
        },
    };

    let (response,): (VetKDDeriveKeyResponse,) = call(
        Principal::management_canister(),
        "vetkd_derive_key",
        (request,),
    )
    .await
    .expect("Failed to derive vetKD key");

    response.encrypted_key
}

/// 本地开发环境使用的 dfx_test_key
fn dfx_test_key() -> VetKDKeyId {
    VetKDKeyId {
        curve: "bls12_381_g2".to_string(),
        name: "dfx_test_key".to_string(),
    }
}

/// 管理 canister 的 Principal ID (aaaaa-aa)
fn management_canister_id() -> Principal {
    Principal::from_text("aaaaa-aa").unwrap()
}

// 导出 candid 接口
ic_cdk::export_candid!();
