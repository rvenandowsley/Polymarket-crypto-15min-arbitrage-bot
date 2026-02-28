//! 代理钱包 + Relayer/Safe 共享基础设施：供 merge、redeem复用。
//!
//! 包含 Relayer 请求（/relay-payload、/submit）、Proxy 调用编码、Gnosis Safe 接口及签名流程。

use std::env;

use alloy::primitives::{keccak256, Address, B256, Bytes, U256};
use alloy::sol_types::SolCall;
use anyhow::Result;
use tracing::info;

use polymarket_client_sdk::types::address;

use alloy::sol;
sol! {
    #[sol(rpc)]
    interface IGnosisSafe {
        function nonce() external view returns (uint256);
        function encodeTransactionData(
            address to,
            uint256 value,
            bytes memory data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            uint256 _nonce
        ) external view returns (bytes memory);
        function execTransaction(
            address to,
            uint256 value,
            bytes memory data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address refundReceiver,
            bytes memory signatures
        ) external payable returns (bool success);
    }
}

sol! {
    struct ProxyCallTuple {
        uint8 typeCode;
        address to;
        uint256 value;
        bytes data;
    }
    function proxy(ProxyCallTuple[] calls) external payable returns (bytes[] returnValues);
}

pub const RPC_URL_DEFAULT: &str = "https://polygon-bor-rpc.publicnode.com";
pub const RELAYER_URL_DEFAULT: &str = "https://relayer-v2.polymarket.com";
pub const USDC_POLYGON: Address = address!("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174");

const RELAYER_GET_RELAY_PAYLOAD: &str = "/relay-payload";
const RELAYER_SUBMIT: &str = "/submit";

pub const PROXY_FACTORY: Address = address!("0xaB45c5A4B0c941a2F231C04C3f49182e1A254052");
const RELAY_HUB: Address = address!("0xD216153c06E857cD7f72665E0aF1d7D82172F494");
const PROXY_INIT_CODE_HASH: [u8; 32] = [
    0xd2, 0x1d, 0xf8, 0xdc, 0x65, 0x88, 0x0a, 0x86, 0x06, 0xf0, 0x9f, 0xe0, 0xce, 0x3d, 0xf9, 0xb8,
    0x86, 0x92, 0x87, 0xab, 0x0b, 0x05, 0x8b, 0xe0, 0x5a, 0xa9, 0xe8, 0xaf, 0x63, 0x30, 0xa0, 0x0b,
];
pub const PROXY_DEFAULT_GAS: u64 = 160_000;

/// 将 0x 开头的长 hex 缩短为 `0x` + 前 8 位 + `..` + 后 6 位，便于日志。
pub fn short_hex(s: &str) -> String {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() > 14 {
        let lo = hex.len().saturating_sub(6);
        format!("0x{}..{}", &hex[..8.min(hex.len())], &hex[lo..])
    } else {
        format!("0x{}", hex)
    }
}

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

pub(crate) fn derive_proxy_wallet(eoa: Address, proxy_factory: Address) -> Address {
    let salt = keccak256(eoa.as_slice());
    let mut buf = [0u8; 1 + 20 + 32 + 32];
    buf[0] = 0xff;
    buf[1..21].copy_from_slice(proxy_factory.as_slice());
    buf[21..53].copy_from_slice(salt.as_slice());
    buf[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    let h = keccak256(buf);
    Address::from_slice(&h.as_slice()[12..32])
}

fn to_hex_0x(b: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

fn build_hmac_signature(secret: &[u8], timestamp: u64, method: &str, path: &str, body: &str) -> String {
    let msg = format!("{}{}{}{}", timestamp, method, path, body);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(msg.as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    sig.replace('+', "-").replace('/', "_")
}

pub(crate) async fn get_relay_payload(client: &reqwest::Client, base: &str, eoa: Address) -> Result<(Address, String)> {
    let url = format!("{}{}", base.trim_end_matches('/'), RELAYER_GET_RELAY_PAYLOAD);
    let resp = client
        .get(&url)
        .query(&[("address", format!("{:#x}", eoa)), ("type", "PROXY".to_string())])
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("GET /relay-payload 失败 status={} body={}", status, text);
    }
    let j: serde_json::Value = serde_json::from_str(&text)?;
    let addr = j.get("address").and_then(|v| v.as_str()).ok_or_else(|| anyhow::anyhow!("relay-payload 缺少 address"))?;
    let nonce = j
        .get("nonce")
        .map(|v| {
            v.as_str()
                .map(String::from)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
                .unwrap_or_else(|| "0".into())
        })
        .unwrap_or_else(|| "0".into());
    let relay = addr.trim().parse::<Address>().map_err(|e| anyhow::anyhow!("relay address 解析失败: {}", e))?;
    Ok((relay, nonce.to_string()))
}

pub(crate) fn encode_proxy_call(target: Address, data: &[u8]) -> Vec<u8> {
    let t = ProxyCallTuple {
        typeCode: 1u8,
        to: target,
        value: U256::ZERO,
        data: Bytes::from(data.to_vec()),
    };
    proxyCall { calls: vec![t] }.abi_encode().to_vec()
}

pub(crate) fn create_struct_hash(
    from: Address,
    to: Address,
    data: &[u8],
    tx_fee: u64,
    gas_price: u64,
    gas_limit: u64,
    nonce: &str,
    relay_hub: Address,
    relay: Address,
) -> B256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"rlx:");
    buf.extend_from_slice(from.as_slice());
    buf.extend_from_slice(to.as_slice());
    buf.extend_from_slice(data);
    buf.extend_from_slice(&U256::from(tx_fee).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(gas_price).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(gas_limit).to_be_bytes::<32>());
    let n: u64 = nonce.parse().unwrap_or(0);
    buf.extend_from_slice(&U256::from(n).to_be_bytes::<32>());
    buf.extend_from_slice(relay_hub.as_slice());
    buf.extend_from_slice(relay.as_slice());
    keccak256(buf)
}

pub(crate) fn eip191_hash(struct_hash: B256) -> B256 {
    let mut msg = b"\x19Ethereum Signed Message:\n32".to_vec();
    msg.extend_from_slice(struct_hash.as_slice());
    keccak256(msg)
}

/// 通过 Relayer 执行单条 proxy 调用（免 gas）。由 merge/redeem/withdraw 调用。
pub(crate) async fn relayer_execute_proxy_calldata(
    calldata: &[u8],
    target_address: Address,
    proxy_wallet: Address,
    signer: &impl alloy::signers::Signer,
    builder_key: &str,
    builder_secret: &str,
    builder_passphrase: &str,
    relayer_url: &str,
    metadata: &str,
) -> Result<String> {
    let client = reqwest::Client::new();
    let eoa = signer.address();
    let base = relayer_url.trim_end_matches('/');

    let (relay, nonce) = get_relay_payload(&client, base, eoa).await?;
    let proxy_data = encode_proxy_call(target_address, calldata);
    let gas_limit: u64 = env::var("MERGE_PROXY_GAS_LIMIT")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(PROXY_DEFAULT_GAS);

    if env::var("MERGE_PROXY_TO").map(|s| s.trim().eq_ignore_ascii_case("PROXY_WALLET")).unwrap_or(false) {
        info!("ℹ️ MERGE_PROXY_TO=PROXY_WALLET 已忽略，使用 to=PROXY_FACTORY");
    }
    let to = PROXY_FACTORY;
    let struct_hash = create_struct_hash(eoa, to, &proxy_data, 0, 0, gas_limit, &nonce, RELAY_HUB, relay);
    let to_sign = eip191_hash(struct_hash);
    let sig = signer.sign_hash(&to_sign).await.map_err(|e| anyhow::anyhow!("EOA 签名失败: {}", e))?;
    let mut sig_bytes = sig.as_bytes().to_vec();
    if sig_bytes.len() == 65 && (sig_bytes[64] == 0 || sig_bytes[64] == 1) {
        sig_bytes[64] += 27;
    }
    let signature_hex = to_hex_0x(&sig_bytes);

    let signature_params = serde_json::json!({
        "gasPrice": "0",
        "gasLimit": gas_limit.to_string(),
        "relayerFee": "0",
        "relayHub": format!("{:#x}", RELAY_HUB),
        "relay": format!("{:#x}", relay)
    });
    let body = serde_json::json!({
        "from": format!("{:#x}", eoa),
        "to": format!("{:#x}", to),
        "proxyWallet": format!("{:#x}", proxy_wallet),
        "data": to_hex_0x(&proxy_data),
        "nonce": nonce,
        "signature": signature_hex,
        "signatureParams": signature_params,
        "type": "PROXY",
        "metadata": metadata
    });
    let body_str = serde_json::to_string(&body)?;

    let path = RELAYER_SUBMIT;
    let method = "POST";
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    let secret_b64 = builder_secret
        .trim()
        .replace('-', "+")
        .replace('_', "/");
    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(&secret_b64)
        .map_err(|e| anyhow::anyhow!("POLY_BUILDER_SECRET base64 解码失败: {}", e))?;
    let sig_hmac = build_hmac_signature(&secret_bytes, timestamp, method, path, &body_str);

    let url = format!("{}{}", base, path);
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("POLY_BUILDER_API_KEY", builder_key)
        .header("POLY_BUILDER_TIMESTAMP", timestamp.to_string())
        .header("POLY_BUILDER_PASSPHRASE", builder_passphrase)
        .header("POLY_BUILDER_SIGNATURE", sig_hmac)
        .body(body_str)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("Relayer 请求失败 status={} body={}", status, text);
    }
    let json: serde_json::Value = serde_json::from_str(&text)?;
    let hash = json
        .get("transactionHash")
        .or_else(|| json.get("transaction_hash"))
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(hash.unwrap_or_else(|| text))
}

// IGnosisSafe 由上方 sol! 生成，供 merge/redeem/withdraw 通过 crate::proxy_relay::IGnosisSafe 使用
