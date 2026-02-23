//! CTF Merge 模块：将等量 YES/NO 代币合并回 USDC。
//!
//! 支持 **Gnosis Safe**（execTransaction）与 **Magic/Email EIP-1167**（Polymarket Relayer）。
//! 合并数量自动取 `min(YES余额, NO余额)`，无需传入。
//!
//! ## 调用示例
//!
//! ```ignore
//! use alloy::primitives::B256;
//! use polymarket_client_sdk::types::Address;
//!
//! let tx = poly_15min_bot::merge::merge_max(
//!     condition_id,
//!     proxy,
//!     &private_key,
//!     Some("https://polygon-rpc.com"),
//! ).await?;
//! ```

use std::env;

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::signers::Signer as _;
use anyhow::Result;
use polymarket_client_sdk::ctf::types::{CollectionIdRequest, MergePositionsRequest, PositionIdRequest};
use polymarket_client_sdk::ctf::Client;
use polymarket_client_sdk::{contract_config, POLYGON};
use std::str::FromStr as _;
use tracing::{info, warn};

use crate::proxy_relay::{
    self, derive_proxy_wallet, relayer_execute_proxy_calldata, IGnosisSafe, PROXY_FACTORY,
    RELAYER_URL_DEFAULT, RPC_URL_DEFAULT, USDC_POLYGON,
};

use alloy::sol;
sol! {
    #[sol(rpc)]
    interface IERC1155Balance {
        function balanceOf(address account, uint256 id) external view returns (uint256);
    }
}

fn encode_merge_calldata(req: &MergePositionsRequest) -> Vec<u8> {
    let sel = &keccak256(b"mergePositions(address,bytes32,bytes32,uint256[],uint256)")[..4];
    let mut out = Vec::from(sel);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(req.collateral_token.as_slice());
    out.extend_from_slice(req.parent_collection_id.as_slice());
    out.extend_from_slice(req.condition_id.as_slice());
    out.extend_from_slice(&U256::from(160u64).to_be_bytes::<32>());
    out.extend_from_slice(&req.amount.to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(req.partition.len()).to_be_bytes::<32>());
    for p in &req.partition {
        out.extend_from_slice(&p.to_be_bytes::<32>());
    }
    out
}

/// 将 0x 开头的长 hex 缩短，便于日志（复用于兼容）。
pub fn short_hex(s: &str) -> String {
    proxy_relay::short_hex(s)
}

/// 对指定 `condition_id` 在 `proxy` 上合并最大可用 YES+NO 为 USDC。
///
/// 合并数量为 `min(YES余额, NO余额)`。支持 Gnosis Safe（execTransaction）与 Magic/Email（Relayer）。
///
/// - `condition_id`: 市场的 condition ID（32 字节十六进制）
/// - `proxy`: Proxy 地址（Gnosis Safe 或 EIP-1167）
/// - `private_key`: EOA 私钥
/// - `rpc_url`: Polygon RPC，`None` 时用默认
///
/// Magic/Email 路径会从环境变量读取：`POLY_BUILDER_API_KEY`、`POLY_BUILDER_SECRET`、`POLY_BUILDER_PASSPHRASE`、`RELAYER_URL`（可选）。
///
/// 返回交易哈希（十六进制字符串）。
pub async fn merge_max(
    condition_id: B256,
    proxy: Address,
    private_key: &str,
    rpc_url: Option<&str>,
) -> Result<String> {
    let rpc = rpc_url.unwrap_or(RPC_URL_DEFAULT);
    let chain = POLYGON;
    let signer = LocalSigner::from_str(private_key)?.with_chain_id(Some(chain));
    let wallet = signer.address();

    let provider = ProviderBuilder::new().wallet(signer.clone()).connect(rpc).await?;
    let client = Client::new(provider.clone(), chain)?;
    let config = contract_config(chain, false).ok_or_else(|| anyhow::anyhow!("不支持的 chain_id: {}", chain))?;
    let prov_read = ProviderBuilder::new().connect(rpc).await?;
    let erc1155 = IERC1155Balance::new(config.conditional_tokens, prov_read);
    let ctf = config.conditional_tokens;

    let req_col_yes = CollectionIdRequest::builder().parent_collection_id(B256::ZERO).condition_id(condition_id).index_set(U256::from(1)).build();
    let req_col_no = CollectionIdRequest::builder().parent_collection_id(B256::ZERO).condition_id(condition_id).index_set(U256::from(2)).build();
    let col_yes = client.collection_id(&req_col_yes).await?;
    let col_no = client.collection_id(&req_col_no).await?;

    let req_pos_yes = PositionIdRequest::builder().collateral_token(USDC_POLYGON).collection_id(col_yes.collection_id).build();
    let req_pos_no = PositionIdRequest::builder().collateral_token(USDC_POLYGON).collection_id(col_no.collection_id).build();
    let pos_yes = client.position_id(&req_pos_yes).await?;
    let pos_no = client.position_id(&req_pos_no).await?;

    let b_yes: U256 = erc1155.balanceOf(proxy, pos_yes.position_id).call().await.unwrap_or(U256::ZERO);
    let b_no: U256 = erc1155.balanceOf(proxy, pos_no.position_id).call().await.unwrap_or(U256::ZERO);

    let merge_amount = b_yes.min(b_no);
    if merge_amount == U256::ZERO {
        anyhow::bail!("无可用份额可 merge：YES={} NO={}，至少一方为 0。", b_yes, b_no);
    }
    info!("🔄 合并数量: {} ({} USDC)", merge_amount, merge_amount / U256::from(1_000_000));

    let merge_req = MergePositionsRequest::for_binary_market(USDC_POLYGON, condition_id, merge_amount);
    let merge_calldata = encode_merge_calldata(&merge_req);
    let code = provider.get_code_at(proxy).await.unwrap_or_default();

    if code.len() < 150 {
        let derived = derive_proxy_wallet(wallet, PROXY_FACTORY);
        let try_anyway = env::var("MERGE_TRY_ANYWAY").map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true")).unwrap_or(false);
        if derived != proxy {
            if !try_anyway {
                anyhow::bail!(
                    "POLYMARKET_PROXY_ADDRESS ({:?}) 与 ProxyFactory 的 CREATE2 推导 ({:?}) 不一致。\
                     请改用 Polymarket 网页 merge，或设 MERGE_TRY_ANYWAY=1 强行尝试。",
                    proxy, derived
                );
            }
            warn!("MERGE_TRY_ANYWAY=1：derive != proxy，仍发 Relayer 请求。");
        }
        let builder_key = env::var("POLY_BUILDER_API_KEY").ok();
        let builder_secret = env::var("POLY_BUILDER_SECRET").ok();
        let builder_passphrase = env::var("POLY_BUILDER_PASSPHRASE").ok();
        let relayer_url = env::var("RELAYER_URL").unwrap_or_else(|_| RELAYER_URL_DEFAULT.to_string());
        match (builder_key.as_deref(), builder_secret.as_deref(), builder_passphrase.as_deref()) {
            (Some(k), Some(s), Some(p)) => {
                let out = relayer_execute_proxy_calldata(
                    &merge_calldata, ctf, proxy, &signer, k, s, p, &relayer_url, "Merge positions",
                )
                .await?;
                info!("✅ Relayer 已提交 tx: {}", out);
                return Ok(out);
            }
            _ => anyhow::bail!(
                "Magic/Email 需配置 POLY_BUILDER_API_KEY、POLY_BUILDER_SECRET、POLY_BUILDER_PASSPHRASE；或改用网页 merge。",
            ),
        }
    }

    let safe = IGnosisSafe::new(proxy, provider);
    let nonce: U256 = safe.nonce().call().await.map_err(|e| {
        let msg = e.to_string();
        let hint = if msg.contains("revert") || msg.contains("reverted") {
            " 该地址可能不是 Gnosis Safe；Magic/Email 请用 Relayer 或网页 merge。"
        } else { "" };
        anyhow::anyhow!("读取 Safe nonce 失败: {}{}", msg, hint)
    })?;

    let tx_hash_data = safe
        .encodeTransactionData(ctf, U256::ZERO, merge_calldata.clone().into(), 0u8, U256::ZERO, U256::ZERO, U256::ZERO, Address::ZERO, Address::ZERO, nonce)
        .call().await.map_err(|e| anyhow::anyhow!("Safe.encodeTransactionData 失败: {}", e))?.0;

    let tx_hash = keccak256(tx_hash_data.as_ref());
    let sig = signer.sign_hash(&tx_hash).await.map_err(|e| anyhow::anyhow!("签名失败: {}", e))?;
    let mut sig_bytes = sig.as_bytes().to_vec();
    if sig_bytes.len() == 65 && (sig_bytes[64] == 0 || sig_bytes[64] == 1) {
        sig_bytes[64] += 27;
    }

    let pending = safe
        .execTransaction(ctf, U256::ZERO, merge_calldata.into(), 0u8, U256::ZERO, U256::ZERO, U256::ZERO, Address::ZERO, Address::ZERO, sig_bytes.into())
        .send().await.map_err(|e| anyhow::anyhow!("Safe.execTransaction 失败: {}", e))?;

    let tx_hash_out = *pending.tx_hash();
    let _receipt = pending.get_receipt().await.map_err(|e| anyhow::anyhow!("等待 receipt 失败: {}", e))?;
    info!("✅ Merge 成功（Safe）tx: {:#x}", tx_hash_out);
    Ok(format!("{:#x}", tx_hash_out))
}
