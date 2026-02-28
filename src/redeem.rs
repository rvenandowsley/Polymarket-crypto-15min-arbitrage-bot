//! CTF Redeem 模块：将已结算市场的赢家代币赎回为 USDC。
//!
//! 支持 **Gnosis Safe**（execTransaction）与 **Magic/Email EIP-1167**（Polymarket Relayer）。
//! 使用 CTF.redeemPositions，binary 市场一次赎回 YES+NO 两个 index set。

use std::env;

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::signers::Signer as _;
use anyhow::Result;
use polymarket_client_sdk::ctf::types::RedeemPositionsRequest;
use polymarket_client_sdk::{contract_config, POLYGON};
use std::str::FromStr as _;
use tracing::{info, warn};

use crate::proxy_relay::{
    derive_proxy_wallet, relayer_execute_proxy_calldata, IGnosisSafe, PROXY_FACTORY,
    RELAYER_URL_DEFAULT, RPC_URL_DEFAULT, USDC_POLYGON,
};

fn encode_redeem_calldata(req: &RedeemPositionsRequest) -> Vec<u8> {
    let sel = &keccak256(b"redeemPositions(address,bytes32,bytes32,uint256[])")[..4];
    let mut out = Vec::from(sel);
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(req.collateral_token.as_slice());
    out.extend_from_slice(req.parent_collection_id.as_slice());
    out.extend_from_slice(req.condition_id.as_slice());
    out.extend_from_slice(&U256::from(128u64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(req.index_sets.len()).to_be_bytes::<32>());
    for idx in &req.index_sets {
        out.extend_from_slice(&idx.to_be_bytes::<32>());
    }
    out
}

/// 从环境变量 SIGNATURE_TYPE 读取：GnosisSafe/Safe => 强制 Safe，Proxy => 强制 Relayer，未设则自动检测。
fn use_relayer_by_config(code_len: usize) -> bool {
    let s = match env::var("SIGNATURE_TYPE") {
        Ok(v) => v.trim().to_lowercase(),
        Err(_) => return code_len < 150,
    };
    if s == "proxy" {
        return true;
    }
    if s == "gnosissafe" || s == "safe" {
        return false;
    }
    code_len < 150
}

/// 对指定 `condition_id` 在 `proxy` 上赎回赢家代币为 USDC。
///
/// 支持 Gnosis Safe（execTransaction）与 Magic/Email（Relayer）。
/// 可通过环境变量 SIGNATURE_TYPE=GnosisSafe 或 Proxy 强制指定路径（与 test_sell_all 一致）。
///
/// - `condition_id`: 市场的 condition ID
/// - `proxy`: Proxy 地址（Gnosis Safe 或 EIP-1167）
/// - `private_key`: EOA 私钥
/// - `rpc_url`: Polygon RPC，`None` 时用默认
///
/// 返回交易哈希（十六进制字符串）。
pub async fn redeem_one(
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
    let config = contract_config(chain, false).ok_or_else(|| anyhow::anyhow!("不支持的 chain_id: {}", chain))?;
    let ctf = config.conditional_tokens;

    let redeem_req = RedeemPositionsRequest::for_binary_market(USDC_POLYGON, condition_id);
    let redeem_calldata = encode_redeem_calldata(&redeem_req);
    let code = provider.get_code_at(proxy).await.unwrap_or_default();
    let use_relayer = use_relayer_by_config(code.len());

    if use_relayer {
        let derived = derive_proxy_wallet(wallet, PROXY_FACTORY);
        let try_anyway = env::var("MERGE_TRY_ANYWAY").map(|s| s.trim() == "1" || s.trim().eq_ignore_ascii_case("true")).unwrap_or(false);
        if derived != proxy && !try_anyway {
            anyhow::bail!(
                "POLYMARKET_PROXY_ADDRESS ({:?}) 与 ProxyFactory 推导 ({:?}) 不一致。设 MERGE_TRY_ANYWAY=1 可强行尝试。",
                proxy, derived
            );
        }
        if derived != proxy {
            warn!("MERGE_TRY_ANYWAY=1：derive != proxy，仍发 Relayer 请求。");
        }
        let builder_key = env::var("POLY_BUILDER_API_KEY").ok();
        let builder_secret = env::var("POLY_BUILDER_SECRET").ok();
        let builder_passphrase = env::var("POLY_BUILDER_PASSPHRASE").ok();
        let relayer_url = env::var("RELAYER_URL").unwrap_or_else(|_| RELAYER_URL_DEFAULT.to_string());
        match (builder_key.as_deref(), builder_secret.as_deref(), builder_passphrase.as_deref()) {
            (Some(k), Some(s), Some(p)) => {
                let out = relayer_execute_proxy_calldata(
                    &redeem_calldata, ctf, proxy, &signer, k, s, p, &relayer_url, "Redeem positions",
                )
                .await?;
                info!("✅ Relayer 已提交 redeem tx: {}", out);
                return Ok(out);
            }
            _ => anyhow::bail!(
                "Magic/Email 需配置 POLY_BUILDER_API_KEY、POLY_BUILDER_SECRET、POLY_BUILDER_PASSPHRASE。",
            ),
        }
    }

    let safe = IGnosisSafe::new(proxy, provider);
    let nonce: U256 = safe.nonce().call().await.map_err(|e| anyhow::anyhow!("读取 Safe nonce 失败: {}", e))?;
    let tx_hash_data = safe
        .encodeTransactionData(ctf, U256::ZERO, redeem_calldata.clone().into(), 0u8, U256::ZERO, U256::ZERO, U256::ZERO, Address::ZERO, Address::ZERO, nonce)
        .call()
        .await
        .map_err(|e| anyhow::anyhow!("Safe.encodeTransactionData 失败: {}", e))?
        .0;
    let tx_hash = keccak256(tx_hash_data.as_ref());
    let sig = signer.sign_hash(&tx_hash).await.map_err(|e| anyhow::anyhow!("签名失败: {}", e))?;
    let mut sig_bytes = sig.as_bytes().to_vec();
    if sig_bytes.len() == 65 && (sig_bytes[64] == 0 || sig_bytes[64] == 1) {
        sig_bytes[64] += 27;
    }
    let pending = safe
        .execTransaction(ctf, U256::ZERO, redeem_calldata.into(), 0u8, U256::ZERO, U256::ZERO, U256::ZERO, Address::ZERO, Address::ZERO, sig_bytes.into())
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Safe.execTransaction 失败: {}", e))?;
    let tx_hash_out = *pending.tx_hash();
    let _receipt = pending.get_receipt().await.map_err(|e| anyhow::anyhow!("等待 receipt 失败: {}", e))?;
    info!("✅ Redeem 成功（Safe）tx: {:#x}", tx_hash_out);
    Ok(format!("{:#x}", tx_hash_out))
}
