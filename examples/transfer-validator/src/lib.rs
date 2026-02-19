//! Transfer validator WASM program for CraftSEC.
//!
//! Uses a simple shared-memory protocol:
//! - Host writes request JSON to WASM memory via `guest_alloc`
//! - Guest exports `attest(ptr, len) -> ptr` where result is null-terminated JSON at returned ptr
//! - Host reads result from WASM memory
//!
//! Host functions for SQL queries and logging are imported from "env".

use serde::{Deserialize, Serialize};
use std::ffi::CString;

// Host functions
extern "C" {
    /// Query SQL: writes result JSON ptr/len to out params.
    fn host_sql_query(
        db_ptr: *const u8, db_len: u32,
        sql_ptr: *const u8, sql_len: u32,
        params_ptr: *const u8, params_len: u32,
    ) -> u64; // returns (ptr << 32) | len

    fn host_log(level: u32, msg_ptr: *const u8, msg_len: u32);
}

fn sql_query(db: &str, sql: &str, params: &str) -> String {
    unsafe {
        let packed = host_sql_query(
            db.as_ptr(), db.len() as u32,
            sql.as_ptr(), sql.len() as u32,
            params.as_ptr(), params.len() as u32,
        );
        let ptr = (packed >> 32) as *const u8;
        let len = (packed & 0xFFFFFFFF) as usize;
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf8_lossy(slice).into_owned()
    }
}

fn log_info(msg: &str) {
    unsafe { host_log(1, msg.as_ptr(), msg.len() as u32); }
}

#[derive(Deserialize)]
struct TransferRequest {
    requester: String,
    program_cid: String,
    args: TransferArgs,
}

#[derive(Deserialize)]
struct TransferArgs {
    recipient: String,
    amount: f64,
    #[serde(default = "default_seq")]
    seq: u64,
    #[serde(default = "default_prev_hash")]
    prev_hash: String,
    #[serde(default)]
    timestamp: u64,
    #[serde(default = "default_asset")]
    asset: String,
    #[serde(default = "default_user_sig")]
    user_sig: String,
}

fn default_seq() -> u64 { 1 }
fn default_prev_hash() -> String { "0000".into() }
fn default_asset() -> String { "USDC".into() }
fn default_user_sig() -> String { "placeholder".into() }

#[derive(Serialize)]
struct AttestResult {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction: Option<TxOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct TxOutput {
    seq: u64,
    prev_hash: String,
    sender: String,
    recipient: String,
    amount: f64,
    asset: String,
    timestamp: u64,
    program_cid: String,
    user_sig: String,
}

/// Allocate memory for the host to write into.
#[unsafe(no_mangle)]
pub extern "C" fn guest_alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Main attestation entry point.
/// Takes a pointer to request JSON, returns packed (ptr << 32 | len) to result JSON.
#[unsafe(no_mangle)]
pub extern "C" fn attest(request_ptr: *const u8, request_len: u32) -> u64 {
    let request_bytes = unsafe { std::slice::from_raw_parts(request_ptr, request_len as usize) };
    let request_str = std::str::from_utf8(request_bytes).unwrap_or("");
    let result = do_attest(request_str);
    let bytes = result.into_bytes();
    let len = bytes.len() as u64;
    let ptr = bytes.as_ptr() as u64;
    std::mem::forget(bytes);
    (ptr << 32) | len
}

fn invalid(reason: &str) -> String {
    serde_json::to_string(&AttestResult {
        status: "invalid".into(),
        transaction: None,
        reason: Some(reason.into()),
    }).unwrap()
}

fn do_attest(request_json: &str) -> String {
    let req: TransferRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => return invalid(&format!("parse error: {e}")),
    };

    log_info(&format!("Transfer {} -> {}: {}", req.requester, req.args.recipient, req.args.amount));

    if req.args.amount <= 0.0 {
        return invalid("amount must be positive");
    }

    // Query balance
    let balance_json = sql_query(
        "balances",
        "SELECT balance FROM accounts WHERE did = ?",
        &serde_json::to_string(&[&req.requester]).unwrap(),
    );

    let balance: f64 = match serde_json::from_str::<Vec<Vec<serde_json::Value>>>(&balance_json) {
        Ok(rows) if !rows.is_empty() => rows[0][0].as_f64().unwrap_or(0.0),
        _ => 0.0,
    };

    if req.args.amount > balance {
        return invalid("insufficient balance");
    }

    // Check recipient exists
    let recipient_json = sql_query(
        "balances",
        "SELECT 1 FROM accounts WHERE did = ?",
        &serde_json::to_string(&[&req.args.recipient]).unwrap(),
    );

    let recipient_exists = match serde_json::from_str::<Vec<Vec<serde_json::Value>>>(&recipient_json) {
        Ok(rows) => !rows.is_empty(),
        _ => false,
    };

    if !recipient_exists {
        return invalid("recipient does not exist");
    }

    serde_json::to_string(&AttestResult {
        status: "valid".into(),
        transaction: Some(TxOutput {
            seq: req.args.seq,
            prev_hash: req.args.prev_hash,
            sender: req.requester,
            recipient: req.args.recipient,
            amount: req.args.amount,
            asset: req.args.asset,
            timestamp: req.args.timestamp,
            program_cid: req.program_cid,
            user_sig: req.args.user_sig,
        }),
        reason: None,
    }).unwrap()
}
