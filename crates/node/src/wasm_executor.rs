//! WASM program executor — loads and runs WASM attestation programs via wasmtime.
//!
//! WASM guest protocol:
//! - Guest exports: `attest(ptr, len) -> u64` (packed ptr<<32|len of result JSON)
//! - Guest exports: `guest_alloc(len) -> ptr` (allocator for host to write into guest memory)
//! - Guest imports from "env":
//!   - `host_sql_query(db_ptr,db_len, sql_ptr,sql_len, params_ptr,params_len) -> u64` (packed ptr<<32|len)
//!   - `host_log(level, msg_ptr, msg_len)`

use craftsec_core::{AttestationRequest, AttestationResult, CraftSecError, Result, Transaction};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasmtime::*;

/// In-memory SQL database stub for WASM host functions.
pub struct SqlDatabase {
    conn: Connection,
}

impl SqlDatabase {
    pub fn new() -> Self {
        let conn = Connection::open_in_memory().expect("failed to open in-memory SQLite");
        Self { conn }
    }

    pub fn execute(&self, sql: &str) -> std::result::Result<(), String> {
        self.conn.execute_batch(sql).map_err(|e| e.to_string())
    }

    pub fn query(&self, sql: &str, params_json: &str) -> String {
        let params: Vec<serde_json::Value> = serde_json::from_str(params_json).unwrap_or_default();

        let result: std::result::Result<String, String> = (|| {
            let mut stmt = self.conn.prepare(sql).map_err(|e| e.to_string())?;
            let column_count = stmt.column_count();

            let param_values: Vec<Box<dyn rusqlite::types::ToSql>> = params
                .iter()
                .map(|v| -> Box<dyn rusqlite::types::ToSql> {
                    match v {
                        serde_json::Value::String(s) => Box::new(s.clone()),
                        serde_json::Value::Number(n) => {
                            if let Some(i) = n.as_i64() { Box::new(i) }
                            else if let Some(f) = n.as_f64() { Box::new(f) }
                            else { Box::new(n.to_string()) }
                        }
                        serde_json::Value::Bool(b) => Box::new(*b),
                        serde_json::Value::Null => Box::new(rusqlite::types::Null),
                        _ => Box::new(v.to_string()),
                    }
                })
                .collect();

            let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

            let rows: Vec<Vec<serde_json::Value>> = stmt
                .query_map(param_refs.as_slice(), |row| {
                    let mut cols = Vec::new();
                    for i in 0..column_count {
                        let val: rusqlite::types::Value = row.get(i)?;
                        cols.push(match val {
                            rusqlite::types::Value::Null => serde_json::Value::Null,
                            rusqlite::types::Value::Integer(i) => serde_json::json!(i),
                            rusqlite::types::Value::Real(f) => serde_json::json!(f),
                            rusqlite::types::Value::Text(s) => serde_json::json!(s),
                            rusqlite::types::Value::Blob(b) => serde_json::json!(hex::encode(b)),
                        });
                    }
                    Ok(cols)
                })
                .map_err(|e| e.to_string())?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;

            serde_json::to_string(&rows).map_err(|e| e.to_string())
        })();

        result.unwrap_or_else(|_| "[]".to_string())
    }
}

impl Default for SqlDatabase {
    fn default() -> Self { Self::new() }
}

/// Host state accessible from WASM host functions.
struct HostState {
    databases: Arc<Mutex<HashMap<String, SqlDatabase>>>,
}

/// Registry that loads WASM modules by CID, caches compiled modules.
pub struct WasmProgramRegistry {
    engine: Engine,
    modules: HashMap<String, Module>,
    databases: Arc<Mutex<HashMap<String, SqlDatabase>>>,
}

impl WasmProgramRegistry {
    pub fn new() -> Self {
        Self {
            engine: Engine::default(),
            modules: HashMap::new(),
            databases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_wasm(&mut self, cid: impl Into<String>, wasm_bytes: &[u8]) -> Result<()> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| CraftSecError::ProgramError(format!("failed to compile WASM: {e}")))?;
        self.modules.insert(cid.into(), module);
        Ok(())
    }

    pub fn setup_database(&self, name: &str, sql: &str) -> Result<()> {
        let mut dbs = self.databases.lock().unwrap();
        let db = dbs.entry(name.to_string()).or_default();
        db.execute(sql).map_err(|e| CraftSecError::ProgramError(format!("SQL setup error: {e}")))?;
        Ok(())
    }

    pub fn execute(&self, request: &AttestationRequest) -> Result<AttestationResult> {
        let module = self.modules.get(&request.program_cid).ok_or_else(|| {
            CraftSecError::ProgramError(format!("unknown program CID: {}", request.program_cid))
        })?;

        let mut store = Store::new(&self.engine, HostState {
            databases: Arc::clone(&self.databases),
        });

        let mut linker = Linker::new(&self.engine);

        // host_log(level, msg_ptr, msg_len)
        linker.func_wrap("env", "host_log",
            |mut caller: Caller<'_, HostState>, level: u32, msg_ptr: u32, msg_len: u32| {
                let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
                let data = memory.data(&caller);
                let msg = String::from_utf8_lossy(&data[msg_ptr as usize..(msg_ptr + msg_len) as usize]);
                let level_str = match level { 0 => "DEBUG", 1 => "INFO", 2 => "WARN", 3 => "ERROR", _ => "?" };
                eprintln!("[WASM {level_str}] {msg}");
            },
        ).map_err(|e| CraftSecError::ProgramError(format!("linker: {e}")))?;

        // host_sql_query(db_ptr,db_len, sql_ptr,sql_len, params_ptr,params_len) -> u64
        linker.func_wrap("env", "host_sql_query",
            |mut caller: Caller<'_, HostState>,
             db_ptr: u32, db_len: u32,
             sql_ptr: u32, sql_len: u32,
             params_ptr: u32, params_len: u32| -> u64 {
                let memory = caller.get_export("memory").unwrap().into_memory().unwrap();

                // Read strings from guest memory
                let db_name = {
                    let data = memory.data(&caller);
                    String::from_utf8_lossy(&data[db_ptr as usize..(db_ptr + db_len) as usize]).into_owned()
                };
                let sql = {
                    let data = memory.data(&caller);
                    String::from_utf8_lossy(&data[sql_ptr as usize..(sql_ptr + sql_len) as usize]).into_owned()
                };
                let params = {
                    let data = memory.data(&caller);
                    String::from_utf8_lossy(&data[params_ptr as usize..(params_ptr + params_len) as usize]).into_owned()
                };

                let result = {
                    let dbs = caller.data().databases.lock().unwrap();
                    if let Some(db) = dbs.get(&db_name) {
                        db.query(&sql, &params)
                    } else {
                        "[]".to_string()
                    }
                };

                let result_bytes = result.into_bytes();
                let len = result_bytes.len() as u32;

                // Allocate in guest via guest_alloc
                let guest_alloc = caller.get_export("guest_alloc").unwrap().into_func().unwrap();
                let mut alloc_result = vec![Val::I32(0)];
                guest_alloc.call(&mut caller, &[Val::I32(len as i32)], &mut alloc_result).unwrap();
                let ptr = alloc_result[0].unwrap_i32() as u32;

                // Write result to guest memory
                let memory = caller.get_export("memory").unwrap().into_memory().unwrap();
                memory.data_mut(&mut caller)[ptr as usize..ptr as usize + len as usize]
                    .copy_from_slice(&result_bytes);

                ((ptr as u64) << 32) | (len as u64)
            },
        ).map_err(|e| CraftSecError::ProgramError(format!("linker: {e}")))?;

        let instance = linker.instantiate(&mut store, module)
            .map_err(|e| CraftSecError::ProgramError(format!("instantiation failed: {e}")))?;

        // Build request JSON
        let request_json = serde_json::to_string(&serde_json::json!({
            "requester": request.requester,
            "program_cid": request.program_cid,
            "args": request.args,
        })).map_err(|e| CraftSecError::SerializationError(e.to_string()))?;

        // Allocate in guest and write request
        let guest_alloc = instance.get_func(&mut store, "guest_alloc")
            .ok_or_else(|| CraftSecError::ProgramError("no guest_alloc export".into()))?;
        let request_bytes = request_json.as_bytes();
        let mut alloc_result = vec![Val::I32(0)];
        guest_alloc.call(&mut store, &[Val::I32(request_bytes.len() as i32)], &mut alloc_result)
            .map_err(|e| CraftSecError::ProgramError(format!("guest_alloc failed: {e}")))?;
        let request_ptr = alloc_result[0].unwrap_i32() as u32;

        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| CraftSecError::ProgramError("no memory export".into()))?;
        memory.data_mut(&mut store)[request_ptr as usize..request_ptr as usize + request_bytes.len()]
            .copy_from_slice(request_bytes);

        // Call attest
        let attest_fn = instance.get_func(&mut store, "attest")
            .ok_or_else(|| CraftSecError::ProgramError("no 'attest' export".into()))?;
        let mut results = vec![Val::I64(0)];
        attest_fn.call(
            &mut store,
            &[Val::I32(request_ptr as i32), Val::I32(request_bytes.len() as i32)],
            &mut results,
        ).map_err(|e| CraftSecError::ProgramError(format!("WASM execution failed: {e}")))?;

        let packed = results[0].unwrap_i64() as u64;
        let result_ptr = (packed >> 32) as u32;
        let result_len = (packed & 0xFFFFFFFF) as u32;

        let memory = instance.get_memory(&mut store, "memory")
            .ok_or_else(|| CraftSecError::ProgramError("no memory export".into()))?;
        let result_bytes = &memory.data(&store)[result_ptr as usize..(result_ptr + result_len) as usize];
        let result_str = std::str::from_utf8(result_bytes)
            .map_err(|e| CraftSecError::ProgramError(format!("invalid UTF-8: {e}")))?;

        let result: serde_json::Value = serde_json::from_str(result_str)
            .map_err(|e| CraftSecError::ProgramError(format!("invalid JSON: {e}")))?;

        match result["status"].as_str() {
            Some("valid") => {
                let tx: Transaction = serde_json::from_value(result["transaction"].clone())
                    .map_err(|e| CraftSecError::ProgramError(format!("invalid transaction: {e}")))?;
                Ok(AttestationResult::Valid(tx))
            }
            Some("invalid") => {
                Ok(AttestationResult::Invalid(result["reason"].as_str().unwrap_or("unknown").to_string()))
            }
            _ => Err(CraftSecError::ProgramError("invalid result status".into())),
        }
    }
}

impl Default for WasmProgramRegistry {
    fn default() -> Self { Self::new() }
}
