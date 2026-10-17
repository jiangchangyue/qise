//! Tauri IPC commands called from the React frontend.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::{qise_cli, SharedState};

#[derive(Deserialize, Serialize)]
pub struct GuardInfo {
    name: String,
    mode: String,
    pipeline: String,
    primary_strategy: String,
}

#[derive(Serialize)]
pub struct CommandText {
    stdout: String,
    stderr: String,
    success: bool,
    exit_status: String,
}

impl From<qise_cli::QiseOutput> for CommandText {
    fn from(output: qise_cli::QiseOutput) -> Self {
        Self {
            stdout: output.stdout,
            stderr: output.stderr,
            success: output.success,
            exit_status: output.exit_status,
        }
    }
}

#[tauri::command]
pub async fn get_status() -> Result<Value, String> {
    qise_cli::run_json(qise_cli::args_with_default_config(&["status", "--json"])).await
}

#[tauri::command]
pub async fn get_doctor() -> Result<Value, String> {
    qise_cli::run_json_permissive(qise_cli::args_with_default_config(&["doctor", "--json"])).await
}

#[tauri::command]
pub async fn get_slm_status() -> Result<Value, String> {
    qise_cli::run_json_permissive(qise_cli::args_with_default_config(&[
        "slm", "status", "--json",
    ]))
    .await
}

#[tauri::command]
pub async fn get_events(limit: usize) -> Result<Vec<Value>, String> {
    let limit_arg = limit.clamp(1, 500).to_string();
    let value = qise_cli::run_json(vec![
        "events".to_string(),
        "--limit".to_string(),
        limit_arg,
        "--json".to_string(),
    ])
    .await?;

    value
        .as_array()
        .cloned()
        .ok_or_else(|| "Qise events output was not a JSON array.".to_string())
}

#[tauri::command]
pub async fn scan_skill(path: String) -> Result<Value, String> {
    let mut args = qise_cli::args_with_default_config(&["scan", "skill"]);
    args.push(path);
    args.push("--json".to_string());
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn scan_mcp(path: String) -> Result<Value, String> {
    let mut args = qise_cli::args_with_default_config(&["scan", "mcp"]);
    args.push(path);
    args.push("--json".to_string());
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn scan_agent_config(agent: String) -> Result<Value, String> {
    let mut args = qise_cli::args_with_default_config(&["scan", "agent-config"]);
    args.push(agent);
    args.push("--json".to_string());
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn scan_agent_assets(
    agent: String,
    include_skills: bool,
    include_mcp: bool,
    include_agent_config: bool,
) -> Result<Value, String> {
    let mut args = qise_cli::args_with_default_config(&["scan", "agent"]);
    args.push(agent);
    if !include_skills {
        args.push("--no-skills".to_string());
    }
    if !include_mcp {
        args.push("--no-mcp".to_string());
    }
    if !include_agent_config {
        args.push("--no-agent-config".to_string());
    }
    args.push("--json".to_string());
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn scan_all_agents(
    agents: Vec<String>,
    include_missing: bool,
    include_skills: bool,
    include_mcp: bool,
    include_agent_config: bool,
) -> Result<Value, String> {
    let mut args = qise_cli::args_with_default_config(&["scan", "all"]);
    if !agents.is_empty() {
        args.push("--agents".to_string());
        args.push(agents.join(","));
    }
    if include_missing {
        args.push("--include-missing".to_string());
    }
    if !include_skills {
        args.push("--no-skills".to_string());
    }
    if !include_mcp {
        args.push("--no-mcp".to_string());
    }
    if !include_agent_config {
        args.push("--no-agent-config".to_string());
    }
    args.push("--json".to_string());
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn slm_start(
    model: String,
    base_url: String,
    api_key: String,
    timeout_ms: u32,
    no_install: bool,
    no_pull: bool,
    no_verify: bool,
) -> Result<CommandText, String> {
    let mut args = qise_cli::args_with_default_config(&["slm", "start"]);
    args.extend([
        "--model".to_string(),
        model,
        "--base-url".to_string(),
        base_url,
        "--timeout-ms".to_string(),
        timeout_ms.to_string(),
    ]);
    if !api_key.trim().is_empty() {
        args.extend(["--api-key".to_string(), api_key]);
    }
    if no_install {
        args.push("--no-install".to_string());
    }
    if no_pull {
        args.push("--no-pull".to_string());
    }
    if no_verify {
        args.push("--no-verify".to_string());
    }
    Ok(qise_cli::run_permissive(args).await?.into())
}

#[tauri::command]
pub async fn slm_stop(keep_server: bool) -> Result<CommandText, String> {
    let mut args = qise_cli::args_with_default_config(&["slm", "stop"]);
    if keep_server {
        args.push("--keep-server".to_string());
    }
    Ok(qise_cli::run_permissive(args).await?.into())
}

#[tauri::command]
pub async fn run_check(
    tool_name: String,
    tool_args: String,
    pipeline: String,
    session_id: String,
) -> Result<Value, String> {
    let normalized_pipeline = match pipeline.as_str() {
        "ingress" | "egress" | "output" => pipeline,
        _ => "egress".to_string(),
    };
    let mut args = qise_cli::args_with_default_config(&["check"]);
    args.push(tool_name);
    args.push(tool_args);
    args.extend(["--pipeline".to_string(), normalized_pipeline]);
    if !session_id.trim().is_empty() {
        args.extend(["--session-id".to_string(), session_id]);
    }
    qise_cli::run_json_permissive(args).await
}

#[tauri::command]
pub async fn get_context(tool_name: String, tool_args: String) -> Result<String, String> {
    let mut args = qise_cli::args_with_default_config(&["context"]);
    args.push(tool_name);
    if !tool_args.trim().is_empty() {
        args.extend(["--tool-args".to_string(), tool_args]);
    }
    Ok(qise_cli::run(args).await?.stdout)
}

#[tauri::command]
pub async fn get_adapter_snippet(adapter: String) -> Result<String, String> {
    let adapter = match adapter.as_str() {
        "nanobot" | "hermes" | "nexau" | "langgraph" | "openai-agents" => adapter,
        _ => return Err(format!("Unsupported adapter: {}", adapter)),
    };
    Ok(qise_cli::run(qise_cli::args(&["adapters", &adapter]))
        .await?
        .stdout)
}

#[tauri::command]
pub async fn stop_qise_services() -> Result<CommandText, String> {
    Ok(qise_cli::run_permissive(qise_cli::args(&["stop"]))
        .await?
        .into())
}

#[tauri::command]
pub async fn restore_all_agents() -> Result<CommandText, String> {
    Ok(
        qise_cli::run_permissive(qise_cli::args(&["restore", "all"]))
            .await?
            .into(),
    )
}

#[tauri::command]
pub async fn detect_agents() -> Result<Vec<Value>, String> {
    let agents = qise_cli::run_json(qise_cli::args(&["agents", "--json"])).await?;
    agents
        .get("agents")
        .and_then(|value| value.as_array())
        .cloned()
        .ok_or_else(|| "Qise agents output did not include agents.".to_string())
}

#[tauri::command]
pub async fn takeover_agent(agent: String) -> Result<(), String> {
    let mut args = qise_cli::args_with_default_config(&["protect"]);
    args.push(agent);
    qise_cli::run(args).await?;
    Ok(())
}

#[tauri::command]
pub async fn protect_agent_with_options(
    agent: String,
    base_url: String,
    experimental: bool,
) -> Result<CommandText, String> {
    let mut args = qise_cli::args_with_default_config(&["protect"]);
    args.push(agent);
    if !base_url.trim().is_empty() {
        args.extend(["--base-url".to_string(), base_url]);
    }
    if experimental {
        args.push("--experimental".to_string());
    }
    Ok(qise_cli::run_permissive(args).await?.into())
}

#[tauri::command]
pub async fn restore_agent(agent: String) -> Result<(), String> {
    qise_cli::run(vec!["restore".to_string(), agent]).await?;
    Ok(())
}

#[tauri::command]
pub async fn get_takeover_status() -> Result<Value, String> {
    let status =
        qise_cli::run_json(qise_cli::args_with_default_config(&["status", "--json"])).await?;
    Ok(status
        .get("protected_agents")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({})))
}

#[tauri::command]
pub async fn get_guards() -> Result<Vec<GuardInfo>, String> {
    let value =
        qise_cli::run_json(qise_cli::args_with_default_config(&["guards", "--json"])).await?;
    serde_json::from_value(value)
        .map_err(|error| format!("Invalid Qise guards response: {}", error))
}

#[tauri::command]
pub async fn set_guard_mode(guard_name: String, mode: String) -> Result<(), String> {
    qise_cli::run_json(qise_cli::args_with_default_config(&[
        "guards",
        "--set",
        &guard_name,
        &mode,
        "--json",
    ]))
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn toggle_protection(enable: bool) -> Result<(), String> {
    if enable {
        return Err(
            "Desktop no longer starts an embedded proxy without an upstream. Use Protect on an installed Agent; Qise will start managed services when protection succeeds."
                .to_string(),
        );
    }

    qise_cli::run(qise_cli::args(&["stop"])).await?;
    qise_cli::run(qise_cli::args(&["restore", "all"])).await?;
    Ok(())
}

#[tauri::command]
pub async fn get_config_path(state: State<'_, SharedState>) -> Result<String, String> {
    let s = state.lock().await;
    if s.config_path.is_empty() {
        default_config_path()
    } else {
        Ok(s.config_path.clone())
    }
}

#[tauri::command]
pub async fn get_config(state: State<'_, SharedState>) -> Result<Value, String> {
    let s = state.lock().await;
    let config_path = if s.config_path.is_empty() {
        default_config_path()?
    } else {
        s.config_path.clone()
    };

    match std::fs::read_to_string(&config_path) {
        Ok(content) => serde_yaml::from_str::<Value>(&content)
            .map_err(|e| format!("Failed to parse shield.yaml: {}", e)),
        Err(_) => Ok(default_config()),
    }
}

#[tauri::command]
pub async fn save_config(config: Value, state: State<'_, SharedState>) -> Result<(), String> {
    let s = state.lock().await;
    let config_path = if s.config_path.is_empty() {
        default_config_path()?
    } else {
        s.config_path.clone()
    };
    drop(s);

    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let yaml_str =
        serde_yaml::to_string(&config).map_err(|e| format!("Failed to serialize config: {}", e))?;

    let temp_path = format!("{}.tmp", config_path);
    std::fs::write(&temp_path, &yaml_str).map_err(|e| format!("Failed to write config: {}", e))?;
    std::fs::rename(&temp_path, &config_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_path);
        format!("Failed to rename config file: {}", e)
    })?;

    tracing::info!("Config saved to {}", config_path);
    Ok(())
}

#[tauri::command]
pub async fn get_default_config() -> Result<Value, String> {
    Ok(default_config())
}

fn default_config_path() -> Result<String, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "Cannot determine home directory".to_string())?;
    Ok(format!("{}/.qise/shield.yaml", home))
}

fn default_config() -> Value {
    serde_json::json!({
        "version": "1.0",
        "integration": {
            "mode": "proxy",
            "proxy": {
                "port": 8822,
                "target_agents": ["codex", "openclaw"],
                "auto_takeover": true,
                "crash_recovery": true,
                "upstream_url": "",
                "upstream_api_key": ""
            }
        },
        "models": {
            "slm": {
                "base_url": "http://localhost:11434/v1",
                "model": "",
                "timeout_ms": 5000
            },
            "llm": {
                "base_url": "",
                "model": "",
                "timeout_ms": 5000
            }
        },
        "guards": {
            "enabled": [
                "prompt", "command", "credential", "reasoning",
                "filesystem", "network", "exfil", "resource", "audit",
                "tool_sanity", "context", "output", "tool_policy", "supply_chain"
            ],
            "config": {}
        }
    })
}
