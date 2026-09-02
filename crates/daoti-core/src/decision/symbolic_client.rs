//! Python 道体符号推理 HTTP 客户端。

use super::DaotiSymbolicOutput;
use reqwest::Client;
use std::time::Duration;

#[derive(Clone)]
pub struct SymbolicInferenceClient {
    client: Client,
    endpoint: String,
    api_key: Option<String>,
}

impl SymbolicInferenceClient {
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(endpoint) = std::env::var_os("DAOTI_SYMBOLIC_INFER_URL") else {
            return Ok(None);
        };
        let endpoint = endpoint.to_string_lossy().trim_end_matches('/').to_string();
        if endpoint.is_empty() {
            return Err("DAOTI_SYMBOLIC_INFER_URL 不能为空".into());
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| format!("符号推理 HTTP 客户端创建失败：{error}"))?;
        Ok(Some(Self {
            client,
            endpoint,
            api_key: std::env::var("DAOTI_SYMBOLIC_API_KEY").ok(),
        }))
    }

    pub async fn infer(&self, text: &str) -> Result<DaotiSymbolicOutput, String> {
        if text.trim().is_empty() {
            return Err("符号推理输入不能为空".into());
        }
        let mut request = self
            .client
            .post(format!("{}/api/symbolic/infer", self.endpoint))
            .json(&serde_json::json!({ "text": text }));
        if let Some(key) = &self.api_key {
            request = request.header("X-API-Key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("符号推理请求失败：{error}"))?;
        if !response.status().is_success() {
            return Err(format!("符号推理服务返回 HTTP {}", response.status()));
        }
        let output = response
            .json::<DaotiSymbolicOutput>()
            .await
            .map_err(|error| format!("符号推理响应解析失败：{error}"))?;
        output.validate()?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 空环境变量不创建客户端() {
        std::env::remove_var("DAOTI_SYMBOLIC_INFER_URL");
        assert!(SymbolicInferenceClient::from_env().unwrap().is_none());
    }
}
