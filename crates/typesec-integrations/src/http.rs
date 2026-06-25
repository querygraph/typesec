//! Small synchronous HTTP abstraction used by provider-backed policy engines.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

/// Minimal HTTP client interface for JSON POST/GET calls.
pub trait HttpClient: Send + Sync {
    /// Perform a JSON GET request.
    fn get_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>>;

    /// Perform a JSON POST request.
    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>>;
}

/// `reqwest`-backed implementation of [`HttpClient`].
pub struct ReqwestHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpClient {
    /// Create a client with a 30-second request timeout.
    ///
    /// Falls back to reqwest defaults if the timeout-configured builder fails.
    pub fn new() -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self { client }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for ReqwestHttpClient {
    fn get_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.client.get(url);
        for (name, value) in headers {
            req = req.header(*name, value);
        }
        Ok(req.send()?.error_for_status()?.json()?)
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut req = self.client.post(url).json(body);
        for (name, value) in headers {
            req = req.header(*name, value);
        }
        Ok(req.send()?.error_for_status()?.json()?)
    }
}

/// Test helper that returns preconfigured responses for exact URLs.
#[derive(Default)]
pub struct StaticHttpClient {
    responses: HashMap<String, Value>,
}

impl StaticHttpClient {
    /// Create an empty static client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a response for `url`.
    pub fn with_response(mut self, url: impl Into<String>, value: Value) -> Self {
        self.responses.insert(url.into(), value);
        self
    }
}

impl HttpClient for StaticHttpClient {
    fn get_json(
        &self,
        url: &str,
        _headers: &[(&str, String)],
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| format!("no static response for {url}").into())
    }

    fn post_json(
        &self,
        url: &str,
        _headers: &[(&str, String)],
        _body: &Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| format!("no static response for {url}").into())
    }
}

/// Captured request made through [`RecordingHttpClient`].
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedRequest {
    /// HTTP method.
    pub method: &'static str,
    /// Request URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Optional JSON body.
    pub body: Option<Value>,
}

/// Static client that also records every request it receives.
#[derive(Clone, Default)]
pub struct RecordingHttpClient {
    responses: HashMap<String, Value>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl RecordingHttpClient {
    /// Create an empty recording client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a response for `url`.
    pub fn with_response(mut self, url: impl Into<String>, value: Value) -> Self {
        self.responses.insert(url.into(), value);
        self
    }

    /// Return all captured requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("recording client lock poisoned")
            .clone()
    }

    fn record(
        &self,
        method: &'static str,
        url: &str,
        headers: &[(&str, String)],
        body: Option<&Value>,
    ) {
        self.requests
            .lock()
            .expect("recording client lock poisoned")
            .push(RecordedRequest {
                method,
                url: url.to_string(),
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), value.clone()))
                    .collect(),
                body: body.cloned(),
            });
    }
}

impl HttpClient for RecordingHttpClient {
    fn get_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.record("GET", url, headers, None);
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| format!("no static response for {url}").into())
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.record("POST", url, headers, Some(body));
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| format!("no static response for {url}").into())
    }
}
