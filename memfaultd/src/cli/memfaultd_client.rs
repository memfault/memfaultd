//
// Copyright (c) Memfault, Inc.
// See License.txt for details
use std::{io::Read, str::from_utf8, time::Duration};

use chrono::{DateTime, Utc};
use eyre::{eyre, Context, Result};
use reqwest::{
    blocking::{Body, Client, Response},
    header::ACCEPT,
    StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    http_server::{MetricsRequest, SessionRequest},
    mar::{ExportFormat, EXPORT_MAR_URL},
    metrics::{KeyedMetricReading, SessionName},
};

/// Client to Memfaultd localhost HTTP API
pub struct MemfaultdClient {
    base_url: String,
    client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct NotifyCrashRequest {
    pub process_name: String,
}

pub struct DeleteToken(String);

pub enum ExportGetResponse {
    Data {
        delete_token: DeleteToken,
        data: Box<dyn Read>,
    },
    NoData,
}

pub enum ExportDeleteResponse {
    Ok,
    ErrorWrongDeleteToken,
    Error404,
}

impl MemfaultdClient {
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(MemfaultdClient {
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            base_url: format!("http://{}", config.config_file.http_server.bind_address),
        })
    }

    pub fn export_get(&self, format: &ExportFormat) -> Result<ExportGetResponse> {
        let r = self
            .client
            .get(format!("{}{}", self.base_url, EXPORT_MAR_URL))
            .header(ACCEPT, format.to_content_type())
            .send()
            .wrap_err_with(|| {
                eyre!(format!(
                    "Error fetching {}/{}",
                    self.base_url, EXPORT_MAR_URL
                ))
            })?;
        match r.status() {
            StatusCode::OK => Ok(ExportGetResponse::Data {
                delete_token: DeleteToken(
                    r.headers()
                        .iter()
                        .find(|h| h.0.as_str() == "etag")
                        .ok_or(eyre!("No ETag header included on the response"))
                        .map(|etag| etag.1.to_str())??
                        .trim_matches('"')
                        .to_owned(),
                ),
                data: Box::new(r),
            }),
            StatusCode::NO_CONTENT => Ok(ExportGetResponse::NoData),
            StatusCode::NOT_ACCEPTABLE => Err(eyre!("Requested format not supported")),
            _ => Err(eyre!("Unexpected status code {}", r.status().as_u16())),
        }
    }

    pub fn export_delete(&self, delete_token: DeleteToken) -> Result<ExportDeleteResponse> {
        let r = self
            .client
            .delete(format!("{}{}", self.base_url, EXPORT_MAR_URL))
            .header("If-Match", delete_token.0)
            .send()?;
        match r.status() {
            StatusCode::NO_CONTENT => Ok(ExportDeleteResponse::Ok),
            StatusCode::PRECONDITION_FAILED => Ok(ExportDeleteResponse::ErrorWrongDeleteToken),
            StatusCode::NOT_FOUND => Ok(ExportDeleteResponse::Error404),
            _ => Err(eyre!(format!(
                "Unexpected status code {}",
                r.status().as_u16()
            ))),
        }
    }

    pub fn add_battery_reading(&self, battery_reading_string: &str) -> Result<()> {
        let r = self
            .client
            .post(format!("{}{}", self.base_url, "/v1/battery/add_reading"))
            .body(battery_reading_string.to_string())
            .send()?;
        match r.status() {
            StatusCode::OK => Ok(()),
            _ => Err(eyre!(
                "Unexpected status code {}: {}",
                r.status().as_u16(),
                from_utf8(&r.bytes()?)?
            )),
        }
    }

    pub fn notify_crash(&self, comm: String) -> Result<()> {
        self.client
            .post(format!("{}{}", self.base_url, "/v1/crash/report"))
            .json(&NotifyCrashRequest { process_name: comm })
            .send()?;
        Ok(())
    }

    pub fn report_sync(&self, success: bool) -> Result<()> {
        let path = if success {
            "/v1/sync/success"
        } else {
            "/v1/sync/failure"
        };
        let r = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .send()?;
        match r.status() {
            StatusCode::OK => Ok(()),
            _ => Err(eyre!(
                "Unexpected status code {}: {}",
                r.status().as_u16(),
                from_utf8(&r.bytes()?)?
            )),
        }
    }

    pub fn start_session(
        &self,
        session_name: SessionName,
        readings: Vec<KeyedMetricReading>,
    ) -> Result<()> {
        let body = build_session_request(session_name, readings)?;
        let r = self.post_url("/v1/session/start", body)?;
        match r.status() {
            StatusCode::OK => Ok(()),
            _ => Err(eyre!(
                "Unexpected status code {}: {}",
                r.status().as_u16(),
                from_utf8(&r.bytes()?)?
            )),
        }
    }

    pub fn end_session(
        &self,
        session_name: SessionName,
        readings: Vec<KeyedMetricReading>,
    ) -> Result<()> {
        let body = build_session_request(session_name, readings)?;
        let r = self.post_url("/v1/session/end", body)?;
        match r.status() {
            StatusCode::OK => Ok(()),
            _ => Err(eyre!(
                "Unexpected status code {}: {}",
                r.status().as_u16(),
                from_utf8(&r.bytes()?)?
            )),
        }
    }

    #[cfg(feature = "logging")]
    pub fn get_crash_logs(&self, time_of_crash: DateTime<Utc>) -> Result<Option<Vec<String>>> {
        use crate::logs::log_collector::{CrashLogs, CRASH_LOGS_URL};

        let r = self
            .client
            .get(format!(
                "{}{}?time_of_crash={}",
                self.base_url,
                CRASH_LOGS_URL,
                time_of_crash.to_rfc3339()
            ))
            .send()?;

        match r.status() {
            StatusCode::OK => Ok(Some(r.json::<CrashLogs>()?.logs)),
            _ => Err(eyre!("Unexpected status code {}", r.status().as_u16())),
        }
    }

    pub fn post_metrics(&self, readings: Vec<KeyedMetricReading>) -> Result<()> {
        let request = MetricsRequest::new(readings);
        let body = serde_json::to_string(&request)?;
        let r = self.post_url("/v1/metrics", body)?;
        match r.status() {
            StatusCode::OK => Ok(()),
            _ => Err(eyre!(
                "Unexpected status code {}: {}",
                r.status().as_u16(),
                from_utf8(&r.bytes()?)?
            )),
        }
    }

    #[cfg(not(feature = "logging"))]
    pub fn get_crash_logs(&self, _time_of_crash: DateTime<Utc>) -> Result<Option<Vec<String>>> {
        Ok(None)
    }

    fn post_url<T: Into<Body>>(&self, url: &str, body: T) -> Result<Response> {
        self.client
            .post(format!("{}{}", self.base_url, url))
            .body(body)
            .send()
            .map_err(|_| eyre!("Failed to POST to {}. Is memfaultd running?", url))
    }
}

fn build_session_request(
    session_name: SessionName,
    readings: Vec<KeyedMetricReading>,
) -> Result<String> {
    if readings.is_empty() {
        Ok(session_name.to_string())
    } else {
        Ok(serde_json::to_string(&SessionRequest::new(
            session_name,
            readings,
        ))?)
    }
}
