use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Geocache {
    pub id: Option<i64>,
    pub short_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub view_key: String,
    pub spend_pub_key: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGeocache {
    pub name: String,
    pub description: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub view_key: String,
    pub spend_pub_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GuestbookEntry {
    pub id: i64,
    pub geocache_id: i64,
    pub full_memo: String,
    pub from_address: String,
    pub memo_string: Option<String>,
    pub output_hash: String,
    pub effective_date_time: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct GuestbookResponse {
    pub entries: Vec<GuestbookEntry>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
}
