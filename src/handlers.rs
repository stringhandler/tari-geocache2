use axum::{
    extract::{Json, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use tari_common::configuration::Network;
use tari_common_types::{
    tari_address::{TariAddress, TariAddressFeatures},
    types::CompressedPublicKey,
};
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_utilities::ByteArray;
use tokio::process::Command;

use crate::models::{
    CreateGeocache, Geocache, GuestbookEntry, GuestbookResponse, PaginationParams,
};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub wallet_exe: String,
}

#[derive(Debug, Deserialize)]
struct WalletEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    event: String,
}

fn generate_short_id(view_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update("geocache_short_id");
    hasher.update(view_key.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..6]) // Take first 6 bytes (12 hex chars)
}

async fn process_wallet_events(
    wallet_db_path: &PathBuf,
    geocache_id: i64,
    db_pool: &SqlitePool,
) -> Result<(usize, i64), String> {
    tracing::info!("Processing wallet events from {:?}", wallet_db_path);

    // Get last scanned event ID from geocaches table
    let last_scanned: (Option<i64>,) =
        sqlx::query_as("SELECT last_scanned_event_id FROM geocaches WHERE id = ?")
            .bind(geocache_id)
            .fetch_one(db_pool)
            .await
            .map_err(|e| format!("Failed to get last scanned event: {}", e))?;

    let last_scanned_id = last_scanned.0.unwrap_or(0);
    tracing::info!("Last scanned event ID: {}", last_scanned_id);

    // Connect to wallet database
    let wallet_db_url = format!("sqlite:{}", wallet_db_path.display());
    let wallet_pool = sqlx::SqlitePool::connect_with(
        SqliteConnectOptions::from_str(&wallet_db_url)
            .map_err(|e| format!("Invalid wallet DB URL: {}", e))?,
    )
    .await
    .map_err(|e| format!("Failed to connect to wallet DB: {}", e))?;

    // Query OutputConfirmed events with ID greater than last scanned
    let events: Vec<(i64, String, String)> = sqlx::query_as(
        r#"
        SELECT id, event_type, data_json
        FROM events
        WHERE event_type = 'OutputConfirmed' AND id > ?
        ORDER BY id ASC
        "#,
    )
    .bind(last_scanned_id)
    .fetch_all(&wallet_pool)
    .await
    .map_err(|e| format!("Failed to query events: {}", e))?;

    tracing::info!("Found {} new OutputConfirmed events", events.len());

    let mut inserted_count = 0;
    let mut max_event_id = last_scanned_id;

    for (event_id, event_name, event_data) in events {
        tracing::debug!("Processing event: {} (ID: {})", event_name, event_id);
        max_event_id = max_event_id.max(event_id);

        // Parse event data as JSON
        let event_json: serde_json::Value = serde_json::from_str(&event_data)
            .map_err(|e| format!("Failed to parse event JSON: {}", e))?;

        // Extract fields from the event data
        let output_hash = event_json
            .get("hash")
            .and_then(|v| v.as_array())
            .and_then(|v| Some(v.iter().filter_map(|n| n.as_u64()).collect::<Vec<u64>>()))
            .and_then(|arr| {
                let bytes: Vec<u8> = arr.iter().map(|&n| n as u8).collect();
                if bytes.len() == 32 { Some(bytes) } else { None }
            })
            .and_then(|bytes| Some(hex::encode(bytes)))
            .unwrap_or_else(|| "unknown".to_string());

        let memo = event_json
            .get("memo_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let memo_string = event_json.get("memo_parsed").and_then(|v| v.as_str());

        // Check if this output_hash already exists in guestbook
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM guestbook WHERE output_hash = ? AND geocache_id = ?",
        )
        .bind(output_hash.clone())
        .bind(geocache_id)
        .fetch_one(db_pool)
        .await
        .map_err(|e| format!("Failed to check existing entry: {}", e))?;

        if exists.0 > 0 {
            tracing::debug!("Entry already exists for output_hash: {}", output_hash);
            continue;
        }

        // Insert into guestbook
        let from_address = "unknown";
        // TODO: put in proper values
        let datetime = chrono::Utc::now().naive_utc();
        sqlx::query(
            r#"
            INSERT INTO guestbook (geocache_id, full_memo, from_address, memo_string, output_hash, effective_date_time)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(geocache_id)
        .bind(memo)
        .bind(from_address)
        .bind(memo_string)
        .bind(output_hash.clone())
        .bind(datetime)
        .execute(db_pool)
        .await
        .map_err(|e| format!("Failed to insert guestbook entry: {}", e))?;

        tracing::info!("Inserted guestbook entry for output_hash: {}", output_hash);
        inserted_count += 1;
    }

    wallet_pool.close().await;

    // Update last_scanned_event_id in geocaches table
    if max_event_id > last_scanned_id {
        sqlx::query("UPDATE geocaches SET last_scanned_event_id = ? WHERE id = ?")
            .bind(max_event_id)
            .bind(geocache_id)
            .execute(db_pool)
            .await
            .map_err(|e| format!("Failed to update last_scanned_event_id: {}", e))?;

        tracing::info!(
            "Updated last_scanned_event_id from {} to {}",
            last_scanned_id,
            max_event_id
        );
    }

    Ok((inserted_count, max_event_id))
}

pub async fn create_geocache(
    State(state): State<AppState>,
    Json(payload): Json<CreateGeocache>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: create_geocache called for '{}'", payload.name);
    tracing::debug!("Payload: {:?}", payload);

    // Generate short ID from view key
    let short_id = generate_short_id(&payload.view_key);
    tracing::debug!("Generated short_id: {}", short_id);

    let result = sqlx::query(
        r#"
        INSERT INTO geocaches (short_id, name, description, latitude, longitude, view_key, spend_pub_key)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&short_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.latitude)
    .bind(&payload.longitude)
    .bind(&payload.view_key)
    .bind(&payload.spend_pub_key)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let geocache = Geocache {
        id: Some(result.last_insert_rowid()),
        short_id: Some(short_id.clone()),
        name: payload.name,
        description: payload.description,
        latitude: payload.latitude,
        longitude: payload.longitude,
        view_key: payload.view_key,
        spend_pub_key: payload.spend_pub_key,
        created_at: None,
    };

    tracing::info!("Successfully created geocache with short_id: {}", short_id);
    Ok((StatusCode::CREATED, Json(geocache)))
}

pub async fn get_geocaches(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: get_geocaches called");
    let geocaches = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    tracing::debug!("Retrieved {} geocaches", geocaches.len());
    Ok(Json(geocaches))
}

pub async fn get_geocache(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: get_geocache called for id: {}", id);
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE id = ?
        "#,
        id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    tracing::debug!("Found geocache: {:?}", geocache);
    Ok(Json(geocache))
}

pub async fn get_guestbook(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: get_guestbook called for short_id: {}", short_id);

    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    tracing::debug!(
        "Pagination - page: {}, per_page: {}, offset: {}",
        page,
        per_page,
        offset
    );

    // First, get the geocache_id from short_id
    let geocache: Option<(i64,)> = sqlx::query_as("SELECT id FROM geocaches WHERE short_id = ?")
        .bind(&short_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    let geocache_id = geocache
        .ok_or((StatusCode::NOT_FOUND, "Geocache not found".to_string()))?
        .0;

    // Get total count
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM guestbook WHERE geocache_id = ?")
        .bind(geocache_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    let total_count = total.0;
    let total_pages = (total_count + per_page - 1) / per_page;

    // Get entries
    let entries = sqlx::query_as!(
        GuestbookEntry,
        r#"
        SELECT id, geocache_id, full_memo, from_address, memo_string, output_hash,
               effective_date_time,
               created_at
        FROM guestbook
        WHERE geocache_id = ?
        ORDER BY effective_date_time DESC
        LIMIT ? OFFSET ?
        "#,
        geocache_id,
        per_page,
        offset
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    tracing::debug!(
        "Retrieved {} guestbook entries for geocache_id: {}",
        entries.len(),
        geocache_id
    );

    let response = GuestbookResponse {
        entries,
        total: total_count,
        page,
        per_page,
        total_pages,
    };

    tracing::info!(
        "Returning guestbook response - total: {}, page: {}/{}",
        total_count,
        page,
        total_pages
    );
    Ok(Json(response))
}

pub async fn scan(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: scan called for short_id: {}", short_id);

    // Find geocache by short_id
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    tracing::debug!("Found geocache via scan: {:?}", geocache);

    // Create wallet directory path
    let wallet_dir = PathBuf::from("wallets").join(&short_id);
    let wallet_db = wallet_dir.join("wallet.db");

    tracing::debug!("Wallet directory: {:?}", wallet_dir);

    // Check if wallet already exists
    if !wallet_db.exists() {
        tracing::info!(
            "Wallet does not exist, creating new wallet for {}",
            short_id
        );

        // Create wallet directory
        std::fs::create_dir_all(&wallet_dir).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create wallet directory: {}", e),
            )
        })?;

        // Run import-view-key command
        // Default birthday to 0 for now - could be configurable
        let birthday = "0";
        tracing::info!("Running import-view-key for {}", short_id);

        let output = Command::new(&state.wallet_exe)
            .arg("import-view-key")
            .arg("-v")
            .arg(&geocache.view_key)
            .arg("-s")
            .arg(&geocache.spend_pub_key)
            .arg("-b")
            .arg("1350")
            .arg("-p")
            .arg("test")
            .arg("-d")
            .arg(&wallet_db)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to execute import-view-key: {}", e),
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("import-view-key failed: {}", stderr);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("import-view-key failed: {}", stderr),
            ));
        }

        tracing::info!("Successfully imported view key for {}", short_id);
    } else {
        tracing::info!("Wallet already exists for {}", short_id);
    }

    // Run scan command
    tracing::info!("Running wallet scan for {}", short_id);

    let scan_output = Command::new(&state.wallet_exe)
        .arg("scan")
        .arg("-d")
        .arg(&wallet_db)
        .arg("-p")
        .arg("test")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to execute scan: {}", e),
            )
        })?;

    let stdout = String::from_utf8_lossy(&scan_output.stdout);
    let stderr = String::from_utf8_lossy(&scan_output.stderr);

    if !scan_output.status.success() {
        tracing::error!("scan failed: {}", stderr);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("scan failed: {}", stderr),
        ));
    }

    tracing::info!("Scan completed successfully for {}", short_id);
    tracing::debug!("Scan output: {}", stdout);

    // Process wallet events and insert into guestbook
    let geocache_id = geocache.id.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Geocache ID not found".to_string(),
    ))?;

    let (inserted_count, last_event_id) = process_wallet_events(&wallet_db, geocache_id, &state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to process wallet events: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to process wallet events: {}", e),
            )
        })?;

    tracing::info!(
        "Inserted {} guestbook entries from wallet events, last event ID: {}",
        inserted_count,
        last_event_id
    );

    // Return geocache with scan info
    Ok(Json(serde_json::json!({
        "geocache": geocache,
        "scan_output": stdout.to_string(),
        "wallet_path": wallet_db.to_string_lossy().to_string(),
        "guestbook_entries_added": inserted_count,
        "last_scanned_event_id": last_event_id,
    })))
}

pub async fn get_address_json(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: get_address_json called for short_id: {}", short_id);

    // Find geocache by short_id
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    Ok(Json(serde_json::json!({
        "short_id": geocache.short_id,
        "name": geocache.name,
        "description": geocache.description,
        "latitude": geocache.latitude,
        "longitude": geocache.longitude,
        "tari_address": geocache.spend_pub_key,
        "created_at": geocache.created_at,
    })))
}

pub async fn print_address(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: print_address called for short_id: {}", short_id);

    // Find geocache by short_id
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    // Load template
    let template = include_str!("../templates/print.html");
    let secret_view_key =
        RistrettoSecretKey::from_canonical_bytes(&hex::decode(geocache.view_key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid view key: {}", e),
            )
        })?)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid view key: {}", e),
            )
        })?;
    let public_view_key = CompressedPublicKey::from_secret_key(&secret_view_key);
    let public_spend_key = CompressedPublicKey::from_canonical_bytes(
        &hex::decode(&geocache.spend_pub_key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Invalid spend public key: {}", e),
            )
        })?,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Invalid spend public key: {}", e),
        )
    })?;
    let tari_address = TariAddress::new_dual_address(
        public_view_key,
        public_spend_key,
        Network::MainNet,
        TariAddressFeatures::create_one_sided_only(),
        None,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create Tari address: {}", e),
        )
    })?;

    // Generate coordinates HTML if available
    let coordinates_html = if let (Some(lat), Some(lon)) = (geocache.latitude, geocache.longitude) {
        format!(
            r#"<div class="coordinates">📍 {:.6}, {:.6}</div>"#,
            lat, lon
        )
    } else {
        String::new()
    };

    // Replace placeholders
    let html = template
        .replace("{name}", &geocache.name)
        .replace("{short_id}", &short_id)
        .replace("{tari_address}", &tari_address.to_base58())
        .replace(
            "{description}",
            geocache
                .description
                .as_deref()
                .unwrap_or("No description provided"),
        )
        .replace("{coordinates_html}", &coordinates_html)
        .replace(
            "{created_at}",
            geocache.created_at.as_deref().unwrap_or("Unknown"),
        );

    Ok(Html(html))
}

#[derive(Debug, Deserialize)]
pub struct AdminAuthRequest {
    pub view_key: String,
}

#[derive(Debug, Serialize)]
pub struct AdminAuthResponse {
    pub authenticated: bool,
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminClaims {
    sub: String,      // Subject (short_id)
    exp: usize,       // Expiry time (timestamp)
    iat: usize,       // Issued at (timestamp)
    geocache_id: i64, // Geocache ID
}

// JWT Configuration
// Reads from JWT_SECRET environment variable
// For development, you can set a default or use: JWT_SECRET=your-dev-secret cargo run
fn get_jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET environment variable not set, using insecure default for development only!");
        "insecure-dev-secret-please-set-JWT_SECRET-env-var".to_string()
    })
}

/// Extract JWT token from Authorization header
///
/// # Arguments
/// * `headers` - HTTP request headers
///
/// # Returns
/// * `Some(String)` - Token if found in "Authorization: Bearer <token>" format
/// * `None` - No valid authorization header found
fn extract_jwt_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            if value.starts_with("Bearer ") {
                Some(value[7..].to_string())
            } else {
                None
            }
        })
}

/// Verify a JWT token and extract claims
///
/// # Arguments
/// * `token` - The JWT token string to verify
///
/// # Returns
/// * `Ok(AdminClaims)` - Valid token with extracted claims
/// * `Err(String)` - Invalid or expired token with error message
///
/// # Example
/// ```ignore
/// let claims = verify_jwt_token(&token)?;
/// println!("Authenticated for geocache: {}", claims.sub);
/// ```
fn verify_jwt_token(token: &str) -> Result<AdminClaims, String> {
    let secret = get_jwt_secret();
    decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Invalid token: {}", e))
}

/// Extract and verify JWT from request headers
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `expected_short_id` - The short_id that the token should be valid for
///
/// # Returns
/// * `Ok(AdminClaims)` - Valid token for the specified geocache
/// * `Err((StatusCode, String))` - Authentication error
fn authenticate_admin(
    headers: &HeaderMap,
    expected_short_id: &str,
) -> Result<AdminClaims, (StatusCode, String)> {
    // Extract token from headers
    let token = extract_jwt_from_headers(headers).ok_or((
        StatusCode::UNAUTHORIZED,
        "Missing or invalid Authorization header".to_string(),
    ))?;

    // Verify token
    let claims = verify_jwt_token(&token).map_err(|e| {
        tracing::warn!("JWT verification failed: {}", e);
        (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e))
    })?;

    // Verify the token is for the correct geocache
    if claims.sub != expected_short_id {
        tracing::warn!(
            "Token mismatch: expected {}, got {}",
            expected_short_id,
            claims.sub
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Token not valid for this geocache".to_string(),
        ));
    }

    Ok(claims)
}

pub async fn admin_authenticate(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
    Json(payload): Json<AdminAuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: admin_authenticate called for short_id: {}", short_id);

    // Find geocache by short_id
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    // Verify view key
    if payload.view_key != geocache.view_key {
        tracing::warn!("Failed admin authentication attempt for {}", short_id);
        return Ok(Json(AdminAuthResponse {
            authenticated: false,
            token: None,
        }));
    }

    // Generate JWT token
    let now = chrono::Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::hours(24)).timestamp() as usize; // Token expires in 24 hours

    let geocache_id = geocache.id.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Geocache ID not found".to_string(),
    ))?;

    let claims = AdminClaims {
        sub: short_id.clone(),
        exp,
        iat,
        geocache_id,
    };

    let secret = get_jwt_secret();
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| {
        tracing::error!("Failed to generate JWT: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate token".to_string(),
        )
    })?;

    tracing::info!("Successful admin authentication for {}", short_id);

    Ok(Json(AdminAuthResponse {
        authenticated: true,
        token: Some(token),
    }))
}

/// Protected endpoint to get admin information about a geocache
/// Requires valid JWT authentication
pub async fn admin_info(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: admin_info called for short_id: {}", short_id);

    // Authenticate admin
    let _claims = authenticate_admin(&headers, &short_id)?;

    // Find geocache by short_id
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    // Get guestbook count
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM guestbook WHERE geocache_id = ?")
        .bind(geocache.id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    Ok(Json(serde_json::json!({
        "geocache": geocache,
        "guestbook_count": count.0,
        "authenticated": true,
    })))
}

pub async fn admin_page(
    State(state): State<AppState>,
    Path(short_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    tracing::info!("API: admin_page called for short_id: {}", short_id);

    // Find geocache by short_id to verify it exists
    let geocache = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        WHERE short_id = ?
        "#,
        short_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Geocache not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    // Load template
    let template = include_str!("../templates/admin.html");

    // Replace placeholders
    let html = template
        .replace("{name}", &geocache.name)
        .replace("{short_id}", &short_id)
        .replace("{spend_pub_key}", &geocache.spend_pub_key)
        .replace("{view_key}", &geocache.view_key);

    Ok(Html(html))
}
