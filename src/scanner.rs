use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::interval;

use crate::models::Geocache;

async fn process_wallet_events(
    wallet_db_path: &PathBuf,
    geocache_id: i64,
    db_pool: &SqlitePool,
) -> Result<(usize, i64), String> {
    tracing::debug!("Processing wallet events from {:?}", wallet_db_path);

    // Get last scanned event ID from geocaches table
    let last_scanned: (Option<i64>,) =
        sqlx::query_as("SELECT last_scanned_event_id FROM geocaches WHERE id = ?")
            .bind(geocache_id)
            .fetch_one(db_pool)
            .await
            .map_err(|e| format!("Failed to get last scanned event: {}", e))?;

    let last_scanned_id = last_scanned.0.unwrap_or(0);
    tracing::debug!("Last scanned event ID: {}", last_scanned_id);

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

    tracing::debug!("Found {} new OutputConfirmed events", events.len());

    let mut inserted_count = 0;
    let mut max_event_id = last_scanned_id;

    for (event_id, event_name, event_data) in events {
        tracing::trace!("Processing event: {} (ID: {})", event_name, event_id);
        max_event_id = max_event_id.max(event_id);

        // Parse event data as JSON
        let event_json: serde_json::Value = serde_json::from_str(&event_data)
            .map_err(|e| format!("Failed to parse event JSON: {}", e))?;

        let event_json = event_json
            .get("OutputConfirmed")
            .ok_or("Missing event field")?;
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
            tracing::trace!("Entry already exists for output_hash: {}", output_hash);
            continue;
        }

        // Insert into guestbook
        let from_address = "unknown";
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

        tracing::info!(
            "Background scan: Inserted guestbook entry for output_hash: {}",
            output_hash
        );
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

        tracing::debug!(
            "Updated last_scanned_event_id from {} to {}",
            last_scanned_id,
            max_event_id
        );
    }

    Ok((inserted_count, max_event_id))
}

async fn scan_single_wallet(
    geocache: &Geocache,
    wallet_exe: &str,
    db_pool: &SqlitePool,
) -> Result<usize, String> {
    let short_id = geocache.short_id.as_ref().ok_or("Missing short_id")?;

    // Create wallet directory path
    let wallet_dir = PathBuf::from("wallets").join(short_id);
    let wallet_db = wallet_dir.join("wallet.db");

    // Check if wallet exists
    if !wallet_db.exists() {
        tracing::debug!("Wallet does not exist for {}, skipping", short_id);
        return Ok(0);
    }

    tracing::debug!("Scanning wallet for {}", short_id);

    // Run scan command
    let scan_output = Command::new(wallet_exe)
        .arg("scan")
        .arg("-d")
        .arg(&wallet_db)
        .arg("-p")
        .arg("test")
        //  --batch-size 10 -n 10000 -
        .arg("--batch-size")
        .arg("10")
        .arg("-n")
        .arg("2000")
        .arg("-u")
        .arg("http://localhost:9000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute scan: {}", e))?;

    if !scan_output.status.success() {
        let stderr = String::from_utf8_lossy(&scan_output.stderr);
        tracing::warn!("Scan failed for {}: {}", short_id, stderr);
        // return Err(format!("Scan failed: {}", stderr));
    }

    // Process wallet events and insert into guestbook
    let geocache_id = geocache.id.ok_or("Missing geocache ID")?;

    let (inserted_count, _) = process_wallet_events(&wallet_db, geocache_id, db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to process wallet events for {}: {}", short_id, e);
            e
        })?;

    if inserted_count > 0 {
        tracing::info!(
            "Background scan: Added {} entries for {}",
            inserted_count,
            short_id
        );
    }

    Ok(inserted_count)
}

async fn scan_all_wallets(wallet_exe: String, db_pool: SqlitePool) {
    tracing::debug!("Starting wallet scan cycle");

    // Get all geocaches
    let geocaches = sqlx::query_as!(
        Geocache,
        r#"
        SELECT id, short_id, name, description, latitude, longitude, view_key, spend_pub_key,
               datetime(created_at) as created_at
        FROM geocaches
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(&db_pool)
    .await;

    match geocaches {
        Ok(caches) => {
            tracing::debug!("Found {} geocaches to scan", caches.len());

            for geocache in caches {
                if let Err(e) = scan_single_wallet(&geocache, &wallet_exe, &db_pool).await {
                    tracing::warn!("Error scanning wallet: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch geocaches for scanning: {}", e);
        }
    }

    tracing::debug!("Completed wallet scan cycle");
}

pub fn start_background_scanner(wallet_exe: String, db_pool: SqlitePool) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));

        tracing::info!("Background wallet scanner started (30s interval)");

        loop {
            ticker.tick().await;
            scan_all_wallets(wallet_exe.clone(), db_pool.clone()).await;
        }
    });
}
