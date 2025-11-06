use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub async fn init_database(database_url: &str) -> SqlitePool {
    // Parse database URL and extract file path
    let db_options = database_url
        .parse::<sqlx::sqlite::SqliteConnectOptions>()
        .expect("Invalid database URL")
        .create_if_missing(true);

    // Extract database file path from the connection string to create parent directory
    if let Some(db_path) = database_url.strip_prefix("sqlite:") {
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).expect("Failed to create database directory");
            }
        }
    }

    // Initialize database
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(db_options)
        .await
        .expect("Failed to connect to database");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("Failed to run migrations");

    db
}
