# Tari Private Geocache

A web-based geocaching application built on the Tari blockchain. Create geocaches with Tari wallet addresses, allowing visitors to leave messages by sending transactions. Each transaction creates a guestbook entry that's displayed on the geocache page.

## Features

- **Create Geocaches**: Generate geocaches with Tari wallet view-only addresses
- **Guestbook System**: Visitors send Tari (even tiny amounts like 0.0000001 XTM) to leave messages
- **Auto-scanning**: Background scanner automatically detects new transactions
- **Admin Panel**: Secure JWT-based authentication for geocache owners
- **Print-friendly Address Pages**: Generate printable QR codes and addresses for physical geocaches
- **RESTful API**: Full API for programmatic access

## How It Works

1. Create a new Tari wallet (dedicated for the geocache, not your main wallet)
2. Export the view key and spend public key
3. Create a geocache with these keys plus name, description, and optional coordinates
4. Print the geocache address and place it at a physical location
5. Visitors find the geocache, scan the QR code, and send Tari with a memo message
6. Messages automatically appear in the guestbook

## Prerequisites

- **Rust** (1.70+)
- **Minotari** executable (for wallet scanning) (https://github.com/tari-project/minotari-cli)
- **SQLite** (bundled with sqlx)

## Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd tari-geocache2
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and set JWT_SECRET to a secure random value
```

Generate a secure JWT secret:
```bash
# Using openssl:
openssl rand -base64 32

# Or using PowerShell:
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

3. Build the project:
```bash
cargo build --release
```

## Configuration

### Environment Variables

- `JWT_SECRET` (required for production): Secret key for JWT token generation
- `DATABASE_URL` (optional): SQLite database path (default: `sqlite://data/geocaches.db`)

### Command Line Arguments

```bash
tarigeocache [OPTIONS]

Options:
  -d, --database-url <DATABASE_URL>  Database URL [default: sqlite://data/geocaches.db]
  -p, --port <PORT>                  Server port [default: 3000]
  -w, --wallet-exe <WALLET_EXE>      Path to wallet executable [default: bin/minotari.exe]
  -h, --help                          Print help
```

## Usage

### Running the Server

```bash
# Development (with default settings):
JWT_SECRET=dev-secret cargo run

# Production:
JWT_SECRET=your-secure-secret-here ./target/release/tarigeocache --port 8080 --wallet-exe /path/to/minotari_console_wallet
```

### Web Interface

Navigate to `http://localhost:3000` in your browser:

- **Home Page** (`/`): Create new geocaches
- **Geocache List** (`/list.html`): View all geocaches
- **Guestbook** (`/?short_code=<id>`): View a specific geocache's guestbook
- **Admin Panel** (`/admin/<short_id>`): Manage your geocache (requires view key)
- **Print Page** (`/print/<short_id>`): Print-friendly address with QR code

## API Endpoints

### Public Endpoints

- `POST /api/geocaches` - Create a new geocache
- `GET /api/geocaches` - List all geocaches
- `GET /api/geocaches/:id` - Get specific geocache
- `GET /api/guestbook/:short_id` - Get guestbook entries (paginated)
- `GET /api/address/:short_id` - Get geocache address info
- `GET /api/scan/:short_id` - Trigger manual scan

### Admin Endpoints (Require Authentication)

- `POST /api/admin/:short_id/authenticate` - Authenticate with view key
- `GET /api/admin/:short_id/info` - Get admin information (requires JWT)

### Example: Create a Geocache

```bash
curl -X POST http://localhost:3000/api/geocaches \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Hidden Treasure Peak",
    "description": "Near the old oak tree",
    "latitude": 37.7749,
    "longitude": -122.4194,
    "view_key": "your-private-view-key-hex",
    "spend_pub_key": "your-public-spend-key-hex"
  }'
```

## Project Structure

```
tari-geocache2/
├── src/
│   ├── main.rs           # Entry point and CLI setup
│   ├── db.rs             # Database initialization
│   ├── models.rs         # Data models
│   ├── handlers.rs       # API request handlers
│   ├── routes.rs         # Route definitions
│   └── scanner.rs        # Background wallet scanner
├── migrations/           # Database migrations
├── static/               # Static web files
│   ├── index.html        # Main page
│   ├── list.html         # Geocache list
│   └── app.js            # Frontend JavaScript
├── templates/            # Server-side templates
│   ├── admin.html        # Admin panel
│   └── print.html        # Printable address page
├── .env.example          # Environment variable template
└── Cargo.toml            # Rust dependencies
```

## Security

### Important Security Notes

1. **JWT Secret**: Always set a strong `JWT_SECRET` environment variable in production
2. **Wallet Isolation**: Create dedicated wallets for geocaches - never use your main wallet
3. **View-Only Keys**: Only the view key and spend public key are stored, not spend keys
4. **Admin Access**: Admin features require the private view key for authentication

### Data Storage

- **Database**: SQLite database stores geocache metadata and guestbook entries
- **Wallets**: Individual wallet databases stored in `/wallets/<short_id>/`
- **Exclusions**: `.gitignore` excludes `.env`, `/data`, `/wallets`, and `/bin`

## Background Scanner

The application runs a background task that:
- Scans all geocache wallets every 5 minutes
- Detects new confirmed transactions
- Automatically adds guestbook entries
- Tracks the last scanned event ID to avoid duplicates

## Development

### Database Migrations

Migrations are automatically applied on startup. Manual migration:

```bash
sqlx migrate run --database-url sqlite://data/geocaches.db
```

### Building for Production

```bash
cargo build --release
strip target/release/tarigeocache  # Reduce binary size (Unix/Linux)
```

## Troubleshooting

### "JWT_SECRET not set" Warning

Set the environment variable:
```bash
export JWT_SECRET="your-secret-here"
```

### Wallet Scan Failures

- Ensure the wallet executable path is correct (`-w` flag)
- Check that wallet databases exist in `/wallets/<short_id>/`
- Verify wallet has proper permissions

### Database Connection Errors

- Ensure the parent directory exists for the database path
- Check file permissions on the database file
- Default location: `./data/geocaches.db`

## Contributing

Contributions are welcome! Please ensure:
- Code follows Rust conventions
- Security best practices are maintained
- No sensitive data is committed

## License

[Your License Here]

## Acknowledgments

Built with:
- [Tari](https://tari.com) - Digital assets protocol
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Async SQL toolkit
- [Tokio](https://tokio.rs) - Async runtime
