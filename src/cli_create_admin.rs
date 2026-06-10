//! `larc-keys create-admin` subcommand.
//!
//! Seeds the first row in the `users` table so the admin-gated key APIs
//! (`POST /api/v1/keys`, etc.) have a JWT-bearing principal to authenticate as.
//!
//! Workflow:
//!   1. Parse `--email <e>` + optional `--name <n>` from argv.
//!   2. Prompt for password twice via `rpassword` (no echo).
//!   3. Argon2id-hash the password with a fresh random salt.
//!   4. Insert into `users` via [`repo::create_user`].
//!   5. Mint a JWT bound to the new `user_id` using the existing
//!      [`auth::generate_jwt`] helper + the configured `jwt_secret`.
//!   6. Print the user UUID + JWT to stdout (shown once).
//!
//! Refuses to run if the email already exists (UNIQUE constraint on
//! `users.email`) — call again with a fresh email or drop the conflicting
//! row manually before re-running.

use std::env;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::auth::generate_jwt;
use crate::config::Config;
use crate::db::{Database, ensure_db_dir};
use crate::repo;

/// Long-lived JWT lifetime for the bootstrap admin — 7 days.  The operator
/// is expected to mint a fresh token via `POST /api/v1/auth/login` once the
/// auth endpoints come online; this is just the immediate bootstrap key.
const BOOTSTRAP_JWT_TTL_SECS: u64 = 60 * 60 * 24 * 7;

#[derive(Debug)]
struct Args {
    email: String,
    name: String,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut email: Option<String> = None;
    let mut name: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--email" | "-e" => {
                i += 1;
                email = Some(argv.get(i).cloned().ok_or("--email needs a value")?);
            }
            "--name" | "-n" => {
                i += 1;
                name = Some(argv.get(i).cloned().ok_or("--name needs a value")?);
            }
            "--help" | "-h" => {
                return Err(usage());
            }
            other => return Err(format!("unknown argument: {other}\n{}", usage())),
        }
        i += 1;
    }
    let email = email.ok_or_else(|| format!("missing --email\n{}", usage()))?;
    if !email.contains('@') {
        return Err(format!("invalid email: `{email}` (no '@')"));
    }
    // Derive a default display name from the local part when --name is absent.
    let name = name.unwrap_or_else(|| {
        email
            .split('@')
            .next()
            .unwrap_or("admin")
            .to_owned()
    });
    Ok(Args { email, name })
}

fn usage() -> String {
    "Usage: larc-keys create-admin --email <e> [--name <n>]\n\
     \n\
     Bootstraps the first admin row in `users`.  Password is prompted twice.\n\
     Prints the new user UUID + a 7-day JWT to stdout on success.\n"
        .to_owned()
}

/// Hash a password using Argon2id with a fresh OS-random 16-byte salt.
fn hash_password(plain: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("argon2 hash failed: {e}"))
}

/// Prompt for a password twice via `rpassword`; return it once both match.
/// Returns `Zeroizing<String>` so the plaintext is overwritten on drop.
fn prompt_password() -> Result<Zeroizing<String>, String> {
    let p1 = Zeroizing::new(
        rpassword::prompt_password("New admin password: ")
            .map_err(|e| format!("password prompt failed: {e}"))?,
    );
    if p1.trim().is_empty() {
        return Err("password must not be empty".into());
    }
    if p1.len() < 12 {
        return Err("password must be at least 12 characters".into());
    }
    let p2 = Zeroizing::new(
        rpassword::prompt_password("Confirm admin password: ")
            .map_err(|e| format!("password prompt failed: {e}"))?,
    );
    if *p1 != *p2 {
        return Err("passwords do not match".into());
    }
    Ok(p1)
}

/// Entry point — wired from `main.rs` when argv[1] == "create-admin".
pub async fn run() -> anyhow::Result<()> {
    let cli_argv: Vec<String> = env::args().skip(2).collect();
    let cli = parse_args(&cli_argv).map_err(anyhow::Error::msg)?;

    let config = Config::from_env().map_err(|e| anyhow::anyhow!("config error: {e}"))?;
    ensure_db_dir(&config.database_path)?;
    let database = Database::open(&config.database_path)?;

    if repo::find_user_by_email(&database, &cli.email)
        .await
        .map_err(|e| anyhow::anyhow!("lookup failed: {e}"))?
        .is_some()
    {
        anyhow::bail!(
            "user with email `{}` already exists.  Pick a different email or \
             remove the existing row manually before re-running.",
            cli.email
        );
    }

    let password = prompt_password().map_err(anyhow::Error::msg)?;
    let hash = hash_password(&password).map_err(anyhow::Error::msg)?;
    // `password` is Zeroizing<String> — plaintext is overwritten on drop here.

    let user_id = repo::create_user(&database, &cli.email, &cli.name, &hash)
        .await
        .map_err(|e| anyhow::anyhow!("insert failed: {e}"))?;

    let jwt = generate_jwt(
        user_id,
        &cli.email,
        &config.jwt_secret,
        BOOTSTRAP_JWT_TTL_SECS,
    )
    .map_err(|e| anyhow::anyhow!("jwt mint failed: {e}"))?;

    // Print summary.  JWT shown ONCE — mirror behavior of `POST /api/v1/keys`.
    println!();
    println!("Admin user created.");
    println!("  user_id : {user_id}");
    println!("  email   : {}", cli.email);
    println!("  name    : {}", cli.name);
    println!();
    println!("Bootstrap JWT (7-day TTL, shown ONCE):");
    println!("{jwt}");
    println!();
    println!("Use it immediately to issue your first lak_* key:");
    println!(
        "  curl -X POST http://{}:{}/api/v1/keys \\",
        config.host, config.port
    );
    println!("    -H \"Authorization: Bearer $JWT\" \\");
    println!("    -H \"Content-Type: application/json\" \\");
    println!("    -d '{{\"name\":\"bootstrap\",\"environment\":\"live\",\"scopes\":[\"all:admin\"]}}'");
    println!();

    // Anchor: jwt_secret was consumed by generate_jwt; this keeps the import
    // graph honest if a future refactor moves the JWT mint elsewhere.
    let _ = config.jwt_secret.expose_secret();

    Ok(())
}
