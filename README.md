# Ballchasing Uploader

A desktop app for auto-uploading Rocket League replays to [ballchasing.com](https://ballchasing.com).

Built as a standalone replacement for BakkesMod's auto-upload feature, which is no longer available after Rocket League added Easy Anti-Cheat.

## Features

- Auto-detects your Rocket League replay folder
- Password-masked API key input with one-click verification
- Displays your ballchasing account tier and rate limits
- Auto-uploads new `.replay` files as they appear
- Deduplicates uploads using SHA256 file hashes
- Retries failed uploads on next startup
- Configurable upload visibility (public, unlisted, private)
- Persists all settings across restarts

## Download

### Windows

Download the latest `ballchasing-uploader.exe` from the [Releases](https://github.com/your-username/ballchasing-uploader/releases) page and run it. No installation required.

### Linux / macOS

Build from source (see below).

## First Run

1. Get your API key from [ballchasing.com/upload](https://ballchasing.com/upload)
2. Launch the app
3. Paste your API key and click **Verify**
4. The app auto-detects your replay folder. If not found, click **Browse...** to set it manually
5. Choose your upload visibility (public, unlisted, or private)
6. Enable **Auto-upload replays** to start watching for new replays

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+)

### Windows

```bash
cargo build --release
```

The executable will be at `target\release\ballchasing-uploader.exe`.

### Linux

Install system dependencies first:

```bash
# Ubuntu / Debian
sudo apt install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
  libxkbcommon-dev libssl-dev libgtk-3-dev

# Fedora
sudo dnf install -y libxcb-devel libxkbcommon-devel openssl-devel gtk3-devel

# Arch
sudo pacman -S libxcb libxkbcommon openssl gtk3
```

Then build:

```bash
cargo build --release
```

The executable will be at `target/release/ballchasing-uploader`.

### macOS

```bash
cargo build --release
```

The executable will be at `target/release/ballchasing-uploader`.

## Configuration

All settings are saved automatically to:

| Platform | Path |
|----------|------|
| Windows  | `%APPDATA%\ballchasing-uploader\config.json` |
| Linux    | `~/.config/ballchasing-uploader/config.json` |
| macOS    | `~/Library/Application Support/ballchasing-uploader/config.json` |

You can also edit the config file directly:

```json
{
  "api_key": "YOUR_KEY",
  "watch_dir": "C:\\Users\\You\\Documents\\My Games\\Rocket League\\TAGame\\Demos",
  "visibility": "private",
  "uploaded_hashes": []
}
```

## Account Tiers

Your ballchasing account tier determines your upload rate limit. The app displays your tier after verifying your API key.

| Tier | Rate Limit |
|------|-----------|
| Regular | 2 uploads/sec |
| Gold | 4 uploads/sec |
| Diamond | 8 uploads/sec |
| Champion | 8 uploads/sec |
| Grand Champion | 16 uploads/sec |

Upgrade your tier at [ballchasing.com](https://www.patreon.com/ballchasing) via Patreon.

## License

MIT
