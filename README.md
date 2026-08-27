# EtherChat 

EtherChat is a serverless-ish peer-to-peer LAN chat application for Windows.

It is designed so that people on the same Wi-Fi/Ethernet network can open the app and discover each other automatically.

## Features

- Automatic LAN device discovery
- Usernames
- Rooms
- Direct peer-to-peer messaging
- Encrypted connections using X25519 + HKDF + AES-GCM
- Typing indicators
- File transfer (currently up to 8 MB per file)
- QR pairing information
- No accounts
- No database
- No cloud server
- No internet connection required after the app is downloaded

## How it works

Every EtherChat executable is both the user interface and the network peer.

```text
Sam's PC  <──────── encrypted LAN connection ────────>  Dad's PC
    │                                                      │
    └──────────────────── Room traffic ───────────────────┘
```

UDP broadcast is used for discovery. Chat traffic then moves directly between EtherChat peers over TCP.

There is no permanent central backend.

## Run from source

Python 3.10+ is recommended.

```bash
py -m pip install -r requirements.txt
py etherchat.py
```

## Build the Windows executable

On Windows:

```bat
build.bat
```

The executable will be created at:

```text
dist\EtherChat.exe
```

Copy that executable next to `index.html` before publishing the download page.

## GitHub Pages

The included `index.html` is intentionally simple. Put these files in the GitHub Pages branch/root:

```text
index.html
EtherChat.exe
```

The Download button points to `EtherChat.exe`, so GitHub Pages can serve the landing page without running a backend.

## Windows Firewall

The first launch may cause Windows Defender Firewall to ask for network permission. Allow EtherChat on **Private networks** so LAN discovery and chat can work.

## Security note

EtherChat encrypts chat payloads in transit using ephemeral X25519 key exchange and AES-GCM authenticated encryption.

QR pairing currently generates a signed-in-data-style pairing payload for sharing identity/address information; a future version can add full camera scanning and explicit trust management.

## Limitations in this first release

- LAN discovery depends on broadcast packets being allowed by the network.
- Guest Wi-Fi networks may isolate clients from one another.
- File transfer is currently limited to 8 MB per file.
- QR generation is included; camera-based QR scanning is not included yet.
- There is no message history/database by design.

## License

MIT
