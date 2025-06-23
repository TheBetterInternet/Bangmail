# Bangmail Protocol Specification v1.0 (WIP)
---

## Overview

**Bangmail** is a decentralized, secure, stateless messaging protocol using the format `user!domain`. It utilizes **SSH as the transport**, **AES encryption for message confidentiality**, and enforces **read-once semantics** — messages are deleted from the server once delivered.

---

## Components

* **Bangmail Address**: `user!domain`
* **Transport Layer**: SSH
* **Encryption Layer**: AES-256-GCM using a secret server key (`BANGMAIL_KEY`)
* **Message Format**: JSON
* **Storage Model**: Ephemeral (only unread messages exist server-side)

---

## Address Format

```text
[user]![domain]

Examples:
  neo!neoapps.dev
  alice!example.org
  anon!onion.site
```

---

## Server Key

* **`BANGMAIL_KEY`** is a text string used for encryption/decryption.
* It is:

  * Set via environment variable.
  * Never shared externally.
  * Used internally to encrypt stored messages.
* It is **required** for the server to run.

---

## Message Encryption

* Messages are encrypted with AES-256-GCM using a derived key from `BANGMAIL_KEY` (e.g., via SHA-256 or even just plain text).
* Nonce (IV) must be random per message (e.g., 12 bytes).
* Optionally, the client may encrypt the message body before transport, but the server also stores it encrypted at rest.

---

## Sending a Message

1. **Client initiates an SSH session** to the target domain on a known port (default: 2222).
2. **Client runs a remote command** over SSH:

   ```sh
   bangmail-receive [recipient]
   ```
3. **Client sends an encrypted message over stdin**.

The server:

* Reads the stream.
* Validates the command.
* Stores the message in the user’s queue (encrypted with `BANGMAIL_KEY`).
* Optionally logs basic metadata (from, timestamp) in plaintext.

---

## Message Format (Encrypted Payload)

```json
{
  "from": "sarah!sarah.dev",
  "to": "neo!neoapps.dev",
  "timestamp": 1721290001,
  "subject": "hello there",
  "body": "Encrypted or plaintext body",
  "nonce": "base64-encoded-12-bytes"
}
```

---

## Receiving Messages

1. **Client SSHes into their server**:

   ```sh
   bangmail-fetch [username]
   ```
2. Server:

   * Decrypts and sends **all unread messages** to the client (JSON array or newline-delimited).
   * Deletes messages **after delivery**.

No messages are retained server-side after they are marked as delivered.

---

## Message Retention Policy

* Messages are:

  * **Stored encrypted**
  * **Deleted after read**
  * **Optionally expire** after a TTL (e.g., 24h)
* All unread messages are stored in:

  ```
  /var/lib/bangmail/inbox/[user]/msg-[timestamp].bmail
  ```

---

## Authentication

* SSH connection **does not require user authentication**.
* Optional: servers may implement key- or IP-based rate limiting / allow-lists.
* Message-level security is handled **at the encryption layer**, not transport.

---

## `bangmaild`

* Exposes an SSH server on configurable port
* Accepts:

  * `bangmail-receive [username]` command
  * `bangmail-fetch [username]` command
* Reads and writes encrypted files to inbox storage
* Deletes messages after delivery

---

## `bangmail`

### Send:

```sh
bangmail send "neo!neoapps.dev" \
  --subject "yo" \
  --body "meet me at the base" \
  --from "sarah!sarah.dev"
```

### Fetch:

```sh
bangmail fetch "sarah!sarah.dev" > inbox.json
```

---

## Philosophy

| Principle                | Implementation                        |
| ------------------------ | ------------------------------------- |
| **No tracking**          | No analytics, no read receipts        |
| **No persistent inbox**  | Read-once then destroy                |
| **Decentralized**        | Anyone can run a domain               |
| **No central server**    | Each domain self-hosts                |
| **Encrypted by default** | AES256-GCM using local `BANGMAIL_KEY` |
| **Simple**               | No complex protocols or APIs          |
| **SSH-native**           | Uses hardened existing transport      |

---

## Summary

| Feature                    | Status             |
| -------------------------- | ------------------ |
| SSH-based messaging        | ✅                  |
| Text-based encryption key  | ✅ (`BANGMAIL_KEY`) |
| Read-once inbox            | ✅                  |
| No user accounts           | ✅                  |
| No server-side identity    | ✅                  |
| Client-side persistence    | ✅                  |
| Simple message format      | ✅                  |

