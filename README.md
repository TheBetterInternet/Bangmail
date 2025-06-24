# Bangmail

A decentralized, secure, stateless messaging protocol using SSH transport.

## Quick Start

### Build
```bash
make build
```

### Run Server
```bash
export BANGMAIL_KEY="server-secret-key-here-that-shouldnt-be-exposed-to-anyone-on-earth"
export BANGMAIL_PORT="2222"
export BANGMAIL_INBOX_PATH="/tmp/bangmail/inbox"
./bin/bangmaild
```

### Send Message
```bash
./bin/bangmail send neo!localhost:2222 --from person!example.com --subject "Hello" --body "Test message"
```

### Fetch Messages
```bash
BANGMAIL_PORT=2222 ./bin/bangmail fetch neo!localhost
```

## Environment Variables

- `BANGMAIL_KEY`: Required encryption key for server
- `BANGMAIL_PORT`: SSH port (default: 2222)
- `BANGMAIL_INBOX_PATH`: Message storage path (default: /var/lib/bangmail/inbox)

## Protocol

- Address format: `user!domain`
- Transport: SSH
- Encryption: AES-256-GCM
- Storage: Read-once, ephemeral messages
- No persistent accounts or authentication required

## Architecture

- `bangmaild`: SSH server handling message storage/retrieval
- `bangmail`: CLI client for sending/fetching messages
- Messages encrypted at rest with server key
- Automatic message deletion after delivery

## Spec

Read the [spec.md](spec.md) file.
