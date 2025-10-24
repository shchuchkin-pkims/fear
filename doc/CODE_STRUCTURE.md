# F.E.A.R. Project - Code Structure Guide

**Last Updated:** October 22, 2025
**Version:** 0.3.0

---

## Project Overview

F.E.A.R. (Fully Encrypted Anonymous Routing) is a cross-platform secure messaging system with end-to-end encryption. This document describes the updated code structure after refactoring.

---

## Module Organization

### 1. Client-Console Module (`client-console/`)

Core messaging functionality for console-based client and server.

#### Structure

```
client-console/
├── include/
│   ├── common.h          # Protocol constants, utility functions
│   ├── network.h         # Network abstraction layer (NEW)
│   ├── client.h          # Client interface
│   └── server.h          # Server interface
└── src/
    ├── main.c            # CLI entry point
    ├── common.c          # Utilities (crypto, I/O, encoding)
    ├── network.c         # Network implementation (NEW)
    ├── client.c          # Client logic
    └── server.c          # Server logic
```

#### Module Responsibilities

**common.c/h**
- Binary I/O (little-endian integer encoding/decoding)
- Network send/receive with complete transfer guarantees
- Base64 encoding/decoding (URL-safe)
- CRC32 checksum calculation
- AES-256-GCM encryption/decryption wrappers

**network.c/h** *(NEW)*
- TCP connection establishment (`dial_tcp`)
- Server socket creation (`server_listen`)
- Cross-platform socket abstractions

**main.c**
- Command-line argument parsing
- Key generation
- Mode selection (server/client)

**client.c**
- Connecting to server
- Encrypting and sending messages
- Receiving and decrypting messages
- File transfer handling
- User list management

**server.c**
- Accepting client connections
- Message relay (broadcast to room)
- Client state management
- Name uniqueness enforcement

---

## Protocol Specification

### Message Frame Format

All messages use this wire format:

```
┌─────────────┬──────────┬─────────────┬──────────┬──────────────┬────────┬──────────┬──────────────┬────────────┐
│ room_len(2) │ room(N)  │ name_len(2) │ name(N)  │ nonce_len(2) │ nonce  │ type(1)  │ clen(4)      │ cipher(N)  │
└─────────────┴──────────┴─────────────┴──────────┴──────────────┴────────┴──────────┴──────────────┴────────────┘
```

- **room_len:** 2 bytes (uint16_t, little-endian)
- **room:** Variable length (max 256 bytes)
- **name_len:** 2 bytes (uint16_t, little-endian)
- **name:** Variable length (max 256 bytes)
- **nonce_len:** 2 bytes (uint16_t, little-endian)
- **nonce:** 12 bytes (AES-GCM nonce)
- **type:** 1 byte (message_type_t enum)
- **clen:** 4 bytes (uint32_t, little-endian, ciphertext length)
- **cipher:** Variable length (plaintext + 16-byte auth tag)

### Message Types

```c
typedef enum {
    MSG_TYPE_TEXT = 0,        // Regular encrypted text message
    MSG_TYPE_FILE_START = 1,  // File transfer start (metadata)
    MSG_TYPE_FILE_CHUNK = 2,  // File transfer data chunk
    MSG_TYPE_FILE_END = 3,    // File transfer completion
    MSG_TYPE_USER_LIST = 4    // Room participant list (from server)
} message_type_t;
```

### Encryption

- **Algorithm:** AES-256-GCM (AEAD)
- **Key Size:** 32 bytes (256 bits)
- **Nonce Size:** 12 bytes (96 bits)
- **Auth Tag:** 16 bytes (128 bits)

**Authenticated Data (not encrypted):**
- Room name
- User name

**Encrypted Data:**
- Message content (or file data)

---

## Security Model

### Zero-Knowledge Server

The server is designed with a zero-knowledge architecture:

**Server CAN see:**
- Room names (metadata)
- User names (metadata)
- Message sizes and timestamps
- Connection patterns

**Server CANNOT see:**
- Message content (encrypted)
- File content (encrypted)
- Anything encrypted with room key

### Key Management

**Key Generation:**
```bash
./fear genkey
# Outputs 32-byte key as Base64 URL-safe string
# Key is NOT saved to disk automatically
```

**Secure Key Input (Priority Order):**

1. **--key-file FILE** (Recommended for scripts)
   ```bash
   ./fear client --host server.com --port 8888 \
                 --room myroom --key-file room_key.txt
   ```

2. **stdin** (Interactive or piped)
   ```bash
   echo "KEY_HERE" | ./fear client --host server.com --port 8888 \
                                    --room myroom --name Alice
   ```

3. **--key KEYSTRING** (DEPRECATED - visible in process list)
   ```bash
   # NOT RECOMMENDED - shows warning
   ./fear client --host server.com --port 8888 \
                 --room myroom --key "KEY_HERE"
   ```

---

## API Reference

### Common Utilities (common.h)

#### Binary I/O

```c
uint16_t rd_u16(const uint8_t *p);
void wr_u16(uint8_t *p, uint16_t v);
uint32_t rd_u32(const uint8_t *p);
void wr_u32(uint8_t *p, uint32_t v);
```

**Purpose:** Little-endian integer encoding/decoding for protocol

#### Network I/O

```c
int recv_all(sock_t fd, void *buf, size_t len);
int send_all(sock_t fd, const void *buf, size_t len);
```

**Purpose:** Guaranteed complete send/receive (blocks until all data transferred)

**Returns:** 0 on success, -1 on error/disconnect

#### Base64 Operations

```c
char *b64_encode(const uint8_t *buf, size_t len);
int b64_decode(const char *b64, uint8_t *out, size_t outlen);
```

**Purpose:** URL-safe Base64 encoding without padding (RFC 4648)

**Note:** Caller must `free()` the result from `b64_encode()`

#### Data Integrity

```c
uint32_t crc32(const uint8_t *data, size_t len);
```

**Purpose:** Calculate CRC32 checksum (ISO 3309 polynomial)

**Usage:** File integrity verification during transfer

#### Encryption

```c
int aes_gcm_encrypt(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *additional_data, size_t additional_data_len,
    const uint8_t *nonce, const uint8_t *key,
    uint8_t *ciphertext, unsigned long long *ciphertext_len
);

int aes_gcm_decrypt(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *additional_data, size_t additional_data_len,
    const uint8_t *nonce, const uint8_t *key,
    uint8_t *plaintext, unsigned long long *plaintext_len
);
```

**Purpose:** AES-256-GCM authenticated encryption (AEAD)

**Returns:** 0 on success, -1 on error or authentication failure

**Security Notes:**
- Nonce MUST be unique for each message with same key
- Use `randombytes_buf(nonce, 12)` to generate random nonce
- NEVER reuse nonces with the same key
- Authentication failure returns -1 - NEVER use plaintext in this case

---

### Network Module (network.h)

#### Client Connection

```c
sock_t dial_tcp(const char *host, uint16_t port);
```

**Purpose:** Establish TCP connection to remote host

**Parameters:**
- `host`: Hostname or IP address (e.g., "example.com" or "192.168.1.1")
- `port`: Port number (e.g., 8888)

**Returns:** Valid socket descriptor on success, exits on failure

**Notes:**
- Resolves DNS using getaddrinfo()
- Tries IPv4 and IPv6
- Initializes Winsock2 on Windows

#### Server Listening

```c
sock_t server_listen(uint16_t port);
```

**Purpose:** Create listening socket for server mode

**Parameters:**
- `port`: Port to listen on (e.g., 8888)

**Returns:** Listening socket descriptor on success, exits on failure

**Notes:**
- Binds to INADDR_ANY (0.0.0.0)
- Sets SO_REUSEADDR
- Listen backlog: 16 connections

---

## File Transfer Protocol

### Sending Files

```bash
# In client mode, use /sendfile command
> /sendfile path/to/file.txt
```

### Transfer Sequence

1. **FILE_START:** Sends filename, total size, expected CRC32
2. **FILE_CHUNK(s):** Sends file in 8KB encrypted chunks with per-chunk CRC
3. **FILE_END:** Sends final CRC32 for verification

### Security

- All file data is encrypted with room key
- CRC32 checksums verify integrity
- Files saved to `Downloads/` directory
- Corrupted files are automatically deleted

---

## Constants

### Protocol Limits

```c
#define MAX_ROOM 256        // Maximum room name length
#define MAX_NAME 256        // Maximum user name length
#define MAX_FILENAME 1024   // Maximum filename length
#define MAX_FRAME 65536     // Maximum message frame size (64KB)
#define FILE_CHUNK_SIZE 8192 // File transfer chunk size (8KB)
#define DEFAULT_PORT 8888   // Default server port
#define MAX_CLIENTS 100     // Maximum concurrent clients
```

### Cryptography

```c
#define CRYPTO_KEYBYTES 32     // AES-256-GCM key size
#define CRYPTO_NPUBBYTES 12    // AES-256-GCM nonce size
#define CRYPTO_ABYTES 16       // AES-256-GCM auth tag size
```

---

## Building

### Linux/macOS

```bash
./build.sh
```

### Windows

```bat
build.bat
```

### CMake (Manual)

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Output

```
build/bin/fear          # Console client/server
build/bin/key-exchange  # Key exchange utility
build/bin/audio_call    # Voice call utility
build/bin/updater       # Update manager
```

---

## Usage Examples

### Generate Room Key

```bash
$ ./fear genkey
z6aK3_k9I7rmpy6Sn-84QZ9Yc0p3T7VhzReWCKE0x4I
Room key generated successfully.
```

### Start Server

```bash
$ ./fear server --port 7777
[server] listening on 0.0.0.0:7777
```

### Connect as Client

```bash
$ echo "z6aK3_k9I7rmpy6Sn-84QZ9Yc0p3T7VhzReWCKE0x4I" | \
  ./fear client --host 127.0.0.1 --port 7777 --room myroom --name Alice
```

### Send File

```
> Hello everyone!
> /sendfile document.pdf
Sending file: document.pdf (1024576 bytes)
Progress: 1024576/1024576 bytes (100.0%)
File sent successfully: document.pdf
```

---

## Error Handling

### Common Errors

**Connection Failed:**
- Check server is running
- Verify host and port are correct
- Check firewall settings

**Invalid Key:**
- Key must be exactly 32 bytes (44 characters in Base64)
- Use `genkey` to generate valid keys
- Check for copy-paste errors

**Name Already Exists:**
- Server enforces unique names per room
- Choose a different name
- Check if you're already connected

---

## Performance Considerations

### Server

- Uses `select()` for I/O multiplexing
- Single-threaded event loop
- Maximum 100 concurrent clients
- Low memory footprint (~1MB per client)

### Client

- Blocking I/O on Windows (input thread)
- Non-blocking I/O on Linux (select)
- Encryption overhead: ~16 bytes per message (auth tag)

### File Transfer

- 8KB chunks minimize memory usage
- CRC32 verification adds ~5% overhead
- Encryption adds ~0.19% overhead (16 bytes per 8KB chunk)

---

## Security Checklist

✅ **Do:**
- Generate keys with `genkey` command
- Use `--key-file` or stdin for key input
- Only connect to trusted servers
- Verify key integrity before sharing
- Use unique names in each room

❌ **Don't:**
- Hardcode keys in scripts
- Use `--key` argument in production
- Connect to unknown third-party servers
- Share keys over unencrypted channels
- Reuse the same key across multiple rooms

---

## Debugging

### Enable Verbose Output

Currently, the code uses `fprintf(stderr, ...)` for diagnostic messages.

### Common Debug Points

**Connection Issues:**
- Check `dial_tcp()` in network.c:44-70
- Verify `getaddrinfo()` resolution

**Encryption Failures:**
- Check nonce is 12 bytes
- Verify key is 32 bytes
- Ensure additional data matches on both sides

**Protocol Errors:**
- Use Wireshark to inspect network traffic
- Check frame lengths and structure
- Verify message type values

---

## Contributing

### Code Style

- Follow existing code style (K&R)
- Add doxygen-style comments for functions
- Use descriptive variable names
- Keep functions under 100 lines when possible

### Testing

Before submitting changes:
1. Build on Linux and Windows
2. Run genkey/client/server tests
3. Verify file transfer works
4. Check for memory leaks (valgrind)

---

## References

- [libsodium Documentation](https://doc.libsodium.org/)
- [AES-GCM Specification](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Base64 URL-safe (RFC 4648)](https://tools.ietf.org/html/rfc4648#section-5)
- [CRC32 (ISO 3309)](https://www.iso.org/standard/8462.html)

---

**Last Updated:** October 22, 2025
**Maintainer:** F.E.A.R. Project Team
