# Advanced-Encryption-Tool-AES-256-
This is a command-line tool built with Python for strong, password-based encryption and decryption of files and text. It uses modern, industry-standard cryptographic practices to ensure your data is kept secure.

The tool provides a simple, menu-driven interface, making it easy to perform encryption tasks without needing complex commands.

Key Features
Strong Encryption: Implements AES-256 (Advanced Encryption Standard) in CBC mode, a widely trusted symmetric encryption algorithm.

Secure Key Derivation: Uses PBKDF2 with HMAC-SHA256 to derive a robust 32-byte encryption key from your password. This process is computationally intensive, making brute-force attacks on the password much more difficult.

Salting and IV: Automatically generates a unique random salt for each encryption, preventing rainbow table attacks. It also uses a unique IV (Initialization Vector) for each operation to ensure cryptographic security.

Versatile Modes:

Encrypt/Decrypt entire files (binary-safe).

Encrypt/Decrypt text strings directly in the terminal.

User-Friendly: Features a simple menu-driven interface and uses getpass for secure, hidden password entry.
