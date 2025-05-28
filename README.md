![Screenshot 2025-05-28 033422](https://github.com/user-attachments/assets/a0f099cf-e332-41b7-a4d7-11f57fa4db37)


<section>
  <h1>AES-256-CBC Encryption Utility</h1>

  <p>
    This program provides a command-line utility to encrypt and decrypt messages using AES-256 in CBC mode, leveraging OpenSSL libraries.
    It supports both default and user-provided keys and initialization vectors (IVs). The tool reads input text, encrypts it securely, 
    and outputs ciphertext in hexadecimal form along with the IV and key used. For decryption, it takes the ciphertext, key, and IV as hex 
    input and returns the original plaintext.
  </p>

  <p>
    Internally, the program initializes OpenSSL’s AES-256-CBC context, handles encryption and decryption with proper padding, and manages 
    input validation and hex parsing. It generates random IVs during encryption if none are provided and offers a default key for ease of use.
  </p>

  <section>
    <h2>Examples</h2>
<img src="https://github.com/user-attachments/assets/52832daa-7b09-4579-8279-7c7b9b540db5" alt="Screenshot 2025-05-28 033753" />
  <h3>Example 1: Encrypt a message</h3>
    <pre><code>
// Run program, select Encrypt mode (1), enter message, then enter key or press Enter to use default.
// Example workflow:
./aes_util
# Choose mode: 1
# Input text: Hello, World!
# Key: (press Enter to use default)
# Output shows encrypted hex, IV, and key
    </code></pre>
    <img src="https://github.com/user-attachments/assets/792bbb31-399c-4efa-b623-0fa6af9c98d2" alt="Screenshot 2025-05-28 033826" />

  <h3>Example 2: Decrypt a message</h3>
    <pre><code>
// Run program, select Decrypt mode (2), then enter:
// Key (64 hex chars or Enter for default)
// IV (32 hex chars)
// Encrypted data (hex)
// Program outputs decrypted plaintext
./aes_util
# Choose mode: 2
# Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
# IV: 1a2b3c4d5e6f7890123456789abcdef0
# Encrypted data: aabbccddeeff...
    </code></pre>
<img src="https://github.com/user-attachments/assets/f244892f-4761-43fc-9c9c-52b846c4771c" alt="Screenshot 2025-05-28 035224" width="100%" />

  <h3>Example 3: Using a custom key for encryption</h3>
    <pre><code>
// On encryption prompt, enter your custom 64-char hex key:
// Input message: Custom message here
// Key: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
./aes_util
# Choose mode: 1
# Input text: Custom message here
# Key: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
    </code></pre>
  </section>
</section>
<h1>Code we use for this Example</h1>
<h2>4f9a1e6d3c78f2b9e51d7aa6c3f249e5f1b0dca4729e8c14a6d2e38c7bf6a1d3
</h2>
<img src="https://github.com/user-attachments/assets/502b73cf-aa69-4b57-8d32-ce5586989cf1" alt="Screenshot 2025-05-28 035636" width="100%" />
<h6>MIT License

Copyright (c) 2025 Kaden

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

Additionally, **any use, distribution, or derivative work must clearly credit the original author, "Kaden", in any related documentation or about sections.**

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
</h6>
