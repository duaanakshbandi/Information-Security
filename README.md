
# Information-Security

This repository contains a collection of challenges that focus on exploiting common vulnerabilities found in software systems, cryptographic implementations, and web applications. The challenges are categorized into three main sections: System-Security, Crypto-Misuse, and Network-Security. Each section contains multiple challenges designed to highlight specific types of vulnerabilities and their potential impacts.

## Table of Contents

- [System-Security](#system-security)
  - [Buffer Overflow](#1-buffer-overflow)
  - [Format String Attacks](#2-format-string-attacks)
  - [Use After Free](#3-use-after-free)
  - [Shellcode Injection](#4-shellcode-injection)
  - [Race Conditions](#5-race-conditions)
  - [Timing Attack](#6-timing-attack)
  - [Combination](#7-combination)
  - [Reverse Engineering (Bonus)](#8-reverse-engineering-bonus)
  - [Fault Attacks Overview](#fault-attacks-overview)
    - [The Safe](#1-the-safe)
    - [Fault Attacks on Deterministic Signature Schemes](#2-fault-attacks-on-deterministic-signature-schemes)
    - [Differential Fault Attacks on AES](#3-differential-fault-attacks-on-aes)
- [Crypto-Misuse](#crypto-misuse)
  - [The ECB Mode of Operation](#1-the-ecb-mode-of-operation)
  - [Nonce Reuse](#2-nonce-reuse)
  - [Encryption without Authentication](#3-encryption-without-authentication)
  - [Encryption with Bad Authentication](#4-encryption-with-bad-authentication)
  - [Bad Randomness](#5-bad-randomness)
  - [Textbook RSA](#6-textbook-rsa)
- [Network-Security](#network-security)
  - [Basic SQL Injection](#1-basic-sql-injection)
  - [Intermediate SQL Injection](#2-intermediate-sql-injection)
  - [Advanced SQL Injection](#3-advanced-sql-injection)
  - [Untrusted Data](#4-untrusted-data)
  - [Path Traversal](#5-path-traversal)
  - [Basic Cross-site Scripting](#6-basic-cross-site-scripting)
  - [Advanced Cross-site Scripting](#7-advanced-cross-site-scripting)
  - [Basic API](#8-basic-api)
  - [Advanced API](#9-advanced-api)
  - [JSON Web Tokens](#10-json-web-tokens)
  - [Server-Side Template Injection (SSTI)](#11-server-side-template-injection-ssti)

# System-Security

In this section, common mistakes in software development are exploited, particularly in systems that are neither memory-safe nor type-safe, leading to security vulnerabilities.

### 1. **Buffer Overflow**

**Objective:** Exploit a buffer overflow vulnerability in a half-finished password manager program to hijack the control flow and access a secret flag.

This exploit script targets a buffer overflow vulnerability in the main.elf binary by crafting a payload that overwrites the program's return address with a specific function's address (0x00401e35). This function likely reveals a secret flag. By carefully aligning the input with the buffer, the script forces the program to execute the payload, extract the flag, and display it, demonstrating a classic example of how buffer overflows can be exploited to hijack program execution and gain unauthorized access to sensitive information.

**Folder:** `system_security/hacklets/01_BOF`

### 2. **Format String Attacks**

**Objective:** Abuse a format string vulnerability in a chatbot program to unveil a secret flag.

This exploit script takes advantage of a format string vulnerability in the main.elf binary to manipulate memory and ultimately gain unauthorized access to a secret flag. The script first leaks memory addresses using the %x format specifier, calculates the address of a target variable (Impressed), and then uses a format string payload to overwrite this variable's value. Finally, the script reads and extracts the flag using a regular expression. This attack showcases how format string vulnerabilities can be exploited to execute arbitrary code or modify program behavior by directly manipulating memory addresses.

**Folder:** `system_security/hacklets/02_Format`

### 3. **Use After Free**

**Objective:** Exploit a use-after-free vulnerability in a simple access system to gain unauthorized access to a secured resource.

This exploit script manipulates memory through a series of interactions with a binary (main.elf) that likely simulates some sort of object management (like colors). The script exploits a use-after-free or heap-based vulnerability by creating and deleting objects (referred to as "yellow" and "green") in a specific sequence. By carefully controlling the memory layout and overwriting certain values, the script gains unauthorized access to the program's functionality, ultimately revealing a secret flag. This attack demonstrates how manipulating memory allocations and deallocations in a vulnerable program can lead to security breaches, such as accessing restricted data or functions.

**Folder:** `system_security/hacklets/03_UAF`

### 4. **Shellcode Injection**

**Objective:** Write and inject shellcode to manipulate a minimal program's behavior, performing operations based on custom assembly code.

This exploit script targets a vulnerable binary (main.elf) by injecting custom assembly code into the program's execution. It begins by reading a buffer memory address and a random number from the program's output. The script then calculates an XOR value by XORing the random number with a constant. Depending on whether the XOR value is even or odd, the script generates and injects different assembly code that either prints "even" or "odd" to the standard output. The injected code also includes system calls for writing the output and terminating the program. The payload, which includes this custom code, is sent to the program, and the script captures the output to determine the success of the injection. This demonstrates how shellcode injection can manipulate a program's control flow to execute arbitrary commands based on runtime data.

**Folder:** `system_security/hacklets/04_Inject`

### 5. **Race Conditions**

**Objective:** Exploit a race condition in a program that derives a password, allowing unauthorized access to secure data.

This exploit script targets a vulnerability in the main.elf binary by using a symlink attack to trick the program into reading a sensitive file, flag.txt, instead of the intended file. The script starts by creating an empty file named damnimgood and then runs the vulnerable program. After sending some initial input to the program, it deliberately wastes time by performing a large number of pointless calculations, likely to create a time window for the exploit. The script then deletes the damnimgood file and replaces it with a symbolic link pointing to flag.txt. When the program attempts to access damnimgood, it inadvertently reads flag.txt instead, allowing the script to capture and print the flag using a regular expression. This exploit demonstrates how symlink attacks can be used to bypass file access controls and trick programs into revealing sensitive data.

**Folder:** `system_security/hacklets/05_Race`

### 6. **Timing Attack**

**Objective:** Perform a timing attack to recover a secret password from a binary by measuring the time taken to execute certain operations.

This exploit script performs a timing attack on the main.elf binary to crack an 8-character password by measuring response times for different input guesses. The script iterates through all possible characters for each position in the password, identifying the correct character based on the longest response time. Once the correct password is determined, the script successfully retrieves and prints the secret flag, showcasing how timing discrepancies can be exploited to extract sensitive information from a vulnerable program.

**Folder:** `system_security/hacklets/06_Timing`

### 7. **Combination**

**Objective:** Combine knowledge from previous challenges to exploit multiple vulnerabilities in a program to achieve the desired goal.

This exploit script targets a binary (main.elf) by combining an integer overflow with a buffer overflow attack to gain control over the program's execution flow. It begins by leaking memory addresses using a format string (%x) to calculate the address of the randomNumbers variable. The script then triggers an integer overflow by inputting a large number (320), followed by a buffer overflow that overwrites the stack with a payload including the calculated address of randomNumbers. This manipulation allows the script to hijack the program's behavior and ultimately extract the secret flag, which is captured and printed using a regular expression. This attack demonstrates how combining multiple vulnerabilities can effectively bypass security controls and gain unauthorized access to sensitive data.

**Folder:** `system_security/hacklets/07_Combination`

# Crypto-Misuse

In this section, vulnerabilities caused by common mistakes in the use of cryptographic algorithms are exploited.

### 1. **The ECB Mode of Operation**

**Objective:** Exploit the weakness in Electronic Code Book (ECB) mode where identical plaintext blocks result in identical ciphertext blocks. The challenge involves decrypting an intercepted encrypted audio stream by identifying patterns using a known plaintext snippet.

This script is designed to encrypt and decrypt audio files using AES in ECB mode, and to solve a cryptographic challenge by decrypting an encrypted audio stream using a known piece of plaintext audio. It exploits the vulnerabilities of ECB mode by mapping identical plaintext and ciphertext blocks to reconstruct the original audio. The script also includes functionality to generate encryption keys, compute SHA256 hashes of audio files, and provides a command-line interface for different operations. The goal is to decrypt the audio stream and validate the solution by matching the hash of the decrypted audio against a known correct hash.

**Folder:** `crypto_misuse/ecb`

### 2. **Nonce Reuse**

**Objective:** Attack cryptographic schemes where the nonce (or Initialization Vector) is reused. The challenge is divided into two parts:
   - **Symmetric Cryptography:** Break a keyless entry system by predicting the next rolling code using a repeated nonce in a stream cipher.
   - **Asymmetric Cryptography:** Recover a private key by exploiting a weak nonce reuse in ECDSA.

**Folder:** `crypto_misuse/nonce_reuse_sym` and `crypto_misuse/nonce_reuse_asym`

### 3. **Encryption without Authentication**



**Objective:** Exploit the absence of data integrity checks in a challenge-response protocol. The task is to manipulate encrypted packets to gain unauthorized access to a high-security facility.

**Folder:** `crypto_misuse/enc_without_auth`

### 4. **Encryption with Bad Authentication**

**Objective:** Break a flawed authenticated encryption scheme to retrieve a critical decryption key, leveraging knowledge from a previous encryption method.

**Folder:** `crypto_misuse/enc_with_bad_auth`

### 5. **Bad Randomness**

**Objective:** Exploit weaknesses in random number generation across three challenges:
   - **Insecure RNG:** Recover plaintext by exploiting a flawed RNG implementation.
   - **Insecure Initialization:** Find an error in the seed generation process to decrypt a file.
   - **Biased RNG:** Recover a password by exploiting the non-uniform distribution in the RNG used by a password generator.

**Folder:** `crypto_misuse/bad_rand_rng`, `crypto_misuse/bad_rand_seed`, and `crypto_misuse/bad_rand_usage`

### 6. **Textbook RSA**

**Objective:** Exploit vulnerabilities in the naive implementation of RSA. The challenges involve manipulating ciphertexts to reveal information without recovering the private key.
   - **Ticket Lottery:** Determine your seat in a lottery system by manipulating ciphertext.
   - **Bank Transfer:** Generate a valid signature to perform an unauthorized large withdrawal.

**Folder:** `crypto_misuse/rsa_ticket_lottery` and `crypto_misuse/rsa_bank`

# Network-Security

In this section, we explore vulnerabilities in web applications, particularly those outlined in the OWASP Top 10, and demonstrate how these can be exploited in practical scenarios.

### 1. **Basic SQL Injection**

**Objective:** Perform a basic SQL injection to bypass login authentication and access an admin account.

**Folder:** `network_web/SQLi1`

### 2. **Intermediate SQL Injection**

**Objective:** Use SQL injection techniques to extract two hidden flags from the database.

**Folder:** `network_web/SQLi2`

### 3. **Advanced SQL Injection**

**Objective:** Exploit SQL injection to read the contents of a file from the server's filesystem.

**Folder:** `network_web/SQLi3`

### 4. **Untrusted Data**

**Objective:** Exploit a flaw in the file upload function of a web service to access the contents of a secured file.

**Folder:** `network_web/File1`

### 5. **Path Traversal**

**Objective:** Perform a path traversal attack to download unauthorized files from the server.

**Folder:** `network_web/File2`

### 6. **Basic Cross-site Scripting**

**Objective:** Inject a script into a web page that captures the session cookie of another user.

**Folder:** `network_web/XSS1`

### 7. **Advanced Cross-site Scripting**

**Objective:** Craft a cross-site scripting attack that tricks an admin user into revealing a secure flag.

**Folder:** `network_web/XSS2`

### 8. **Basic API**

**Objective:** Exploit API vulnerabilities to access restricted data meant only for administrators.

**Folder:** `network_web/API1`

### 9. **Advanced API**

**Objective:** Exploit flaws in an API's session management to escalate privileges and access secure data.

**Folder:** `network_web/API2`

### 10. **JSON Web Tokens**

**Objective:** Exploit weaknesses in a custom JWT implementation to elevate privileges to an admin level and retrieve a flag.

**Folder:** `network_web/JWT`

### 11. **Server-Side Template Injection (SSTI)**

**Objective:** Perform a server-side template injection attack to execute arbitrary code on the server and access secure data.

**Folder:** `network_web/SSTI`