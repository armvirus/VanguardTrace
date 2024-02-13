# VanguardTrace

### Decrypting and Intercepting Encrypted Imports of Vanguard's Kernel Driver

Welcome to VanguardTrace, a tool designed to decrypt and intercept encrypted imports within Vanguard's Kernel Driver.

## Overview

I began my journey by delving deep into the mysterious vgk.sys. Through careful analysis, I uncovered the secrets of decrypting specific imports essential for my purposes. Leveraging this knowledge, I engineered a powerful tool capable of encrypting my pointers, enabling seamless substitution and hooking of desired imports.

## Features

- **Decryption**: Decrypt encrypted imports within Vanguard's Kernel Driver.
- **Interception**: Intercept and manipulate encrypted imports.
- **Pointer Encryption**: Encrypt pointers with their encryption routine to assist with intercepting.
- **Automatic Import Table Location**: Automatically locate the start of the encrypted import table using a signature scan.
- **Offset Identification**: Identify the offset of the desired import for easy manipulation/hooking.

## Usage

1. Simply manual map the driver.

## License

This project is licensed under the [MIT License](LICENSE).
