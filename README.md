# VanguardTrace

### Decrypting and Intercepting Encrypted Imports of Vanguard's Kernel Driver

Welcome to VanguardTrace, a tool designed to decrypt and intercept encrypted imports within Vanguard's Kernel Driver.

## Overview

I began my exploration of vgk.sys and its import protection mechanisms. One strategy that immediately occurred to me for gaining insight was to employ a patchguard bypass. By hooking potential imports and capturing their return addresses, I could trace back to where vgk.sys calls these imports. This approach led me directly to their decryption algorithm. With a clear understanding of this algorithm, I proceeded to rewrite it for readability and created the complementary encryption function. Additionally, I developed functions to determine the starting offset of the imports encryption "table" using a simple signature scan, and to retrieve the offset of specific imports of interest.

## Features

- **Decryption**: Decrypt encrypted imports within Vanguard's Kernel Driver.
- **Interception**: Intercept and manipulate encrypted imports.
- **Pointer Encryption**: Encrypt pointers with their encryption routine to assist with intercepting.
- **Automatic Import Table Location**: Automatically locate the start of the encrypted import table using a signature scan.
- **Offset Identification**: Identify the offset of the desired import for easy manipulation/hooking.

## Example Usage

![CiCheckSignedFile](./hook.jpg)

## License

This project is licensed under the [MIT License](LICENSE).
