# AES File Encryption Web App

A simple, secure web application built with Python and Flask that allows users to encrypt and decrypt files using the **Advanced Encryption Standard (AES)** algorithm in CBC mode. 

## ✨ Features

*   **File Encryption:** Upload any file and receive an AES-encrypted version.
*   **File Decryption:** Upload an encrypted file to restore it to its original state.
*   **Secure Implementation:** Uses AES-256 (32-byte key) with CBC mode and PKCS7 padding. The Initialization Vector (IV) is randomly generated and securely prepended to the encrypted file.
*   **Automatic Cleanup:** Automatically deletes temporary uploaded files from the server once processing is complete.

## 🛠️ Prerequisites

Before running the application, ensure you have Python installed on your machine. You will also need to install the required Python packages.

Install the dependencies using `pip`:

```bash
pip install Flask pycryptodome Werkzeug
