# Avalanche Effect Comparison Tool 🔐

This is a Python GUI-based project that demonstrates the **Avalanche Effect** in cryptographic algorithms using **Tkinter**. The Avalanche Effect refers to the desirable property of cryptographic algorithms where a small change in input (e.g., flipping a single bit) results in a significantly different output.

## 🔍 Features

- Compare how different encryption and hashing algorithms react to minor input changes
- Calculate and display the **Avalanche Effect** percentage
- Supported algorithms:
  - **SHA-256**
  - **MD5**
  - **Caesar Cipher**
  - **Vigenère Cipher**
  - **Blowfish (ECB mode)**

## 🖥️ GUI Overview

The application provides:
- Input for the original and modified message
- Dropdown to select the algorithm
- Buttons to:
  - Calculate Avalanche Effect
  - Compare and highlight the best-performing algorithm
  - Reset inputs and outputs

## 📦 Requirements

Make sure you have Python 3 installed. Then install the required libraries:

```bash
pip install pycryptodome