import tkinter as tk
from tkinter import ttk, messagebox
from hashlib import sha256, md5
from Crypto.Cipher import Blowfish
import os

# Caesar Cipher Function
def caesar_cipher_encrypt(text, shift):
    encrypted = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('a') if char.islower() else ord('A')
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

# vigener cyper algorithm
def vigenere_cipher_encrypt(text, key):
    key = key.lower()
    encrypted = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('a')
            if char.islower():
                encrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            key_index = (key_index + 1) % len(key)
        else:
            encrypted += char
    return encrypted

# MD5 Hash Function
def md5_hash(text):
    return md5(text.encode()).hexdigest()

# Blowfish Encryption Function
def blowfish_encrypt(text):
    key = b"securekey"  # Key for Blowfish
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_text = text + (8 - len(text) % 8) * ' '
    encrypted = cipher.encrypt(padded_text.encode())
    return encrypted.hex()

# Calculate Avalanche Effect
def calculate_avalanche_effect():
    message = message_field.get("1.0", tk.END).strip()
    changed_message = changed_message_field.get("1.0", tk.END).strip()
    selected_algorithm = algorithm_choice.get()

    if not message or not changed_message:
        messagebox.showerror("Error", "Please enter text in both input fields.")
        return

    try:
        if selected_algorithm == "SHA-256":
            hash1 = sha256(message.encode()).hexdigest()
            hash2 = sha256(changed_message.encode()).hexdigest()
        elif selected_algorithm == "Caesar Cipher":
            shift = 3
            hash1 = caesar_cipher_encrypt(message, shift)
            hash2 = caesar_cipher_encrypt(changed_message, shift)
        elif selected_algorithm == "Vigenère Cipher":
            key = "key"
            hash1 = vigenere_cipher_encrypt(message, key)
            hash2 = vigenere_cipher_encrypt(changed_message, key)
        elif selected_algorithm == "MD5":
            hash1 = md5_hash(message)
            hash2 = md5_hash(changed_message)
        elif selected_algorithm == "Blowfish":
            hash1 = blowfish_encrypt(message)
            hash2 = blowfish_encrypt(changed_message)

        bin_hash1 = ''.join(format(ord(c), '08b') for c in hash1)
        bin_hash2 = ''.join(format(ord(c), '08b') for c in hash2)
        differing_bits = sum(b1 != b2 for b1, b2 in zip(bin_hash1, bin_hash2))
        total_bits = max(len(bin_hash1), len(bin_hash2))
        avalanche_percentage = (differing_bits / total_bits) * 100

        result_text.set(f"Hash 1: {hash1}\nHash 2: {hash2}\n\nDiffering Bits: {differing_bits}\nAvalanche Effect: {avalanche_percentage:.2f}%")
        avalanche_results[selected_algorithm] = avalanche_percentage

    except Exception as e:
        messagebox.showerror("Error", str(e))

# Compare Algorithms
def compare_algorithms():
    if not avalanche_results:
        messagebox.showerror("Error", "Please calculate the Avalanche Effect for at least one algorithm.")
        return

    best_algorithm = max(avalanche_results, key=avalanche_results.get)
    comparison_result.set(f"Best Algorithm Based on Avalanche Effect: {best_algorithm}")

# Reset Fields
def reset_fields():
    message_field.delete("1.0", tk.END)
    changed_message_field.delete("1.0", tk.END)
    result_text.set("")
    comparison_result.set("")
    avalanche_results.clear()

# Tkinter GUI Setup
root = tk.Tk()
root.title("Avalanche Effect Comparison Tool")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Message Field
ttk.Label(frame, text="Message:").grid(row=0, column=0, sticky=tk.W, pady=5)
message_field = tk.Text(frame, height=5, width=60)
message_field.grid(row=1, column=0, columnspan=2, pady=5)

# Changed Message Field
ttk.Label(frame, text="Changed Message:").grid(row=2, column=0, sticky=tk.W, pady=5)
changed_message_field = tk.Text(frame, height=5, width=60)
changed_message_field.grid(row=3, column=0, columnspan=2, pady=5)

# Algorithm Choice
ttk.Label(frame, text="Select Algorithm:").grid(row=4, column=0, sticky=tk.W, pady=5)
algorithm_choice = ttk.Combobox(frame, values=["SHA-256", "Caesar Cipher", "Vigenère Cipher", "MD5", "Blowfish"], state="readonly")
algorithm_choice.set("SHA-256")
algorithm_choice.grid(row=4, column=1, sticky=tk.E, pady=5)

# Buttons
ttk.Button(frame, text="Calculate Avalanche Effect", command=calculate_avalanche_effect).grid(row=5, column=0, pady=10)
ttk.Button(frame, text="Compare Algorithms", command=compare_algorithms).grid(row=5, column=1, pady=10)
ttk.Button(frame, text="Reset", command=reset_fields).grid(row=6, column=0, columnspan=2, pady=10)

# Result Display
result_text = tk.StringVar()
result_label = ttk.Label(frame, textvariable=result_text, wraplength=500, justify="left")
result_label.grid(row=7, column=0, columnspan=2, pady=10)

# Comparison Result Display
comparison_result = tk.StringVar()
comparison_label = ttk.Label(frame, textvariable=comparison_result, wraplength=500, justify="left", foreground="blue")
comparison_label.grid(row=8, column=0, columnspan=2, pady=10)

# Global Storage for Avalanche Results
avalanche_results = {}

root.mainloop()
