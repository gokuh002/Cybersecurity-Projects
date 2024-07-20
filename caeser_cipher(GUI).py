import tkinter as tk
from tkinter import messagebox

# Defining the Caesar Cipher functions
letters = 'abcdefghijklmnopqrstuvwxyz'

def encrypt(plaintext, shift_value):
    ciphertext = ''
    for letter in plaintext:
        letter = letter.lower()
        if not letter == ' ':
            index = letters.find(letter)
            if index == -1:
                ciphertext += letter
            else:
                new_index = (index + shift_value) % 26
                ciphertext += letters[new_index]
        else:
            ciphertext += ' '  
    return ciphertext    

def decrypt(ciphertext, shift_value):
    plaintext = ''
    for letter in ciphertext:
        letter = letter.lower()
        if not letter == ' ':
            index = letters.find(letter)
            if index == -1:
                plaintext += letter
            else:
                new_index = (index - shift_value) % 26
                plaintext += letters[new_index]
        else:
            plaintext += ' '  
    return plaintext  

# Creating GUI functions
def encrypt_text():
    text = text_input.get("1.0", "end-1c")
    key = int(key_input.get())
    encrypted_text = encrypt(text, key)
    result_text.delete("1.0", "end")
    result_text.insert("1.0", encrypted_text)

def decrypt_text():
    text = text_input.get("1.0", "end-1c")
    key = int(key_input.get())
    decrypted_text = decrypt(text, key)
    result_text.delete("1.0", "end")
    result_text.insert("1.0", decrypted_text)

# main window
root = tk.Tk()
root.title("Caesar Cipher")

# input and output widgets
frame = tk.Frame(root, padx=10, pady=10)
frame.pack()

# Label and Text widget for entering text
tk.Label(frame, text="Enter Text:").grid(row=0, column=0, sticky="w")
text_input = tk.Text(frame, height=5, width=40)
text_input.grid(row=0, column=1, columnspan=2)

# Label and Entry widget for entering shift key
tk.Label(frame, text="Enter Shift Key (1 to 26):").grid(row=1, column=0, sticky="w")
key_input = tk.Entry(frame)
key_input.grid(row=1, column=1)

# Buttons for encryption and decryption
encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=2, column=1, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=2, column=2, pady=5)

# Label and Text widget for displaying result
tk.Label(frame, text="Result:").grid(row=3, column=0, sticky="w")
result_text = tk.Text(frame, height=5, width=40)
result_text.grid(row=3, column=1, columnspan=2)

# Start the GUI main loop
root.mainloop()
