def vigenere_sq():
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    square = []

    for i in range(len(alphabet)):
        row = [(alphabet[(i + j) % len(alphabet)]) for j in range(len(alphabet))]
        square.append(row)

    header = "|   | " + " | ".join(alphabet) + " |"
    separator = "|" + "---|" * (len(alphabet) + 1)
    print(header)
    print(separator)
    for i, row in enumerate(square):
        print(f"| {alphabet[i]} | " + " | ".join(row) + " |")

vigenere_sq()

encrypted_texts = []

def letter_to_index(letter, alphabet):
    if letter in alphabet:
        return alphabet.index(letter)
    else:
        raise ValueError(f"'{letter}' is not in the alphabet.")

def index_to_letter(index, alphabet):
    return alphabet[index % len(alphabet)]

def vigenere_index(key_letter, plaintext_letter, alphabet):
    key_idx = letter_to_index(key_letter, alphabet)
    text_idx = letter_to_index(plaintext_letter, alphabet)
    cipher_idx = (key_idx + text_idx) % len(alphabet)
    return index_to_letter(cipher_idx, alphabet)

def encrypt_vigenere(key, plaintext, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    cipher_list = []
    key_length = len(key)

    for i, letter in enumerate(plaintext):
        if letter not in alphabet:
            cipher_list.append(letter)
        else:
            key_letter = key[i % key_length]
            cipher_letter = vigenere_index(key_letter, letter, alphabet)
            cipher_list.append(cipher_letter)

    return ''.join(cipher_list)

def undo_vigenere_index(key_letter, cipher_letter, alphabet):
    key_idx = letter_to_index(key_letter, alphabet)
    cipher_idx = letter_to_index(cipher_letter, alphabet)
    plain_idx = (cipher_idx - key_idx) % len(alphabet)
    return index_to_letter(plain_idx, alphabet)

def decrypt_vigenere(key, cipher_text, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    plain_list = []
    key_length = len(key)

    for i, letter in enumerate(cipher_text):
        if letter not in alphabet:
            plain_list.append(letter)
        else:
            key_letter = key[i % key_length]
            plain_letter = undo_vigenere_index(key_letter, letter, alphabet)
            plain_list.append(plain_letter)

    return ''.join(plain_list)

def vigenere_sq():
    """Prints the Vigenère square."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    square = []

    for i in range(len(alphabet)):
        row = [(alphabet[(i + j) % len(alphabet)]) for j in range(len(alphabet))]
        square.append(row)

    header = "|   | " + " | ".join(alphabet) + " |"
    separator = "|" + "---|" * (len(alphabet) + 1)
    print(header)
    print(separator)
    for i, row in enumerate(square):
        print(f"| {alphabet[i]} | " + " | ".join(row) + " |")

def encrypt_text():
    key = input("Enter encryption key: ").upper()
    plaintext = input("Enter plaintext: ").upper()
    encrypted = encrypt_vigenere(key, plaintext)
    encrypted_texts.append(encrypted)
    print(f"Encrypted Text: {encrypted}")

def decrypt_texts():
    key = input("Enter decryption key: ").upper()
    if not encrypted_texts:
        print("No encrypted texts available.")
    else:
        for text in encrypted_texts:
            decrypted = decrypt_vigenere(key, text)
            print(f"Decrypted Text: {decrypted}")

def dump_encrypted_texts():
    print("Encrypted Texts:", encrypted_texts)

def quit_program():
    print("Goodbye!")
    exit()

def menu():
    return [
        ["Encrypt", encrypt_text],
        ["Decrypt", decrypt_texts],
        ["Dump Encrypted Texts", dump_encrypted_texts],
        ["Quit", quit_program]
    ]

def main():
    while True:
        print("\nMain Menu")
        options = menu()
        for i, option in enumerate(options):
            print(f"{i + 1}) {option[0]}")
        choice = input("Choose an option: ")

        if choice.isdigit() and 1 <= int(choice) <= len(options):
            options[int(choice) - 1][1]()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    vigenere_sq()
    main()

