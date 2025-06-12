import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def preproc(str):
    l=[]
    for c in str:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def encrypt(key, plaintext):
    ciphertext = ''
    for i in range(len(plaintext)):
        K = ALPHABET.index(key)
        P = ALPHABET.index(plaintext[i])
        C = (P + K) % 26
        ciphertext = ciphertext + ALPHABET[C]
    return ciphertext

def decrypt(key, ciphertext):
    plaintext = ''
    for i in range(len(ciphertext)):
        K = ALPHABET.index(key)
        P = ALPHABET.index(ciphertext[i])
        C = (P - K) % 26
        plaintext = plaintext + ALPHABET[C]
    return plaintext

def attack(ciphertext, words):
    for key in ALPHABET:
        decrypted_cipher = decrypt(key,ciphertext)
        for word in words:
            if word in decrypted_cipher:
                print(key)
                print(decrypted_cipher)


def main(args):
    if len(args) < 4:
        print("Usage: python script.py <encrypt/decrypt> <key> <message>")
        return
    
    operation = args[1].lower()
    key = args[2].upper()
    message = preproc(args[3])
    
    if len(key) != 1 or key not in ALPHABET:
        print("Key must be a single letter from A-Z.")
        return
    
    if operation == "encrypt":
        result = encrypt(key, message)
    elif operation == "decrypt":
        result = decrypt(key, message)
    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'.")
        return
    
    print(result)

if __name__ == "__main__":
    main(sys.argv)