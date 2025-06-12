import sys
import os


def writebytestofile(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)

def readfilesasbytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list


def main():
    if len(sys.argv) != 5:
        print("Input incorreto, tente novamente.")
        sys.exit(1)
    
    filename = sys.argv[1]


if __name__ == "__main__":
    main()