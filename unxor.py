#!/usr/bin/env python3

import sys

def xor_file(input_file, output_file, key):

    KEY = bytes.fromhex(key)

    with open(input_file, "rb") as f:
        data = f.read()

    decrypted = bytes(
        b ^ key[i % len(key)]
        for i, b in enumerate(data)
    )

    with open(output_file, "wb") as f:
        f.write(decrypted)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file> <xor_key>")
        sys.exit(1)

    xor_file(sys.argv[1], sys.argv[2], sys.argv[3])
    print(f"Output written to {sys.argv[2]}")
