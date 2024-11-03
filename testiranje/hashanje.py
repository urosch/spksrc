
import os
import hashlib


def hash_file(file_path):
    """Calculate the SHA1, SHA256, and MD5 hashes of a file."""
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    with open(file_path, 'rb') as f:
        # Read the file in chunks to avoid memory issues with large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)
            md5_hash.update(byte_block)

    return {
        'SHA1': sha1_hash.hexdigest(),
        'SHA256': sha256_hash.hexdigest(),
        'MD5': md5_hash.hexdigest()
    }


def hash_files_in_directory(directory):
    """Hash all files in the given directory."""
    results = {}

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            results[file_path] = hash_file(file_path)

    return results


if __name__ == "__main__":
    directory = input("Enter the directory path: ")
    hashes = hash_files_in_directory(directory)

    for file_path, hash_values in hashes.items():
        print(f"File: {file_path}")
        print(f"  SHA1: {hash_values['SHA1']}")
        print(f"  SHA256: {hash_values['SHA256']}")
        print(f"  MD5: {hash_values['MD5']}")
