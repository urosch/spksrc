import hashlib
import requests


def download_file(url):
    """Download a file from a URL."""
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for bad responses
    return response.content


def compute_hashes(file_content):
    """Compute SHA1, SHA256, and MD5 hashes of the given content."""
    sha1_hash = hashlib.sha1(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    md5_hash = hashlib.md5(file_content).hexdigest()

    return {
        'SHA1': sha1_hash,
        'SHA256': sha256_hash,
        'MD5': md5_hash
    }


def write_digest_file(hashes, filename='digest.txt'):
    """Write the hashes to a digest file."""
    with open(filename, 'w') as f:
        for hash_name, hash_value in hashes.items():
            f.write(f"{hash_name}: {hash_value}\n")


if __name__ == "__main__":
    url = "https://github.com/SynoCommunity/spksrc/releases/download/toolchains%2Fsrm1.3/ipq806x-gcc1030_glibc232_srm-1.3.tar.xz"

    # Step 1: Download the file
    print("Downloading file...")
    file_content = download_file(url)

    # Step 2: Compute hashes
    print("Computing hashes...")
    hashes = compute_hashes(file_content)

    # Step 3: Write to digest file
    print("Writing to digest file...")
    write_digest_file(hashes)

    print("Digest file created successfully.")