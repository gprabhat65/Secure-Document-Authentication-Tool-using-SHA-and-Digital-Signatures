import hashlib
import rsa
import os


def generate_rsa_keys(key_folder: str):
    """Generate RSA key pair inside the given folder."""
    os.makedirs(key_folder, exist_ok=True)

    print("Generating new RSA key pair...")

    public_key, private_key = rsa.newkeys(2048)

    private_path = os.path.join(key_folder, "private_key.pem")
    public_path = os.path.join(key_folder, "public_key.pem")

    with open(private_path, "wb") as f:
        f.write(private_key.save_pkcs1("PEM"))

    with open(public_path, "wb") as f:
        f.write(public_key.save_pkcs1("PEM"))

    print("RSA key pair generated successfully!")


def hash_document(file_path: str, algorithm="sha256") -> str:
    """Return SHA-256 or SHA-512 hash of a file."""
    if algorithm == "sha512":
        hash_func = hashlib.sha512()
    else:
        hash_func = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.hexdigest()


def sign_hash(doc_hash: str, key_folder: str) -> bytes:
    """Sign the hash using RSA private key."""
    private_path = os.path.join(key_folder, "private_key.pem")

    if not os.path.exists(private_path):
        raise FileNotFoundError("Private key missing. Generate keys first.")

    with open(private_path, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    signature = rsa.sign(doc_hash.encode(), private_key, "SHA-256")
    return signature


def verify_signature(doc_hash: str, signature: bytes, key_folder: str) -> bool:
    """Verify RSA signature using public key."""
    public_path = os.path.join(key_folder, "public_key.pem")

    if not os.path.exists(public_path):
        raise FileNotFoundError("Public key missing. Generate keys first.")

    with open(public_path, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    try:
        rsa.verify(doc_hash.encode(), signature, public_key)
        return True
    except rsa.VerificationError:
        return False
