import hashlib
import math
import os
from typing import Dict, Any

def compute_hashes_and_entropy(file_path: str) -> Dict[str, Any]:
    """
    Computes cryptographic hashes (SHA-256, MD5, SHA-1) and Shannon entropy
    for chain-of-custody verification.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return {
            "file_size": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "entropy": 0.0,
            "is_empty": True,
            "header_hex": ""
        }

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    
    byte_counts = [0] * 256
    total_bytes = 0
    header_bytes = b""

    with open(file_path, "rb") as f:
        header_bytes = f.read(64)
        f.seek(0)
        
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            total_bytes += len(chunk)
            for b in chunk:
                byte_counts[b] += 1

    entropy = 0.0
    if total_bytes > 0:
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

    return {
        "file_size": file_size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "entropy": round(entropy, 4),
        "is_empty": False,
        "header_hex": header_bytes[:32].hex(" ").upper()
    }
