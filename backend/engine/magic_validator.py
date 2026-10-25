import os
from typing import Dict, Any, Optional

SIGNATURES = [
    # (Magic bytes, offset, detected_mime, detected_type, description)
    (b"\xFF\xD8\xFF", 0, "image/jpeg", "JPEG", "JPEG Image"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png", "PNG", "PNG Image"),
    (b"GIF87a", 0, "image/gif", "GIF", "GIF Image (87a)"),
    (b"GIF89a", 0, "image/gif", "GIF", "GIF Image (89a)"),
    (b"%PDF", 0, "application/pdf", "PDF", "Adobe Portable Document Format (PDF)"),
    (b"PK\x03\x04", 0, "application/zip", "ZIP", "ZIP Archive / OpenPackaging (DOCX/XLSX/APK/JAR)"),
    (b"PK\x05\x06", 0, "application/zip", "ZIP", "Empty ZIP Archive"),
    (b"PK\x07\x08", 0, "application/zip", "ZIP", "Spanned ZIP Archive"),
    (b"\x1a\x45\xdf\xa3", 0, "video/x-matroska", "MKV", "Matroska / WebM Video"),
    (b"ID3", 0, "audio/mpeg", "MP3", "MP3 Audio (ID3v2)"),
    (b"\xFF\xFB", 0, "audio/mpeg", "MP3", "MP3 Audio (MPEG-1 Layer 3)"),
    (b"\xFF\xF3", 0, "audio/mpeg", "MP3", "MP3 Audio (MPEG-2 Layer 3)"),
    (b"RIFF", 0, "audio/wav", "WAV/AVI", "Resource Interchange File Format (WAV/AVI)"),
    (b"\x00\x00\x01\xBA", 0, "video/mpeg", "MPEG", "MPEG Video"),
    (b"OggS", 0, "audio/ogg", "OGG", "Ogg Audio/Video"),
    (b"fLaC", 0, "audio/flac", "FLAC", "FLAC Audio"),
    (b"\x7FELF", 0, "application/x-executable", "ELF", "ELF Executable"),
    (b"MZ", 0, "application/x-dosexec", "EXE", "DOS/Windows Executable"),
]

def detect_file_signature(file_path: str) -> Dict[str, Any]:
    """
    Examines file header magic bytes to verify authenticity against declared extension.
    Flags container spoofing, mismatched extensions, and hidden archives.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    _, ext = os.path.splitext(filename)
    declared_ext = ext.lower().lstrip(".")

    if file_size == 0:
        return {
            "filename": filename,
            "declared_extension": declared_ext,
            "detected_type": "EMPTY",
            "detected_mime": "application/x-empty",
            "is_mismatch": True,
            "tampering_confidence": 1.0,
            "severity": "CRITICAL",
            "reason": "File is completely empty (0 bytes). Invalid or corrupted evidence artifact.",
            "magic_bytes_hex": ""
        }

    header = b""
    with open(file_path, "rb") as f:
        header = f.read(64)

    detected_type = "UNKNOWN"
    detected_mime = "application/octet-stream"
    description = "Unknown Binary Stream"

    # Check MP4 / MOV (ftyp box at offset 4)
    if len(header) >= 12 and header[4:8] == b"ftyp":
        detected_type = "MP4"
        detected_mime = "video/mp4"
        brand = header[8:12].decode("latin-1", errors="replace")
        description = f"ISO Base Media File / MP4 Video (brand: {brand})"
    elif len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        detected_type = "WAV"
        detected_mime = "audio/wav"
        description = "WAV Audio (RIFF)"
    elif len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"AVI ":
        detected_type = "AVI"
        detected_mime = "video/x-msvideo"
        description = "AVI Video (RIFF)"
    else:
        for magic, offset, mime, ftype, desc in SIGNATURES:
            if header[offset:offset + len(magic)] == magic:
                detected_type = ftype
                detected_mime = mime
                description = desc
                break

    # Determine if declared extension matches detected format
    ext_mapping = {
        "jpg": ["JPEG"],
        "jpeg": ["JPEG"],
        "png": ["PNG"],
        "gif": ["GIF"],
        "pdf": ["PDF"],
        "zip": ["ZIP"],
        "docx": ["ZIP"],
        "xlsx": ["ZIP"],
        "xls": ["ZIP", "XLS_OLE"],
        "mp4": ["MP4"],
        "mkv": ["MKV"],
        "avi": ["AVI", "WAV/AVI"],
        "wav": ["WAV", "WAV/AVI"],
        "mp3": ["MP3"],
    }

    allowed_types = ext_mapping.get(declared_ext, [])
    is_mismatch = False
    reason = "File header matches declared extension."
    severity = "NONE"

    if detected_type != "UNKNOWN":
        if detected_type not in allowed_types:
            is_mismatch = True
            severity = "CRITICAL"
            reason = (
                f"Severe file signature spoofing: Declared as '.{declared_ext}', "
                f"but internal magic bytes identify it as {description} ({detected_type})."
            )
    else:
        # If magic is unknown but declared is common image/audio/video, flag as suspicious
        if declared_ext in ["jpg", "jpeg", "png", "pdf", "mp4", "mp3", "wav"]:
            is_mismatch = True
            severity = "HIGH"
            reason = f"Corrupted or non-standard header for declared type '.{declared_ext}'."

    confidence = 0.98 if is_mismatch else 0.05

    return {
        "filename": filename,
        "declared_extension": declared_ext,
        "detected_type": detected_type,
        "detected_mime": detected_mime,
        "description": description,
        "is_mismatch": is_mismatch,
        "tampering_confidence": confidence,
        "severity": severity,
        "reason": reason,
        "magic_bytes_hex": header[:16].hex(" ").upper()
    }
