import os
import re
from typing import Dict, Any, List, Optional

KNOWN_PDF_EDITORS = [
    "acrobat", "ilovepdf", "smallpdf", "pdfescape", "sejda", "canva",
    "word", "libreoffice", "pdf-xchange", "foxit", "nitro", "photoshop",
    "illustrator", "indesign", "distiller", "ghostscript", "camscanner"
]

def analyze_pdf_document(file_path: str) -> Dict[str, Any]:
    """
    Forensic examination of PDF documents:
    1. ISO 32000-1 Permanent ID vs Changing ID mismatch (/ID [<ID0> <ID1>]).
    2. Incremental revisions / update detection (counting %%EOF markers).
    3. Document editing software fingerprints.
    4. CreationDate vs ModDate discrepancy.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    if file_size == 0:
        return {
            "filename": filename,
            "modality": "document",
            "verdict": "EMPTY / UNREADABLE",
            "risk_score": 100,
            "authenticity_confidence": 0,
            "forensic_flags": ["Document file is 0 bytes (empty)."]
        }

    with open(file_path, "rb") as f:
        content = f.read()

    flags: List[str] = []
    risk_score = 0

    # 1. ISO 32000-1 Trailer /ID Check
    # ID[0] is Permanent Identifier (creation). ID[1] is Changing Identifier (each edit/resave).
    id_mismatch = False
    id_match = re.search(rb"/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]", content)
    if id_match:
        id0 = id_match.group(1).decode().upper()
        id1 = id_match.group(2).decode().upper()
        if id0 != id1:
            id_mismatch = True
            risk_score += 45
            flags.append(
                f"ISO 32000-1 Document Alteration Detected: Permanent ID ({id0[:8]}...) "
                f"differs from Changing ID ({id1[:8]}...). Document was modified/re-saved after initial creation."
            )

    # 2. Count %%EOF markers (Incremental Updates)
    eof_matches = re.findall(b"%%EOF", content)
    revision_count = len(eof_matches)
    has_incremental_updates = revision_count > 1
    if has_incremental_updates:
        risk_score += 35
        flags.append(
            f"Multiple incremental PDF updates detected ({revision_count} revision %%EOF markers). "
            "Body was appended or updated post-creation."
        )

    # 3. Extract Metadata
    metadata: Dict[str, str] = {}
    for field in [b"Title", b"Author", b"Subject", b"Creator", b"Producer", b"CreationDate", b"ModDate"]:
        m = re.search(rb"/" + field + rb"\s*\((.*?)\)", content)
        if m:
            try:
                metadata[field.decode()] = m.group(1).decode("latin-1", errors="replace")
            except Exception:
                pass
        else:
            m_hex = re.search(rb"/" + field + rb"\s*<([0-9a-fA-F]+)>", content)
            if m_hex:
                try:
                    metadata[field.decode()] = bytes.fromhex(m_hex.group(1).decode()).decode("latin-1", errors="replace")
                except Exception:
                    pass

    # 4. Check Editor Signatures
    producer = metadata.get("Producer", "").lower()
    creator = metadata.get("Creator", "").lower()
    combined_tools = f"{producer} {creator}"

    detected_editor = None
    for tool in KNOWN_PDF_EDITORS:
        if tool in combined_tools:
            detected_editor = tool.capitalize()
            break

    # Also search raw stream for editor signatures
    if not detected_editor:
        content_lower = content[:65536].lower() + content[-65536:].lower()
        for tool in KNOWN_PDF_EDITORS:
            if tool.encode() in content_lower:
                detected_editor = tool.capitalize()
                break

    if detected_editor:
        risk_score += 40
        flags.append(f"Document Editing Software Fingerprint: Altered via '{detected_editor}' (Producer: {metadata.get('Producer', 'N/A')})")

    # 5. Check CreationDate vs ModDate discrepancy
    c_date = metadata.get("CreationDate", "")
    m_date = metadata.get("ModDate", "")
    if c_date and m_date and c_date != m_date:
        risk_score += 25
        flags.append(f"Document timestamp discrepancy: CreationDate differs from ModDate ({m_date})")

    # 6. Embedded Executable / JavaScript
    if b"/JavaScript" in content or b"/JS" in content:
        risk_score += 30
        flags.append("Embedded executable JavaScript object found inside PDF document stream.")

    risk_score = min(100, max(0, risk_score))
    authenticity_confidence = max(0, 100 - risk_score)

    verdict = "ORIGINAL / UNMODIFIED DOCUMENT"
    if risk_score >= 45:
        verdict = "MODIFIED / EDITED DOCUMENT"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS DOCUMENT"

    return {
        "filename": filename,
        "modality": "document",
        "file_size": file_size,
        "revision_count": revision_count,
        "has_incremental_updates": has_incremental_updates,
        "id_mismatch": id_mismatch,
        "metadata": metadata,
        "risk_score": risk_score,
        "authenticity_confidence": authenticity_confidence,
        "verdict": verdict,
        "forensic_flags": flags
    }
