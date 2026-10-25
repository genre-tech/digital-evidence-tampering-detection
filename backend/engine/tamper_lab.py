import os
import io
import cv2
import numpy as np
from PIL import Image, ExifTags
from typing import Dict, Any, Tuple, Optional

def get_most_textured_region(img_bgr: np.ndarray, patch_size: int = 140) -> Tuple[int, int]:
    """Finds the (x, y) coordinates of the most feature-rich/textured patch in the image."""
    h, w, _ = img_bgr.shape
    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    orb = cv2.ORB_create(nfeatures=2000)
    kp, _ = orb.detectAndCompute(gray, None)
    
    if not kp or len(kp) < 10:
        # Default fallback to center
        return max(0, (w - patch_size) // 2), max(0, (h - patch_size) // 2)
        
    # Grid binning to find densest keypoint cluster
    cell_size = 80
    grid = {}
    for p in kp:
        gx = int(p.pt[0] // cell_size) * cell_size
        gy = int(p.pt[1] // cell_size) * cell_size
        grid[(gx, gy)] = grid.get((gx, gy), 0) + 1
        
    best_gx, best_gy = max(grid.items(), key=lambda it: it[1])[0]
    best_x = max(10, min(w - patch_size - 10, best_gx))
    best_y = max(10, min(h - patch_size - 10, best_gy))
    return best_x, best_y

def simulate_strip_metadata(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates Windows Shell 'Remove Properties and Personal Information' cleaner
    by zeroing resolution tags and stripping all provenance EXIF tags.
    """
    with Image.open(src_path) as im:
        exif = Image.Exif()
        # Windows Property Handler WIC signature: XResolution=0.0, YResolution=0.0, ResUnit=2
        exif[282] = 0.0 # XResolution
        exif[283] = 0.0 # YResolution
        exif[296] = 2   # ResolutionUnit (inches)
        exif[531] = 1   # YCbCrPositioning
        
        # Save without any other camera tags
        im.save(dst_path, "JPEG", quality=90, exif=exif)
        
    return {
        "attack_type": "strip_metadata",
        "name": "Anti-Forensic Metadata Sanitization",
        "description": "Purged all camera provenance, acquisition timestamps, and injected Windows WIC 0.0 DPI signature.",
        "simulated_modifications": ["Cleared DateTimeOriginal", "Cleared Make/Model", "Cleared Software", "Zeroed X/Y Resolution"]
    }

def simulate_forge_metadata(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates malicious metadata tampering:
    1. Injects a photo manipulation software tag (e.g. 'Adobe Photoshop 2026').
    2. Modifies DateTimeOriginal vs ModifyDate timestamp discrepancy.
    3. Fakes camera Make/Model to contradict DQT table.
    """
    with Image.open(src_path) as im:
        exif = im.getexif()
        if not exif:
            exif = Image.Exif()
            
        exif[271] = "Canon"
        exif[272] = "EOS 5D Mark IV"
        exif[305] = "Adobe Photoshop 2026 (Windows)"
        exif[306] = "2026:05:01 14:22:10" # Manipulated ModifyDate
        
        # SubIFD 0x8769 for DateTimeOriginal
        sub_ifd = exif.get_ifd(0x8769)
        sub_ifd[36867] = "2026:04:10 09:15:00" # Original was 21 days earlier
        sub_ifd[36868] = "2026:04:10 09:15:00"
        
        im.save(dst_path, "JPEG", quality=90, exif=exif)
        
    return {
        "attack_type": "forge_metadata",
        "name": "Metadata Provenance Forgery & Software Tag Injection",
        "description": "Fabricated camera model ('Canon EOS 5D'), injected 'Adobe Photoshop 2026' signature, and created a 21-day timestamp discrepancy.",
        "simulated_modifications": [
            "Injected Software: Adobe Photoshop 2026",
            "Modified ModifyDate: 2026:05:01 vs DateTimeOriginal: 2026:04:10",
            "Contradicted DQT software encoder with hardware Canon make"
        ]
    }

def simulate_copy_move_cloning(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates coherent Copy-Move (CMFD) cloning by locating the densest textured
    feature region and copying it to a spatially displaced coordinate.
    """
    img_bgr = cv2.imread(src_path)
    h, w, _ = img_bgr.shape
    patch_size = min(150, min(h, w) // 3)
    
    x1, y1 = get_most_textured_region(img_bgr, patch_size)
    patch = img_bgr[y1:y1+patch_size, x1:x1+patch_size].copy()
    
    # Calculate displacement vector
    dx = -220 if (x1 > w // 2) else 220
    dy = 60 if (y1 + 60 + patch_size < h) else -60
    
    x2 = max(10, min(w - patch_size - 10, x1 + dx))
    y2 = max(10, min(h - patch_size - 10, y1 + dy))
    
    # Apply seamless clone or clean insertion
    tampered = img_bgr.copy()
    tampered[y2:y2+patch_size, x2:x2+patch_size] = patch
    
    # Preserve original EXIF if possible
    with Image.open(src_path) as orig_pil:
        exif = orig_pil.getexif()
        
    tampered_rgb = cv2.cvtColor(tampered, cv2.COLOR_BGR2RGB)
    pil_tampered = Image.fromarray(tampered_rgb)
    pil_tampered.save(dst_path, "JPEG", quality=92, exif=exif if exif else None)
    
    return {
        "attack_type": "copy_move",
        "name": "Coherent Copy-Move Region Cloning (CMFD)",
        "description": f"Cloned a {patch_size}x{patch_size}px textured feature patch from ({x1}, {y1}) to ({x2}, {y2}) [shift: dx={x2-x1}, dy={y2-y1}].",
        "simulated_modifications": [
            f"Extracted textured object cluster from ({x1}, {y1})",
            f"Duplicated and pasted at ({x2}, {y2})",
            f"Consistent spatial shift vector: ({x2-x1}px, {y2-y1}px)"
        ]
    }

def simulate_foreign_splicing(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates foreign object/splicing with compression discontinuity:
    Inserts a forged foreign graphic patch pre-compressed at quality Q=50,
    then re-encodes the whole file at quality Q=92 (JPEG Ghost effect).
    """
    img_bgr = cv2.imread(src_path)
    h, w, _ = img_bgr.shape
    patch_w, patch_h = min(160, w // 3), min(90, h // 4)
    
    x = max(20, w // 2 - patch_w // 2)
    y = max(20, h // 2 - patch_h // 2)
    
    # Create foreign forged graphic (e.g. simulated timestamp or badge)
    foreign = np.zeros((patch_h, patch_w, 3), dtype=np.uint8)
    foreign[:, :] = (20, 20, 20)
    cv2.rectangle(foreign, (4, 4), (patch_w - 4, patch_h - 4), (0, 0, 220), 2)
    cv2.putText(foreign, "FORGED 13:45", (14, patch_h // 2 + 6), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 2)
    
    # Pre-compress foreign patch at Q=50 in memory
    _, enc = cv2.imencode('.jpg', foreign, [cv2.IMWRITE_JPEG_QUALITY, 50])
    low_q_foreign = cv2.imdecode(enc, cv2.IMREAD_COLOR)
    
    tampered = img_bgr.copy()
    tampered[y:y+patch_h, x:x+patch_w] = low_q_foreign
    
    with Image.open(src_path) as orig_pil:
        exif = orig_pil.getexif()
        
    tampered_rgb = cv2.cvtColor(tampered, cv2.COLOR_BGR2RGB)
    pil_tampered = Image.fromarray(tampered_rgb)
    pil_tampered.save(dst_path, "JPEG", quality=92, exif=exif if exif else None)
    
    return {
        "attack_type": "foreign_splice",
        "name": "Foreign Splicing & JPEG Ghost Compression",
        "description": f"Spliced an external graphic element pre-compressed at low quality (Q=50) into a Q=92 background at ({x}, {y}).",
        "simulated_modifications": [
            f"Inserted foreign forged graphic at ({x}, {y})",
            "Compression history discontinuity (Q=50 foreign patch in Q=92 frame)",
            "Generates acute Error Level Analysis (ELA) thermal anomaly"
        ]
    }

def simulate_double_compression(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates double JPEG compression:
    First compresses the image at Q=65, then re-encodes at Q=90.
    """
    with Image.open(src_path) as im:
        exif = im.getexif()
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=65)
        buf.seek(0)
        with Image.open(buf) as low_im:
            low_im.save(dst_path, "JPEG", quality=90, exif=exif if exif else None)
            
    return {
        "attack_type": "double_compress",
        "name": "Double JPEG Compression Cycle",
        "description": "Simulated multi-generation recompression: Image compressed at Q=65, then re-encoded at Q=90.",
        "simulated_modifications": [
            "Introduced periodic quantization error and DCT grid misalignment",
            "Warps Benford's Law distribution across AC coefficients"
        ]
    }

def simulate_affine_resample(src_path: str, dst_path: str) -> Dict[str, Any]:
    """
    Simulates geometric affine resampling and scaling (1.3x bicubic),
    introducing periodic correlation in pixel derivatives (p-spectrum peaks).
    """
    img_bgr = cv2.imread(src_path)
    h, w, _ = img_bgr.shape
    
    # Scale up and crop back to original resolution
    scaled = cv2.resize(img_bgr, (int(w * 1.3), int(h * 1.3)), interpolation=cv2.INTER_CUBIC)
    ch, cw, _ = scaled.shape
    start_y = (ch - h) // 2
    start_x = (cw - w) // 2
    resampled = scaled[start_y:start_y+h, start_x:start_x+w]
    
    with Image.open(src_path) as orig_pil:
        exif = orig_pil.getexif()
        
    tampered_rgb = cv2.cvtColor(resampled, cv2.COLOR_BGR2RGB)
    pil_tampered = Image.fromarray(tampered_rgb)
    pil_tampered.save(dst_path, "JPEG", quality=90, exif=exif if exif else None)
    
    return {
        "attack_type": "affine_resample",
        "name": "Geometric Affine Resampling (1.3x Bicubic)",
        "description": "Applied 1.3x affine interpolation and cropping, introducing periodic second-derivative interpolation artifacts.",
        "simulated_modifications": [
            "Bicubic spatial interpolation across pixel grid",
            "Creates Dirac delta peaks in 2D FFT second-derivative p-spectrum"
        ]
    }
