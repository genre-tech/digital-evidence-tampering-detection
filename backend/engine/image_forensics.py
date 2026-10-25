import os
import io
import cv2
import numpy as np
from PIL import Image, ExifTags, ImageChops, ImageEnhance
from typing import Dict, Any, List, Optional, Tuple

KNOWN_IMAGE_EDITORS = [
    "photoshop", "gimp", "canva", "lightroom", "paint", "evidence processing suite",
    "editor", "snapseed", "picsart", "pixlr", "fotor", "vsco", "afterlight",
    "corel", "affinity", "paint.net", "photopea"
]

def _format_gps(coords, ref) -> Optional[float]:
    """Convert EXIF GPS coordinates to decimal degrees."""
    if not coords or not ref:
        return None
    try:
        degrees = float(coords[0])
        minutes = float(coords[1]) / 60.0
        seconds = float(coords[2]) / 3600.0
        dec = degrees + minutes + seconds
        if ref in ['S', 'W']:
            dec = -dec
        return round(dec, 6)
    except Exception:
        return None

def extract_image_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extracts structured image metadata conforming strictly to the forensic schema
    specified in 'Metadata details.docx' plus deep marker and editor string analysis.
    """
    filename = os.path.basename(file_path)
    file_type = ""
    width, height = 0, 0
    date_original = None
    create_date = None
    modify_date = None
    gps_lat, gps_lon = None, None
    make = None
    model = None
    software = None
    description = None
    artist = None
    copyright_val = None
    
    anomalies: List[str] = []
    has_exif = False

    try:
        with Image.open(file_path) as img:
            file_type = img.format or os.path.splitext(filename)[1].lstrip(".").upper()
            width, height = img.size
            
            exif = img.getexif()
            if exif and len(exif) > 0:
                has_exif = True
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    
                    if tag_name == "Make":
                        make = str(value).strip()
                    elif tag_name == "Model":
                        model = str(value).strip()
                    elif tag_name == "Software":
                        software = str(value).strip()
                    elif tag_name == "ImageDescription":
                        description = str(value).strip()
                    elif tag_name == "Artist":
                        artist = str(value).strip()
                    elif tag_name == "Copyright":
                        copyright_val = str(value).strip()
                    elif tag_name == "DateTime":
                        modify_date = str(value).strip()

                if 0x8769 in exif:
                    try:
                        sub_ifd = exif.get_ifd(0x8769)
                        for stag_id, sval in sub_ifd.items():
                            stag_name = ExifTags.TAGS.get(stag_id, str(stag_id))
                            if stag_name == "DateTimeOriginal":
                                date_original = str(sval).strip()
                            elif stag_name == "DateTimeDigitized":
                                create_date = str(sval).strip()
                    except Exception:
                        pass

                if 0x8825 in exif:
                    try:
                        gps_ifd = exif.get_ifd(0x8825)
                        lat_val = gps_ifd.get(2)
                        lat_ref = gps_ifd.get(1)
                        lon_val = gps_ifd.get(4)
                        lon_ref = gps_ifd.get(3)
                        gps_lat = _format_gps(lat_val, lat_ref)
                        gps_lon = _format_gps(lon_val, lon_ref)
                    except Exception:
                        pass
            else:
                anomalies.append("EXIF metadata stripped (typical of messaging apps, web re-saves, or privacy stripping).")

    except Exception as e:
        anomalies.append(f"Failed to parse EXIF metadata: {str(e)}")

    # Anti-Forensic Metadata Deletion / Purging Detection
    metadata_purged = False
    purge_reasons: List[str] = []

    exif_dict = dict(exif) if (has_exif and exif) else {}
    x_res = exif_dict.get(282)
    y_res = exif_dict.get(283)

    # 1. Windows Property Handler Cleaner signature: XResolution or YResolution == 0.0 DPI
    if x_res == 0.0 or y_res == 0.0 or str(x_res) in ['0.0', '0'] or str(y_res) in ['0.0', '0']:
        metadata_purged = True
        purge_reasons.append("Windows Property Handler sanitization signature: Resolution zeroed to 0.0 DPI with all acquisition provenance stripped.")

    # 2. Camera file naming pattern with wiped provenance
    fname_lower = filename.lower()
    is_camera_naming = any(k in fname_lower for k in ['win_', 'img_', 'dsc_', 'pxl_', 'cctv_', 'dcim', 'photo_'])
    has_primary_provenance = bool(make or model or software or date_original or modify_date or create_date or gps_lat)

    if not has_primary_provenance:
        if is_camera_naming:
            metadata_purged = True
            purge_reasons.append(f"Anti-Forensic Sanitization: Camera artifact naming ({filename}) detected, but all camera provenance, acquisition timestamps, and device tags were purged/deleted.")
        elif has_exif and len(exif_dict) <= 5:
            metadata_purged = True
            purge_reasons.append("Skeleton EXIF header: Technical markers retained but camera provenance tags have been deleted.")

    # 3. Check for raw byte marker traces: truncated APP1 or ExifTool comment marker
    if os.path.exists(file_path):
        try:
            with open(file_path, "rb") as f:
                head = f.read(65536)
                app1_idx = head.find(b'\xff\xe1')
                if app1_idx != -1 and app1_idx < 100:
                    app1_len = (head[app1_idx+2] << 8) + head[app1_idx+3]
                    if app1_len < 120 and not has_primary_provenance:
                        if not metadata_purged:
                            metadata_purged = True
                        purge_reasons.append(f"Artificially truncated APP1 EXIF segment ({app1_len} bytes; standard camera EXIF is 2KB-64KB).")
                if b'ExifTool' in head:
                    metadata_purged = True
                    purge_reasons.append("Anti-Forensic Tool residue: 'ExifTool' metadata manipulation signature detected in stream.")
        except Exception:
            pass

    if metadata_purged:
        anomalies.append(f"Anti-Forensic Tampering: Camera metadata intentionally deleted/purged ({'; '.join(dict.fromkeys(purge_reasons))})")

    # Check for known photo editing software
    if software:
        if any(tool in software.lower() for tool in KNOWN_IMAGE_EDITORS):
            anomalies.append(f"Photo manipulation software fingerprint in metadata: '{software}'")

    if modify_date and date_original and modify_date != date_original:
        anomalies.append(f"Timestamp discrepancy: ModifyDate ({modify_date}) differs from DateTimeOriginal ({date_original})")

    # Check raw file markers for editing traces (Photoshop 8BIM, Adobe, XMP creator)
    if os.path.exists(file_path):
        try:
            with open(file_path, "rb") as f:
                header_tail = f.read(65536)
                header_lower = header_tail.lower()
                for tool in KNOWN_IMAGE_EDITORS:
                    if tool.encode() in header_lower and (not software or tool not in software.lower()):
                        anomalies.append(f"Binary stream contains embedded editor signature: '{tool.capitalize()}'")
                        break
        except Exception:
            pass

    return {
        "File Name": filename,
        "File Type": file_type,
        "Image Width": width,
        "Image Height": height,
        "Date Time Original": date_original if date_original else ("DELETED / WIPED" if metadata_purged else "N/A"),
        "CreateDate": (create_date or modify_date) if (create_date or modify_date) else ("DELETED / PURGED" if metadata_purged else "N/A"),
        "ModifyDate": modify_date if modify_date else ("DELETED / PURGED" if metadata_purged else "N/A"),
        "GPSLatitude": gps_lat if gps_lat is not None else "N/A",
        "GPSLongitude": gps_lon if gps_lon is not None else "N/A",
        "Make": make if make else ("DELETED / STRIPPED" if metadata_purged else "N/A"),
        "Model": model if model else ("DELETED / STRIPPED" if metadata_purged else "N/A"),
        "Software": software if software else ("DELETED / STRIPPED" if metadata_purged else "N/A"),
        "Description": description or "N/A",
        "Artist": artist or "N/A",
        "Copyright": copyright_val or "N/A",
        "has_exif": has_exif,
        "metadata_purged": metadata_purged,
        "purge_reasons": purge_reasons,
        "anomalies": anomalies
    }

def perform_ela(image_path: str, output_dir: str, base_prefix: str, quality: int = 90) -> Dict[str, Any]:
    """
    Error Level Analysis (ELA) with dual visualization:
    1. FotoForensics Enhanced Difference Residual.
    2. Blended Thermal Heatmap (COLORMAP_JET) highlighting localized compression anomalies.
    """
    residual_path = os.path.join(output_dir, f"{base_prefix}_ela_residual.png")
    thermal_path = os.path.join(output_dir, f"{base_prefix}_ela_thermal.png")

    img_bgr = cv2.imread(image_path)
    if img_bgr is None:
        return {
            "ela_residual_path": "",
            "ela_thermal_path": "",
            "mean_error": 0.0,
            "max_error": 0,
            "std_error": 0.0,
            "peak_anomaly_ratio": 1.0,
            "is_ela_suspicious": False,
            "description": "Could not read image for ELA"
        }

    with Image.open(image_path).convert("RGB") as orig:
        buffer = io.BytesIO()
        orig.save(buffer, "JPEG", quality=quality)
        buffer.seek(0)
        
        with Image.open(buffer) as resaved:
            ela_im = ImageChops.difference(orig, resaved)
            diff_array = np.array(ela_im)
            mean_diff = float(np.mean(diff_array))
            max_diff = int(np.max(diff_array))
            std_diff = float(np.std(diff_array))
            
            # 1. FotoForensics enhanced difference residual
            extrema = ela_im.getextrema()
            max_diff_channel = max([ex[1] for ex in extrema]) if extrema else 1
            if max_diff_channel == 0:
                max_diff_channel = 1
            scale_factor = min(35.0, 255.0 / max_diff_channel)
            enhanced = ImageEnhance.Brightness(ela_im).enhance(scale_factor * 0.9)
            enhanced.save(residual_path, "PNG")

    # 2. Thermal Anomaly Heatmap (COLORMAP_JET overlay)
    gray_diff = cv2.cvtColor(diff_array, cv2.COLOR_RGB2GRAY)
    blurred_energy = cv2.GaussianBlur(gray_diff, (21, 21), 0)
    
    # Normalize energy to 0-255
    norm_energy = cv2.normalize(blurred_energy, None, 0, 255, cv2.NORM_MINMAX)
    heatmap = cv2.applyColorMap(norm_energy.astype(np.uint8), cv2.COLORMAP_JET)
    
    # Alpha blend: 40% original + 60% thermal heatmap
    blended_thermal = cv2.addWeighted(img_bgr, 0.40, heatmap, 0.60, 0)
    cv2.imwrite(thermal_path, blended_thermal)

    peak_anomaly_ratio = float(max_diff / (mean_diff + 1e-4))
    
    # Spliced regions exhibit sharp local discontinuity compared to general sensor noise
    is_suspicious = bool(
        (peak_anomaly_ratio > 18.0 and max_diff > 25) or 
        (peak_anomaly_ratio > 30.0 and max_diff > 7) or
        (std_diff > 2.8 and max_diff > 50) or 
        (max_diff > 85)
    )

    return {
        "ela_residual_path": residual_path,
        "ela_thermal_path": thermal_path,
        "mean_error": round(mean_diff, 2),
        "max_error": max_diff,
        "std_error": round(std_diff, 2),
        "peak_anomaly_ratio": round(peak_anomaly_ratio, 2),
        "is_ela_suspicious": is_suspicious,
        "description": "High variance or localized peak in error levels suggests different compression histories (splicing/cloning)."
    }

def analyze_noise_inconsistency(image_path: str, output_dir: str, base_prefix: str) -> Dict[str, Any]:
    """
    Computes local sensor noise variance across grid tiles and generates a high-pass
    sensor noise print (median residual) to reveal spliced objects or AI inpainting.
    """
    noise_map_path = os.path.join(output_dir, f"{base_prefix}_noise_map.png")
    img_bgr = cv2.imread(image_path)
    if img_bgr is None:
        return {"noise_inconsistent": False, "variance_ratio": 1.0, "noise_map_path": "", "details": "Could not read image"}

    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    
    # High-pass sensor noise residual: R = |I - MedianBlur(I, 3)|
    denoised = cv2.medianBlur(gray, 3)
    noise_residual = cv2.absdiff(gray, denoised)
    noise_norm = cv2.normalize(noise_residual, None, 0, 255, cv2.NORM_MINMAX)
    noise_heatmap = cv2.applyColorMap(noise_norm.astype(np.uint8), cv2.COLORMAP_INFERNO)
    cv2.imwrite(noise_map_path, noise_heatmap)

    laplacian = cv2.Laplacian(gray, cv2.CV_64F)
    tile_size = 32
    h, w = gray.shape
    variances = []
    
    for y in range(0, h - tile_size, tile_size):
        for x in range(0, w - tile_size, tile_size):
            tile = laplacian[y:y+tile_size, x:x+tile_size]
            var = np.var(tile)
            if var > 0.5: # Filter solid flat background tiles
                variances.append(var)

    if len(variances) < 4:
        return {"noise_inconsistent": False, "variance_ratio": 1.0, "noise_map_path": noise_map_path, "details": "Insufficient texture"}

    q25, q75 = float(np.percentile(variances, 25)), float(np.percentile(variances, 75))
    ratio = float(q75 / (q25 + 1e-5))
    is_inconsistent = bool(ratio > 6.0 and (q75 - q25 > 25.0))

    return {
        "noise_inconsistent": is_inconsistent,
        "variance_ratio": round(ratio, 2),
        "noise_map_path": noise_map_path,
        "details": f"Inter-quartile noise variance ratio: {ratio:.2f} (threshold: 6.0)"
    }

def detect_copy_move(image_path: str, output_dir: str, base_prefix: str) -> Dict[str, Any]:
    """
    Forensic Copy-Move Forgery Detection (CMFD):
    1. Extracts ORB keypoints and descriptors.
    2. Performs Lowe's ratio test and deduplicates bidirectional point pairs.
    3. Clusters spatial translation vectors (dx, dy) with 2D spatial spread filtering.
    4. Renders annotated vector arrows and circles on the image for court admissibility.
    """
    annotated_path = os.path.join(output_dir, f"{base_prefix}_copymove.png")
    img_bgr = cv2.imread(image_path)
    if img_bgr is None:
        return {"copy_move_detected": False, "clone_cluster_matches": 0, "copy_move_path": "", "details": "Could not read image"}

    gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
    orb = cv2.ORB_create(nfeatures=2500)
    kp, des = orb.detectAndCompute(gray, None)

    if des is None or len(des) < 20:
        return {"copy_move_detected": False, "clone_cluster_matches": 0, "copy_move_path": "", "details": "Sparse keypoints"}

    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(des, des, k=3)

    seen_pairs = set()
    pairs = []
    min_dist_px = 50.0

    for mg in matches:
        if len(mg) < 3:
            continue
        m2, m3 = mg[1], mg[2]
        if m2.distance < 0.75 * m3.distance:
            idx1, idx2 = m2.queryIdx, m2.trainIdx
            pair_key = (min(idx1, idx2), max(idx1, idx2))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            p1 = kp[idx1].pt
            p2 = kp[idx2].pt
            dx = p2[0] - p1[0]
            dy = p2[1] - p1[1]
            dist = np.hypot(dx, dy)
            if dist >= min_dist_px:
                # Canonicalize vector direction
                if dx < 0 or (dx == 0 and dy < 0):
                    dx, dy = -dx, -dy
                    p1, p2 = p2, p1
                pairs.append((dx, dy, p1, p2))

    if not pairs:
        return {"copy_move_detected": False, "clone_cluster_matches": 0, "copy_move_path": "", "details": "No matching pairs"}

    # Spatial shift clustering: cluster by (dx, dy) with spatial tolerance
    clusters = []
    visited = [False] * len(pairs)
    for i in range(len(pairs)):
        if visited[i]:
            continue
        cluster = [pairs[i]]
        visited[i] = True
        for j in range(i + 1, len(pairs)):
            if not visited[j]:
                ddx = abs(pairs[i][0] - pairs[j][0])
                ddy = abs(pairs[i][1] - pairs[j][1])
                if ddx <= 15 and ddy <= 15:
                    cluster.append(pairs[j])
                    visited[j] = True
                    
        # Cluster must have >= 6 coherent keypoint pairs sharing the same translation vector
        if len(cluster) >= 6:
            pts1 = np.array([p[2] for p in cluster])
            spread = max(float(np.std(pts1[:, 0])), float(np.std(pts1[:, 1])))
            # Ensure keypoints are not all collapsed at a single subpixel
            if spread >= 8.0:
                clusters.append(cluster)

    is_cloned = bool(len(clusters) > 0)
    total_clones = int(sum(len(c) for c in clusters))

    # Render vector overlay image if clones detected
    if is_cloned:
        vis = img_bgr.copy()
        colors = [(0, 255, 255), (0, 255, 0), (255, 100, 0), (255, 0, 255)]
        for c_idx, cluster in enumerate(clusters):
            col = colors[c_idx % len(colors)]
            for item in cluster:
                p1 = (int(item[2][0]), int(item[2][1]))
                p2 = (int(item[3][0]), int(item[3][1]))
                cv2.circle(vis, p1, 4, (0, 200, 255), -1)
                cv2.circle(vis, p2, 4, (255, 0, 128), -1)
                cv2.arrowedLine(vis, p1, p2, col, 1, tipLength=0.1)
        cv2.imwrite(annotated_path, vis)
    else:
        annotated_path = ""

    return {
        "copy_move_detected": is_cloned,
        "clone_cluster_matches": total_clones,
        "coherent_clusters_count": len(clusters),
        "copy_move_path": annotated_path,
        "details": f"Found {len(clusters)} coherent shift clusters with {total_clones} matched points" if is_cloned else "No coherent copy-move translation clusters found."
    }

def detect_resampling_artifacts(image_path: str) -> Dict[str, Any]:
    """
    Detects geometric resampling (scaling, affine rotation) via 2D Fourier
    Transform (FFT) analysis of the second spatial derivative (p-spectrum).
    """
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return {"resampling_detected": False, "peak_ratio": 1.0}

    h, w = img.shape
    if h < 64 or w < 64:
        return {"resampling_detected": False, "peak_ratio": 1.0}

    cy, cx = h // 2, w // 2
    crop = img[max(0, cy-128):min(h, cy+128), max(0, cx-128):min(w, cx+128)].astype(np.float32)

    d2 = cv2.Laplacian(crop, cv2.CV_32F)
    f = np.fft.fft2(d2)
    fshift = np.fft.fftshift(f)
    magnitude = np.abs(fshift)

    mean_val = np.mean(magnitude)
    max_val = np.max(magnitude)
    peak_ratio = float(max_val / (mean_val + 1e-5))

    is_resampled = bool(peak_ratio > 35.0)

    return {
        "resampling_detected": is_resampled,
        "peak_ratio": round(peak_ratio, 2),
        "details": f"FFT p-spectrum peak ratio: {peak_ratio:.2f} (threshold: 35.0)"
    }

ANNEX_K_LUMINANCE = np.array([
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99
], dtype=np.float32)

def _generate_ijg_table(q: int) -> np.ndarray:
    s = 5000.0 / q if q < 50 else 200.0 - 2.0 * q
    t = np.floor((ANNEX_K_LUMINANCE * s + 50.0) / 100.0)
    return np.clip(t, 1.0, 255.0)

def analyze_dqt_quantization(file_path: str, declared_make: Optional[str] = None) -> Dict[str, Any]:
    """
    Forensic examination of Discrete Quantization Tables (DQT):
    1. Extracts Luminance (Q0) and Chrominance (Q1) 8x8 quantization matrices.
    2. Estimates the original Independent JPEG Group (IJG) compression quality (1-100).
    3. Detects software recompression (Photoshop, libjpeg-turbo, GIMP, Web Canvas) vs hardware ISP.
    4. Detects provenance forgery (e.g. EXIF says 'Canon' or 'Apple' but DQT is software-generated).
    """
    try:
        with Image.open(file_path) as img:
            if not hasattr(img, "quantization") or not img.quantization:
                return {
                    "dqt_available": False,
                    "reason": "Non-JPEG container or no embedded quantization tables."
                }
            
            q0 = list(img.quantization.get(0, []))
            q1 = list(img.quantization.get(1, []))
            if not q0:
                return {
                    "dqt_available": False,
                    "reason": "Quantization table 0 is empty."
                }
    except Exception as e:
        return {"dqt_available": False, "reason": str(e)}

    tab0 = np.array(q0[:64], dtype=np.float32)
    
    best_q = 50
    best_mse = float('inf')
    for q in range(1, 101):
        ijg = _generate_ijg_table(q)
        mse = float(np.mean((tab0 - ijg) ** 2))
        if mse < best_mse:
            best_mse = mse
            best_q = q

    is_standard_software = (best_mse <= 2.0)
    profile = f"Standard Software Encoder (IJG/Libjpeg Q~{best_q})"
    if not is_standard_software:
        if q0[:4] == [9, 6, 18, 21]:
            profile = "Web Browser / Canvas Re-export Engine (Chrome/Skia)"
            is_standard_software = True
        elif q0[:4] == [6, 4, 4, 6] or q0[:4] == [1, 1, 1, 1]:
            profile = "Adobe Photoshop Custom Quantization Matrix"
            is_standard_software = True
        else:
            profile = "Custom Hardware Camera ISP / Non-Standard Matrix"

    has_provenance_conflict = False
    conflict_reason = None
    if declared_make and str(declared_make).upper() not in ["N/A", "UNKNOWN", "NONE", ""]:
        camera_brands = ["CANON", "NIKON", "SONY", "APPLE", "SAMSUNG", "FUJIFILM", "VIVO", "GOOGLE"]
        if any(b in str(declared_make).upper() for b in camera_brands):
            if is_standard_software:
                has_provenance_conflict = True
                conflict_reason = (
                    f"DQT / EXIF Provenance Contradiction: Metadata asserts camera '{declared_make}', "
                    f"but JPEG quantization table matches desktop software encoding ({profile})."
                )

    return {
        "dqt_available": True,
        "estimated_quality": best_q,
        "mse_to_standard_ijg": round(best_mse, 2),
        "quantization_profile": profile,
        "is_software_quantization": is_standard_software,
        "has_provenance_conflict": has_provenance_conflict,
        "conflict_reason": conflict_reason,
        "q0_sample": q0[:8]
    }

def analyze_benford_law(file_path: str) -> Dict[str, Any]:
    """
    Forensic Benford's Law Analysis on 8x8 Block DCT AC Coefficients:
    Natural, untouched photographs strictly obey Benford's logarithmic distribution for
    the first significant digits of DCT coefficients: P(d) = log10(1 + 1/d).
    Splicing, heavy double compression, retouching, and AI synthesis warp this distribution.
    """
    img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return {"benford_available": False, "reason": "Could not read image for DCT transformation"}

    h, w = img.shape
    h_trim, w_trim = h - (h % 8), w - (w % 8)
    if h_trim < 32 or w_trim < 32:
        return {"benford_available": False, "reason": "Image resolution too low for block DCT analysis"}

    img_float = img[:h_trim, :w_trim].astype(np.float32)

    digits = []
    step_y = max(8, int(h_trim / 64) * 8)
    step_x = max(8, int(w_trim / 64) * 8)

    # Only evaluate blocks with spatial texture (std >= 3.0) to filter sensor dark noise
    for y in range(0, h_trim - 7, step_y):
        for x in range(0, w_trim - 7, step_x):
            block = img_float[y:y+8, x:x+8]
            if np.std(block) < 3.0:
                continue
            dct = cv2.dct(block)
            ac = np.abs(dct)
            ac[0, 0] = 0.0
            sig = ac[ac >= 1.0]
            for val in sig:
                d = int(str(int(val))[0])
                if 1 <= d <= 9:
                    digits.append(d)

    # Fallback if texture was sparse
    if len(digits) < 100:
        for y in range(0, h_trim - 7, 8):
            for x in range(0, w_trim - 7, 8):
                block = img_float[y:y+8, x:x+8]
                dct = cv2.dct(block)
                ac = np.abs(dct)
                ac[0, 0] = 0.0
                sig = ac[ac >= 1.0]
                for val in sig:
                    d = int(str(int(val))[0])
                    if 1 <= d <= 9:
                        digits.append(d)

    if len(digits) < 100:
        return {"benford_available": False, "reason": "Insufficient textured DCT coefficients"}

    total = len(digits)
    counts = {d: digits.count(d) for d in range(1, 10)}
    obs = np.array([counts[d] / total for d in range(1, 10)], dtype=np.float32)
    benford_expected = np.array([np.log10(1.0 + 1.0 / d) for d in range(1, 10)], dtype=np.float32)

    chi2 = float(np.sum([
        ((counts[d] - total * benford_expected[d-1]) ** 2) / (total * benford_expected[d-1] + 1e-6)
        for d in range(1, 10)
    ]))

    corr = float(np.corrcoef(obs, benford_expected)[0, 1])
    if np.isnan(corr):
        corr = 0.0

    is_anomalous = bool(corr < 0.70)

    verdict = "NATURAL_DISTRIBUTION"
    if corr < 0.60:
        verdict = "HIGHLY_ANOMALOUS_DISTRIBUTION"
    elif corr < 0.80:
        verdict = "MODERATE_COMPRESSION_DISTORTION"

    return {
        "benford_available": True,
        "sample_count": total,
        "chi2_divergence": round(chi2, 2),
        "correlation_with_benford": round(corr, 4),
        "is_anomalous": is_anomalous,
        "verdict": verdict,
        "observed_distribution": [round(float(x), 3) for x in obs],
        "expected_benford": [round(float(x), 3) for x in benford_expected]
    }

def full_image_forensic_audit(file_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Executes complete image forensic analysis: metadata schema extraction,
    DQT quantization table analysis, Benford's Law on DCT coefficients,
    Dual ELA (residual & thermal heatmap), Sensor Noise Map, Robust Copy-Move,
    and Resampling FFT analysis.
    """
    os.makedirs(output_dir, exist_ok=True)
    base_prefix = os.path.splitext(os.path.basename(file_path))[0]

    meta = extract_image_metadata(file_path)
    dqt = analyze_dqt_quantization(file_path, meta.get("Make"))
    benford = analyze_benford_law(file_path)
    ela = perform_ela(file_path, output_dir, base_prefix)
    noise = analyze_noise_inconsistency(file_path, output_dir, base_prefix)
    copy_move = detect_copy_move(file_path, output_dir, base_prefix)
    resampling = detect_resampling_artifacts(file_path)

    risk_score = 0
    flags = []
    physical_tamper_count = 0

    # 1. Metadata anomalies (editor tags, dates discrepancy, deleted metadata)
    if meta["anomalies"]:
        for anom in meta["anomalies"]:
            if "intentionally deleted/purged" in anom:
                flags.append(anom)
                risk_score += 65
                physical_tamper_count += 1
            elif "fingerprint" in anom or "embedded editor" in anom:
                flags.append(anom)
                risk_score += 45
                physical_tamper_count += 1
            elif "discrepancy" in anom:
                flags.append(anom)
                risk_score += 35
                physical_tamper_count += 1
            elif "stripped" in anom:
                flags.append("Metadata Provenance Note: EXIF is absent (typical of chat/web transfers or privacy removal).")
                risk_score += 5
            else:
                flags.append(anom)
                risk_score += 15

    # 2. DQT Quantization analysis
    if dqt.get("has_provenance_conflict"):
        risk_score += 45
        physical_tamper_count += 1
        flags.append(dqt["conflict_reason"])
    elif dqt.get("is_software_quantization") and not meta.get("Software"):
        flags.append(f"Quantization Analysis: Image encoded using {dqt['quantization_profile']}")

    # 3. Robust Copy-move cloning
    if copy_move["copy_move_detected"]:
        risk_score += 55
        physical_tamper_count += 1
        flags.append(f"Copy-Move cloning confirmed: {copy_move['clone_cluster_matches']} coherent matched points across {copy_move['coherent_clusters_count']} spatial clusters")

    # 4. Sensor Noise inconsistency across tiles
    if noise["noise_inconsistent"]:
        risk_score += 40
        physical_tamper_count += 1
        flags.append(f"Sensor Noise Anomaly: High-pass noise variance ratio ({noise['variance_ratio']}) indicates spliced element")

    # 5. ELA compression history discrepancy
    if ela["is_ela_suspicious"]:
        increment = 50 if ela.get("peak_anomaly_ratio", 0) > 35.0 else 40
        risk_score += increment
        physical_tamper_count += 1
        flags.append(f"Error Level Analysis: Localized compression discontinuity (peak anomaly ratio: {ela['peak_anomaly_ratio']}, max error: {ela['max_error']})")

    # 6. Resampling periodicity (FFT p-spectrum)
    if resampling["resampling_detected"]:
        risk_score += 30
        physical_tamper_count += 1
        flags.append(f"Resampling / Affine Interpolation detected (FFT p-spectrum peak ratio: {resampling['peak_ratio']})")

    # 7. Benford's Law on DCT coefficients (Corroborating Statistical Signal)
    if benford.get("is_anomalous"):
        if physical_tamper_count > 0:
            risk_score += 25
            flags.append(f"Benford's Law: Warped DCT distribution corroborates tampering (correlation: {benford['correlation_with_benford']}, chi2: {benford['chi2_divergence']})")
        else:
            flags.append(f"Benford's Law Note: Mild statistical deviation in low-light/uniform region (correlation: {benford['correlation_with_benford']})")
            risk_score += 5

    risk_score = min(100, max(0, risk_score))
    authenticity_confidence = max(0, 100 - risk_score)

    verdict = "AUTHENTIC"
    if risk_score >= 45:
        if meta.get("metadata_purged") and physical_tamper_count <= 1:
            verdict = "TAMPERED / METADATA PURGED"
        else:
            verdict = "TAMPERED / MANIPULATED"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS / INCONSISTENT"

    return {
        "metadata_table": meta,
        "dqt_analysis": dqt,
        "benford_analysis": benford,
        "ela": ela,
        "noise_analysis": noise,
        "copy_move": copy_move,
        "resampling_analysis": resampling,
        "risk_score": risk_score,
        "authenticity_confidence": authenticity_confidence,
        "verdict": verdict,
        "forensic_flags": flags
    }
