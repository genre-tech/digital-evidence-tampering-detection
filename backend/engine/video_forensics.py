import os
import re
import cv2
import json
import subprocess
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

_easyocr_reader = None

def get_ocr_reader():
    global _easyocr_reader
    if _easyocr_reader is None:
        try:
            import easyocr
            _easyocr_reader = easyocr.Reader(['en'], gpu=False)
        except Exception:
            _easyocr_reader = None
    return _easyocr_reader

KNOWN_VIDEO_EDITORS = [
    "clipchamp", "premiere", "capcut", "davinci", "resolve", "final cut",
    "imovie", "vegas", "filmora", "kinemaster", "inshot", "camtasia",
    "handbrake", "lavf", "ffmpeg", "shotcut", "openshot", "powerdirector",
    "obs", "adobe", "quicktime player", "movie maker", "after effects"
]

def analyze_video_container_metadata(video_path: str) -> Dict[str, Any]:
    """
    Extracts container metadata, encoding tags, and tool fingerprints using ffprobe.
    Identifies non-linear editing (NLE) software, re-encoding tools, and stream desync.
    """
    cmd = [
        "ffprobe",
        "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        video_path
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        data = json.loads(proc.stdout)
    except Exception as e:
        return {
            "metadata_available": False,
            "error": str(e),
            "editing_software_detected": False,
            "editor_name": None,
            "format_tags": {},
            "stream_desync_seconds": 0.0
        }

    format_data = data.get("format", {})
    format_tags = format_data.get("tags", {})
    streams = data.get("streams", [])

    editor_detected = False
    editor_name = None
    editor_details = []

    # Check format tags (encoder, comment, software)
    all_tag_strings = []
    for k, v in format_tags.items():
        all_tag_strings.append(f"{k}: {v}")
        v_lower = str(v).lower()
        for ed in KNOWN_VIDEO_EDITORS:
            if ed in v_lower:
                editor_detected = True
                editor_name = v
                editor_details.append(f"Format tag '{k}' indicates editor: '{v}'")
                break

    # Check individual stream tags
    vid_dur = 0.0
    aud_dur = 0.0
    for s in streams:
        c_type = s.get("codec_type")
        s_dur = float(s.get("duration", 0.0))
        if c_type == "video":
            vid_dur = s_dur or vid_dur
        elif c_type == "audio":
            aud_dur = s_dur or aud_dur

        s_tags = s.get("tags", {})
        for sk, sv in s_tags.items():
            sv_lower = str(sv).lower()
            for ed in KNOWN_VIDEO_EDITORS:
                if ed in sv_lower and ed not in ["video"]:
                    editor_detected = True
                    editor_name = editor_name or sv
                    editor_details.append(f"Stream tag '{sk}' indicates editor: '{sv}'")
                    break

    # Calculate Audio/Video duration desync
    desync = abs(vid_dur - aud_dur) if (vid_dur > 0 and aud_dur > 0) else 0.0
    has_desync = desync > 0.25 # Over 250ms discrepancy suggests timeline splice

    # Check raw binary tail for editing tags (e.g. Clipchamp, Premiere at EOF)
    if not editor_detected and os.path.exists(video_path):
        try:
            with open(video_path, "rb") as vf:
                # Read last 64KB where moov/udta atoms reside
                vf.seek(-min(65536, os.path.getsize(video_path)), 2)
                tail = vf.read().lower()
                for ed in KNOWN_VIDEO_EDITORS:
                    if ed.encode() in tail:
                        editor_detected = True
                        editor_name = ed.capitalize()
                        editor_details.append(f"Binary metadata atom contains editing software signature: '{editor_name}'")
                        break
        except Exception:
            pass

    return {
        "metadata_available": True,
        "editing_software_detected": editor_detected,
        "editor_name": editor_name,
        "editor_details": editor_details,
        "major_brand": format_tags.get("major_brand", "unknown"),
        "video_duration": round(vid_dur, 2),
        "audio_duration": round(aud_dur, 2),
        "stream_desync_seconds": round(desync, 2),
        "has_stream_desync": has_desync,
        "format_tags": format_tags
    }

def analyze_video_stream_packets(video_path: str) -> Dict[str, Any]:
    """
    Uses ffprobe to inspect packet presentation timestamps (PTS) and flags
    jitter, packet dropouts, or non-linear timestamp jumps.
    """
    cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=r_frame_rate,nb_frames,duration:packet=pts_time,duration_time,flags",
        "-of", "json",
        video_path
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        data = json.loads(proc.stdout)
    except Exception as e:
        return {
            "packet_analysis_available": False,
            "error": str(e),
            "pts_gaps": [],
            "max_pts_gap": 0.0
        }

    packets = data.get("packets", [])
    if not packets:
        return {"packet_analysis_available": False, "pts_gaps": [], "max_pts_gap": 0.0}

    pts_list = []
    for pkt in packets:
        if "pts_time" in pkt:
            try:
                pts_list.append(float(pkt["pts_time"]))
            except ValueError:
                pass

    pts_gaps = []
    max_gap = 0.0
    if len(pts_list) >= 2:
        nominal_diff = np.median(np.diff(pts_list[:50])) if len(pts_list) > 50 else 0.04
        for i in range(len(pts_list) - 1):
            gap = pts_list[i + 1] - pts_list[i]
            if gap > max_gap:
                max_gap = gap
            if gap > nominal_diff * 2.5 and gap > 0.1:
                pts_gaps.append({
                    "packet_index": i,
                    "pts_from": round(pts_list[i], 3),
                    "pts_to": round(pts_list[i + 1], 3),
                    "gap_seconds": round(gap, 3)
                })

    # GOP (Group of Pictures) & Keyframe Cadence Analysis
    keyframe_indices = []
    keyframe_pts = []
    for idx, pkt in enumerate(packets):
        flags = pkt.get("flags", "")
        if "K" in flags:
            keyframe_indices.append(idx)
            try:
                keyframe_pts.append(float(pkt.get("pts_time", 0.0)))
            except ValueError:
                pass

    gop_intervals = []
    if len(keyframe_indices) > 1:
        gop_intervals = [
            keyframe_indices[i+1] - keyframe_indices[i]
            for i in range(len(keyframe_indices) - 1)
        ]

    nominal_gop = float(np.median(gop_intervals)) if gop_intervals else 0.0
    gop_std = float(np.std(gop_intervals)) if gop_intervals else 0.0

    anomalous_gop_cuts = []
    for i, gop in enumerate(gop_intervals):
        if nominal_gop > 5 and abs(gop - nominal_gop) > max(3.0, nominal_gop * 0.35):
            anomalous_gop_cuts.append({
                "cut_index": i,
                "packet_from": keyframe_indices[i],
                "packet_to": keyframe_indices[i+1],
                "pts_from": round(keyframe_pts[i], 3) if i < len(keyframe_pts) else 0.0,
                "pts_to": round(keyframe_pts[i+1], 3) if i+1 < len(keyframe_pts) else 0.0,
                "interval_frames": gop,
                "expected_interval": round(nominal_gop, 1)
            })

    is_gop_irregular = (gop_std > 3.0 and len(anomalous_gop_cuts) > 0) or (len(anomalous_gop_cuts) >= 2)

    return {
        "packet_analysis_available": True,
        "total_packets": len(packets),
        "pts_gaps": pts_gaps,
        "max_pts_gap": round(max_gap, 4),
        "has_packet_dropout": len(pts_gaps) > 0,
        "keyframe_count": len(keyframe_indices),
        "nominal_gop_size": round(nominal_gop, 1),
        "gop_variance": round(gop_std, 2),
        "is_gop_irregular": is_gop_irregular,
        "anomalous_gop_cuts": anomalous_gop_cuts
    }

def _parse_time_str(s: str) -> Optional[int]:
    """Robust OCR parser for CCTV clocks with optical character normalization."""
    s_clean = s.replace(" ", "")
    char_map = {'Z': '2', 'z': '2', 'O': '0', 'o': '0', 'S': '5', 's': '5', 'l': '1', 'I': '1', '|': '1', 'B': '8'}
    for ch, d in char_map.items():
        s_clean = s_clean.replace(ch, d)

    m = re.search(r'(\d{1,2})[:.](\d{2})[:.](\d{2})', s_clean)
    if m:
        h, mn, sc = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if h < 24 and mn < 60 and sc < 60:
            return h * 3600 + mn * 60 + sc
    return None

def enhance_cctv_patch(patch: np.ndarray) -> np.ndarray:
    """Forensic image enhancement: 2x upscaling, CLAHE contrast, bilateral filtering."""
    if patch.size == 0:
        return patch

    h, w = patch.shape[:2]
    upscaled = cv2.resize(patch, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
    gray = cv2.cvtColor(upscaled, cv2.COLOR_BGR2GRAY) if len(upscaled.shape) == 3 else upscaled
    denoised = cv2.bilateralFilter(gray, 7, 50, 50)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    return clahe.apply(denoised)

def analyze_cctv_burned_timestamps(video_path: str, base_sample_interval: float = 1.0) -> Dict[str, Any]:
    """Adaptive CCTV Clock Anomaly Engine."""
    reader = get_ocr_reader()
    if reader is None:
        return {"ocr_available": False, "cctv_clipping_detected": False, "clipping_events": []}

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"ocr_available": False, "cctv_clipping_detected": False, "clipping_events": []}

    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_sec = total_frames / fps

    ret, frame0 = cap.read()
    if not ret:
        cap.release()
        return {"ocr_available": True, "cctv_clipping_detected": False, "clipping_events": []}

    h, w = frame0.shape[:2]
    
    # Fast, high-accuracy ROI locator: scan top 28% and bottom 22%
    # Bound detection width to <= 960px to ensure sub-second text discovery without CPU stall
    clock_roi = None
    initial_reading = None

    regions = [
        (0, int(h * 0.28)),
        (int(h * 0.78), h)
    ]

    for y_start, y_end in regions:
        crop = frame0[y_start:y_end, :]
        ch, cw = crop.shape[:2]
        if ch <= 0 or cw <= 0:
            continue
        scale = 960.0 / cw if cw > 960 else 1.0
        if scale < 1.0:
            scan_img = cv2.resize(crop, (int(cw * scale), int(ch * scale)), interpolation=cv2.INTER_AREA)
        else:
            scan_img = crop

        try:
            results = reader.readtext(scan_img)
            for bbox, text, conf in results:
                t_sec = _parse_time_str(text)
                if t_sec is not None:
                    pts = np.array(bbox, dtype=np.float32) / scale
                    min_x = max(0, int(np.min(pts[:, 0])) - 20)
                    max_x = min(w, int(np.max(pts[:, 0])) + 20)
                    min_y = max(0, y_start + int(np.min(pts[:, 1])) - 10)
                    max_y = min(h, y_start + int(np.max(pts[:, 1])) + 10)
                    clock_roi = (min_y, max_y, min_x, max_x)
                    initial_reading = {
                        "video_sec": 0.0,
                        "frame_index": 0,
                        "clock_text": text,
                        "clock_sec": t_sec,
                        "conf": round(conf, 2)
                    }
                    break
        except Exception:
            pass

        if clock_roi is not None:
            break

    if clock_roi is None or initial_reading is None:
        cap.release()
        return {
            "ocr_available": True,
            "has_cctv_clock": False,
            "cctv_clipping_detected": False,
            "clipping_events": [],
            "sample_count": 0
        }

    clock_readings = [initial_reading]
    min_y, max_y, min_x, max_x = clock_roi

    curr_sec = base_sample_interval
    while curr_sec < duration_sec:
        cap.set(cv2.CAP_PROP_POS_MSEC, curr_sec * 1000.0)
        ret, frame = cap.read()
        if not ret:
            break

        patch = frame[min_y:max_y, min_x:max_x]
        enhanced = enhance_cctv_patch(patch)
        
        try:
            res = reader.readtext(enhanced)
            for bbox, text, conf in res:
                t_sec = _parse_time_str(text)
                if t_sec is not None:
                    clock_readings.append({
                        "video_sec": round(curr_sec, 2),
                        "frame_index": int(curr_sec * fps),
                        "clock_text": text,
                        "clock_sec": t_sec,
                        "conf": round(conf, 2)
                    })
                    break
        except Exception:
            pass

        curr_sec += base_sample_interval

    candidate_gaps = []
    for i in range(len(clock_readings) - 1):
        c1 = clock_readings[i]
        c2 = clock_readings[i + 1]
        delta_video = c2["video_sec"] - c1["video_sec"]
        delta_clock = c2["clock_sec"] - c1["clock_sec"]
        
        if 1.2 < delta_clock - delta_video < 3600:
            candidate_gaps.append((c1["video_sec"], c2["video_sec"], delta_clock - delta_video))

    refined_clipping_events = []
    for start_win, end_win, est_missing in candidate_gaps:
        sub_readings = []
        sub_sec = start_win
        while sub_sec <= end_win:
            cap.set(cv2.CAP_PROP_POS_MSEC, sub_sec * 1000.0)
            ret, frame = cap.read()
            if not ret: break
            patch = frame[min_y:max_y, min_x:max_x]
            enhanced = enhance_cctv_patch(patch)
            try:
                res = reader.readtext(enhanced)
                for bbox, text, conf in res:
                    t_sec = _parse_time_str(text)
                    if t_sec is not None:
                        sub_readings.append({
                            "video_sec": round(sub_sec, 3),
                            "frame_index": int(sub_sec * fps),
                            "clock_text": text,
                            "clock_sec": t_sec
                        })
                        break
            except Exception:
                pass
            sub_sec += 0.25

        for j in range(len(sub_readings) - 1):
            s1 = sub_readings[j]
            s2 = sub_readings[j + 1]
            d_v = s2["video_sec"] - s1["video_sec"]
            d_c = s2["clock_sec"] - s1["clock_sec"]
            if 1.0 < d_c - d_v < 3600:
                missing = d_c - d_v
                refined_clipping_events.append({
                    "video_timestamp_start": s1["video_sec"],
                    "video_timestamp_end": s2["video_sec"],
                    "exact_frame_start": s1["frame_index"],
                    "exact_frame_end": s2["frame_index"],
                    "clock_before": s1["clock_text"],
                    "clock_after": s2["clock_text"],
                    "missing_duration_seconds": round(missing, 2),
                    "description": (
                        f"High-Precision CCTV Cut Detected! At frame #{s1['frame_index']} ({s1['video_sec']}s) "
                        f"to frame #{s2['frame_index']} ({s2['video_sec']}s), burned clock jumped from "
                        f"'{s1['clock_text']}' to '{s2['clock_text']}' ({missing:.1f}s missing footage)."
                    )
                })
                break
        else:
            refined_clipping_events.append({
                "video_timestamp_start": start_win,
                "video_timestamp_end": end_win,
                "exact_frame_start": int(start_win * fps),
                "exact_frame_end": int(end_win * fps),
                "clock_before": str(start_win),
                "clock_after": str(end_win),
                "missing_duration_seconds": round(est_missing, 2),
                "description": f"Missing CCTV footage detected in {start_win}s - {end_win}s window ({est_missing:.1f}s missing)."
            })

    cap.release()

    return {
        "ocr_available": True,
        "has_cctv_clock": True,
        "sample_count": len(clock_readings),
        "cctv_clipping_detected": len(refined_clipping_events) > 0,
        "clipping_events": refined_clipping_events
    }

def analyze_visual_discontinuities_and_theme(video_path: str) -> Dict[str, Any]:
    """Inspects visual frame continuity and color grading/night theme application."""
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"error": "Could not open video file"}

    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration_sec = total_frames / fps
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    prev_gray = None
    frame_diffs = []
    hsv_values = []
    hsv_saturations = []
    
    step = 5
    f_idx = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if f_idx % step == 0:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
            
            hsv_values.append(np.mean(hsv[:, :, 2]))
            hsv_saturations.append(np.mean(hsv[:, :, 1]))

            if prev_gray is not None:
                diff = np.mean(cv2.absdiff(gray, prev_gray))
                frame_diffs.append((f_idx / fps, diff))
            prev_gray = gray

        f_idx += 1

    cap.release()

    mean_sat = float(np.mean(hsv_saturations)) if hsv_saturations else 0.0
    mean_val = float(np.mean(hsv_values)) if hsv_values else 0.0
    is_night_theme = mean_sat < 32.0

    diff_values = [d[1] for d in frame_diffs]
    sharp_cuts = []
    if diff_values:
        mean_diff = np.mean(diff_values)
        std_diff = np.std(diff_values)
        threshold = mean_diff + 3.0 * std_diff
        
        for sec, d in frame_diffs:
            if d > threshold and d > 3.5:
                sharp_cuts.append({"timestamp_sec": round(sec, 2), "magnitude": round(float(d), 2)})

    return {
        "fps": round(fps, 2),
        "total_frames": total_frames,
        "duration_seconds": round(duration_sec, 2),
        "resolution": f"{width}x{height}",
        "is_night_theme_detected": is_night_theme,
        "mean_saturation": round(mean_sat, 2),
        "mean_value": round(mean_val, 2),
        "sharp_visual_cuts": sharp_cuts
    }

def extract_invid_keyframes(video_path: str, output_dir: str, max_keyframes: int = 6) -> List[Dict[str, Any]]:
    """
    InVID-style keyframe and scene boundary thumbnail extractor:
    Extracts representative keyframes and cut-boundary frames as forensic thumbnails.
    """
    keyframes = []
    if not os.path.exists(video_path):
        return keyframes

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return keyframes

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    duration_sec = total_frames / fps
    base_name = os.path.splitext(os.path.basename(video_path))[0]
    os.makedirs(output_dir, exist_ok=True)

    if total_frames <= 0:
        cap.release()
        return keyframes

    count = min(max_keyframes, max(2, int(duration_sec)))
    sample_indices = [int(i * (total_frames - 1) / (count - 1)) for i in range(count)]

    for idx in sample_indices:
        cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
        ret, frame = cap.read()
        if not ret:
            continue
        thumb = cv2.resize(frame, (320, 180), interpolation=cv2.INTER_AREA)
        thumb_name = f"{base_name}_kf_{idx}.jpg"
        thumb_path = os.path.join(output_dir, thumb_name)
        cv2.imwrite(thumb_path, thumb, [cv2.IMWRITE_JPEG_QUALITY, 85])
        keyframes.append({
            "frame_index": idx,
            "timestamp_seconds": round(idx / fps, 2),
            "thumbnail_file": thumb_name,
            "thumbnail_path": thumb_path
        })

    cap.release()
    return keyframes

def full_video_forensic_audit(video_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Comprehensive Video Forensics Engine:
    1. Container metadata & NLE editing software detection (Clipchamp, Premiere, CapCut, DaVinci, FFmpeg).
    2. Audio/Video stream desynchronization.
    3. CCTV burned-in timestamp OCR continuity.
    4. Packet stream PTS continuity & GOP cadence analysis.
    5. Visual cut and night-theme filter detection.
    6. InVID-style keyframe extraction.
    """
    filename = os.path.basename(video_path)
    meta_res = analyze_video_container_metadata(video_path)
    stream_res = analyze_video_stream_packets(video_path)
    visual_res = analyze_visual_discontinuities_and_theme(video_path)
    ocr_res = analyze_cctv_burned_timestamps(video_path, base_sample_interval=1.0)
    keyframes = extract_invid_keyframes(video_path, output_dir) if output_dir else []

    risk_score = 0
    flags = []

    # 1. NLE Video Editor Fingerprints (Crucial for edited video projects!)
    if meta_res.get("editing_software_detected"):
        risk_score += 65
        flags.append(f"Video Editor Signature Detected: Created/exported via '{meta_res['editor_name']}'")
        for detail in meta_res.get("editor_details", []):
            flags.append(f"Encoding Metadata: {detail}")

    # 2. Audio/Video Stream Desync
    if meta_res.get("has_stream_desync"):
        risk_score += 25
        flags.append(f"Audio/Video stream duration desynchronization ({meta_res['stream_desync_seconds']}s delta)")

    # 3. CCTV clock clipping
    if ocr_res.get("cctv_clipping_detected"):
        risk_score += 60
        for ev in ocr_res["clipping_events"]:
            flags.append(f"CCTV Footage Clipped: {ev['description']}")

    # 4. Stream packet dropouts
    if stream_res.get("has_packet_dropout"):
        risk_score += 30
        flags.append(f"Video container stream dropout detected ({len(stream_res['pts_gaps'])} packet gaps)")

    # 5. Night Theme / Monochrome filter
    if visual_res.get("is_night_theme_detected"):
        risk_score += 25
        flags.append(f"Night theme / monochrome color grading applied (saturation: {visual_res['mean_saturation']})")

    # 6. Sharp visual jump cuts
    if visual_res.get("sharp_visual_cuts"):
        risk_score += min(30, len(visual_res['sharp_visual_cuts']) * 15)
        flags.append(f"Detected {len(visual_res['sharp_visual_cuts'])} anomalous scene jump-cuts (splicing transitions)")

    # 7. GOP Cadence & Inter-frame Keyframe Irregularity
    if stream_res.get("is_gop_irregular"):
        risk_score += 35
        flags.append(
            f"GOP Cadence Disruption: Irregular keyframe interval detected "
            f"(nominal GOP: {stream_res.get('nominal_gop_size')} frames, std: {stream_res.get('gop_variance')}). "
            f"Indicates frame deletion, insertion, or non-linear splicing cut."
        )

    risk_score = min(100, max(0, risk_score))
    authenticity_confidence = max(0, 100 - risk_score)

    verdict = "ORIGINAL / UNTAMPERED"
    if risk_score >= 45:
        verdict = "TAMPERED / EDITED VIDEO"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS / FILTERED"

    return {
        "filename": filename,
        "container_metadata": meta_res,
        "stream_analysis": stream_res,
        "visual_analysis": visual_res,
        "cctv_ocr_analysis": ocr_res,
        "keyframes": keyframes,
        "risk_score": risk_score,
        "authenticity_confidence": authenticity_confidence,
        "verdict": verdict,
        "forensic_flags": flags
    }
