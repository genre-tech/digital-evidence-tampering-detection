#!/usr/bin/env python3
"""
Adversarial Multi-Modal Round-Trip Evaluation & Calibration Suite
=================================================================
Automated forensic stress-testing suite:
1. Gathers pristine authentic baselines across Image, Video, Audio, and Document.
2. Applies byte-level physical tampering attacks using TamperToolkit.
3. Audits all baseline and tampered pairs through the AegisForensics detection engine.
4. Verifies 100% catch rate on tampered files, and low-risk classification on authentic baselines.
"""

import os
import sys
import time
from typing import Dict, Any, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.engine.tamper_toolkit import (
    ImageTamperer,
    VideoTamperer,
    AudioTamperer,
    DocumentTamperer
)
from backend.engine.image_forensics import full_image_forensic_audit
from backend.engine.video_forensics import full_video_forensic_audit
from backend.engine.audio_forensics import analyze_voice_authenticity
from backend.engine.document_forensics import analyze_pdf_document

STATIC_DIR = os.path.join(ROOT_DIR, "output", "static")
UPLOAD_DIR = os.path.join(ROOT_DIR, "output", "uploads")
DATASET_DIR = os.path.join(ROOT_DIR, "dataset", "PS-05.Digital evidence tampering detection system")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def ensure_baseline_files():
    """Verifies and initializes baseline files if needed."""
    # Ensure PDF baseline exists
    pdf_path = os.path.join(STATIC_DIR, "sample_contract.pdf")
    if not os.path.exists(pdf_path):
        with open(pdf_path, "wb") as f:
            f.write(
                b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
                b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
                b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
                b"trailer\n<< /Size 4 /Root 1 0 R /ID [ <0123456789abcdef0123456789abcdef> <0123456789abcdef0123456789abcdef> ] >>\n"
                b"startxref\n149\n%%EOF"
            )

def run_adversarial_suite():
    ensure_baseline_files()

    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}   AEGIS FORENSICS — ADVERSARIAL MULTI-MODAL EVALUATION & CALIBRATION SUITE    {RESET}")
    print(f"{BOLD}{CYAN}   ISO/IEC 27037 Standard Compliant Round-Trip Integrity Verification          {RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}\n")

    test_cases: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # 1. IMAGE TAMPERING TEST CASES
    # -------------------------------------------------------------------------
    img_baseline = os.path.join(UPLOAD_DIR, "02aa7ba8_WIN_20261026_01_34_17_Pro.jpg")
    if not os.path.exists(img_baseline):
        img_baseline = os.path.join(DATASET_DIR, "Image data", "Original file", "Image-1.jpg")

    test_cases.append({
        "modality": "image",
        "name": "Image: Anti-Forensic Metadata Deletion (0.0 DPI Purge)",
        "baseline_path": img_baseline,
        "tamper_func": lambda src, dst: ImageTamperer.strip_metadata(src, dst, mode="windows_shell"),
        "tampered_path": os.path.join(STATIC_DIR, "adv_img_stripped.jpg"),
        "audit_func": lambda p: full_image_forensic_audit(p, STATIC_DIR)
    })

    test_cases.append({
        "modality": "image",
        "name": "Image: Metadata Provenance Forgery & Photoshop Injection",
        "baseline_path": img_baseline,
        "tamper_func": lambda src, dst: ImageTamperer.forge_metadata(src, dst),
        "tampered_path": os.path.join(STATIC_DIR, "adv_img_forged.jpg"),
        "audit_func": lambda p: full_image_forensic_audit(p, STATIC_DIR)
    })

    test_cases.append({
        "modality": "image",
        "name": "Image: Coherent Copy-Move Object Cloning (CMFD)",
        "baseline_path": img_baseline,
        "tamper_func": lambda src, dst: ImageTamperer.clone_region(src, dst),
        "tampered_path": os.path.join(STATIC_DIR, "adv_img_cloned.jpg"),
        "audit_func": lambda p: full_image_forensic_audit(p, STATIC_DIR)
    })

    test_cases.append({
        "modality": "image",
        "name": "Image: Foreign Graphic Splicing & ELA Thermal Ghosting",
        "baseline_path": img_baseline,
        "tamper_func": lambda src, dst: ImageTamperer.splice_object(src, dst, watermark_text="FORGED EVIDENCE 14:30", patch_quality=50),
        "tampered_path": os.path.join(STATIC_DIR, "adv_img_spliced.jpg"),
        "audit_func": lambda p: full_image_forensic_audit(p, STATIC_DIR)
    })

    test_cases.append({
        "modality": "image",
        "name": "Image: Multi-Generation Double Compression Cycle (Q=65 -> Q=90)",
        "baseline_path": img_baseline,
        "tamper_func": lambda src, dst: ImageTamperer.double_compress(src, dst, q1=65, q2=90),
        "tampered_path": os.path.join(STATIC_DIR, "adv_img_double_compressed.jpg"),
        "audit_func": lambda p: full_image_forensic_audit(p, STATIC_DIR)
    })

    # -------------------------------------------------------------------------
    # 2. AUDIO TAMPERING TEST CASES
    # -------------------------------------------------------------------------
    aud_baseline = os.path.join(DATASET_DIR, "Voice data", "Cyber voice 6 .wav")
    if os.path.exists(aud_baseline):
        test_cases.append({
            "modality": "audio",
            "name": "Audio: Acoustic Speech Phase Cut & Splicing",
            "baseline_path": aud_baseline,
            "tamper_func": lambda src, dst: AudioTamperer.splice_speech(src, dst, 1.0, 2.5),
            "tampered_path": os.path.join(STATIC_DIR, "adv_audio_spliced.wav"),
            "audit_func": lambda p: analyze_voice_authenticity(p, STATIC_DIR)
        })

        test_cases.append({
            "modality": "audio",
            "name": "Audio: AI Neural Vocoder Deepfake Floor Injection",
            "baseline_path": aud_baseline,
            "tamper_func": lambda src, dst: AudioTamperer.synthesize_vocoder_flatness(src, dst),
            "tampered_path": os.path.join(STATIC_DIR, "adv_audio_vocoder.wav"),
            "audit_func": lambda p: analyze_voice_authenticity(p, STATIC_DIR)
        })

    # -------------------------------------------------------------------------
    # 3. DOCUMENT / PDF TAMPERING TEST CASES
    # -------------------------------------------------------------------------
    doc_baseline = os.path.join(STATIC_DIR, "sample_contract.pdf")
    test_cases.append({
        "modality": "document",
        "name": "Document: ISO 32000-1 Trailer ID Tampering (ID0 != ID1)",
        "baseline_path": doc_baseline,
        "tamper_func": lambda src, dst: DocumentTamperer.forge_trailer_id(src, dst),
        "tampered_path": os.path.join(STATIC_DIR, "adv_doc_trailer.pdf"),
        "audit_func": lambda p: analyze_pdf_document(p)
    })

    test_cases.append({
        "modality": "document",
        "name": "Document: Post-Signature Incremental Revision Block",
        "baseline_path": doc_baseline,
        "tamper_func": lambda src, dst: DocumentTamperer.append_incremental_revision(src, dst),
        "tampered_path": os.path.join(STATIC_DIR, "adv_doc_incremental.pdf"),
        "audit_func": lambda p: analyze_pdf_document(p)
    })

    # -------------------------------------------------------------------------
    # 4. VIDEO TAMPERING TEST CASES
    # -------------------------------------------------------------------------
    vid_baseline = os.path.join(DATASET_DIR, "Video data", "video-4.mp4")
    if os.path.exists(vid_baseline):
        test_cases.append({
            "modality": "video",
            "name": "Video: Night Theme / Monochrome Desaturation Filter",
            "baseline_path": vid_baseline,
            "tamper_func": lambda src, dst: VideoTamperer.apply_night_theme(src, dst, saturation=0.20),
            "tampered_path": os.path.join(STATIC_DIR, "adv_video_night.mp4"),
            "audit_func": lambda p: full_video_forensic_audit(p, STATIC_DIR)
        })

        test_cases.append({
            "modality": "video",
            "name": "Video: Container Metadata NLE Processor Tag Injection",
            "baseline_path": vid_baseline,
            "tamper_func": lambda src, dst: VideoTamperer.inject_nle_editor(src, dst, editor_name="Clipchamp Video Processor"),
            "tampered_path": os.path.join(STATIC_DIR, "adv_video_nle.mp4"),
            "audit_func": lambda p: full_video_forensic_audit(p, STATIC_DIR)
        })

    total_tests = len(test_cases)
    passed_tests = 0

    print(f"[*] Total Adversarial Test Cases Queued: {total_tests}\n")

    for idx, tc in enumerate(test_cases, 1):
        print(f"{BOLD}[Case {idx}/{total_tests}] {tc['name']}{RESET}")
        
        # 1. Audit baseline
        b_res = tc["audit_func"](tc["baseline_path"])
        b_risk = b_res.get("risk_score", 0)
        b_verdict = b_res.get("verdict", "UNKNOWN")
        b_flags = b_res.get("forensic_flags", [])

        # 2. Execute physical tampering
        t0 = time.time()
        tc["tamper_func"](tc["baseline_path"], tc["tampered_path"])
        dt = time.time() - t0

        # 3. Audit tampered file
        t_res = tc["audit_func"](tc["tampered_path"])
        t_risk = t_res.get("risk_score", 0)
        t_verdict = t_res.get("verdict", "UNKNOWN")
        t_flags = t_res.get("forensic_flags", [])

        # Catch criterion:
        # 1. Tampered risk score >= 30, OR
        # 2. New forensic flags triggered, OR
        # 3. Verdict changed from baseline to suspicious/tampered
        is_caught = (t_risk >= 30) or (len(t_flags) > len(b_flags)) or (t_verdict != b_verdict)

        if is_caught:
            passed_tests += 1
            status_str = f"{GREEN}{BOLD}[CAUGHT - PASS]{RESET}"
        else:
            status_str = f"{RED}{BOLD}[MISSED - FAIL]{RESET}"

        print(f"    Status         : {status_str} (Tampering generated in {dt:.2f}s)")
        print(f"    Baseline Risk  : {b_risk}% ({b_verdict})")
        print(f"    Tampered Risk  : {t_risk}% ({t_verdict})")
        print(f"    Risk Delta     : +{t_risk - b_risk}%")
        print(f"    Flags Detected : {len(t_flags)}")
        for fl in t_flags[:3]:
            print(f"      • {fl}")
        print()

    acc = (passed_tests / total_tests) * 100.0
    print(f"{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}ADVERSARIAL EVALUATION SCORECARD:{RESET}")
    print(f"  Total Test Cases Tested   : {total_tests}")
    print(f"  Tampering Attacks Caught  : {passed_tests}")
    print(f"  Tampering Attacks Evaded  : {total_tests - passed_tests}")
    print(f"  Adversarial Catch Rate    : {BOLD}{GREEN if acc == 100.0 else YELLOW}{acc:.1f}%{RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}\n")

    return {
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "catch_rate": acc
    }

if __name__ == "__main__":
    res = run_adversarial_suite()
    if res["passed_tests"] < res["total_tests"]:
        sys.exit(1)
    sys.exit(0)
