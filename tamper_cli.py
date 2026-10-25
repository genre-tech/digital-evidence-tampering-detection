#!/usr/bin/env python3
"""
AegisForensics Tampering Toolkit & Forensic Verification CLI
============================================================
Physical, byte-level multi-modal evidentiary tampering tool and
adversarial stress-testing CLI.

Supports:
- Image: EXIF stripping, metadata forgery, coherent copy-move cloning, foreign splicing, double compression.
- Video: Temporal segment excise, night theme desaturation, NLE container tag injection.
- Audio: Speech segment splicing, AI neural vocoder artifact injection.
- PDF: ISO 32000-1 trailer ID tampering, incremental revision appending.
- Verification: Direct forensic audit and side-by-side adversarial evaluation.
"""

import os
import sys
import argparse
import hashlib
from typing import Dict, Any

# Ensure project root is in path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.engine.tamper_toolkit import (
    ImageTamperer,
    VideoTamperer,
    AudioTamperer,
    DocumentTamperer
)

def compute_sha256(filepath: str) -> str:
    """Calculates SHA-256 hex digest of a file."""
    if not os.path.exists(filepath):
        return "N/A"
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()

def print_banner():
    banner = r"""
   ___              _      ____                        _          
  / _ \___ ___ ____(_)___ / __/___  _______ ___  ___  (_)____  ___
 / __ / -_) _ `/ _ / (_-</ _// _  \/ __/ -_) _ \(_-< / // __/(_-<
/_/ |_\__/\_, /\_//_/___/_/  \___/_/  \__/_//_/___//_/ \__//___/
         /___/                                                   
    Physical Multi-Modal Digital Evidence Tamperer & Auditor
    ISO/IEC 27037 Standard Compliant Adversarial Verification
    """
    print(banner)

def print_file_diff(src: str, dst: str, details: Dict[str, Any]):
    print("\n" + "="*70)
    print(" TAMPERING EXECUTION SUMMARY")
    print("="*70)
    print(f"[*] Action Executed    : {details.get('action')}")
    print(f"[*] Description        : {details.get('description')}")
    print("-" * 70)
    print(f"[-] Source File        : {src}")
    print(f"    Size               : {os.path.getsize(src):,} bytes")
    print(f"    SHA-256            : {compute_sha256(src)}")
    print("-" * 70)
    print(f"[+] Tampered File      : {dst}")
    print(f"    Size               : {os.path.getsize(dst):,} bytes")
    print(f"    SHA-256            : {compute_sha256(dst)}")
    print("="*70)
    print("[SUCCESS] Physical file tampering written successfully to disk.")
    print("          You can now re-upload or test this artifact in AegisForensics.\n")

def handle_image(args):
    src = os.path.abspath(args.input)
    dst = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

    if not os.path.exists(src):
        print(f"[ERROR] Source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Executing image tampering '{args.action}' on: {src} -> {dst}")

    if args.action == "strip_metadata":
        res = ImageTamperer.strip_metadata(src, dst, mode=args.mode)
    elif args.action == "forge_metadata":
        res = ImageTamperer.forge_metadata(
            src, dst,
            software=args.software,
            make=args.make,
            model=args.model,
            date_original=args.date_original,
            modify_date=args.modify_date
        )
    elif args.action == "clone_region":
        res = ImageTamperer.clone_region(src, dst)
    elif args.action == "splice_object":
        res = ImageTamperer.splice_object(
            src, dst,
            watermark_text=args.watermark,
            patch_quality=args.patch_quality,
            output_quality=args.output_quality
        )
    elif args.action == "double_compress":
        res = ImageTamperer.double_compress(src, dst, q1=args.q1, q2=args.q2)
    else:
        print(f"[ERROR] Unknown image action: {args.action}", file=sys.stderr)
        sys.exit(1)

    print_file_diff(src, dst, res)

def handle_video(args):
    src = os.path.abspath(args.input)
    dst = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

    if not os.path.exists(src):
        print(f"[ERROR] Source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Executing video tampering '{args.action}' on: {src} -> {dst}")

    if args.action == "cut_segment":
        res = VideoTamperer.cut_temporal_segment(src, dst, cut_start=args.start, cut_end=args.end)
    elif args.action == "night_theme":
        res = VideoTamperer.apply_night_theme(src, dst, saturation=args.saturation)
    elif args.action == "inject_nle":
        res = VideoTamperer.inject_nle_editor(src, dst, editor_name=args.editor)
    else:
        print(f"[ERROR] Unknown video action: {args.action}", file=sys.stderr)
        sys.exit(1)

    print_file_diff(src, dst, res)

def handle_audio(args):
    src = os.path.abspath(args.input)
    dst = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

    if not os.path.exists(src):
        print(f"[ERROR] Source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Executing audio tampering '{args.action}' on: {src} -> {dst}")

    if args.action == "splice_speech":
        res = AudioTamperer.splice_speech(src, dst, cut_start_sec=args.start, cut_end_sec=args.end)
    elif args.action == "synthesize_vocoder":
        res = AudioTamperer.synthesize_vocoder_flatness(src, dst)
    else:
        print(f"[ERROR] Unknown audio action: {args.action}", file=sys.stderr)
        sys.exit(1)

    print_file_diff(src, dst, res)

def handle_pdf(args):
    src = os.path.abspath(args.input)
    dst = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

    if not os.path.exists(src):
        print(f"[ERROR] Source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Executing PDF tampering '{args.action}' on: {src} -> {dst}")

    if args.action == "forge_trailer":
        res = DocumentTamperer.forge_trailer_id(src, dst)
    elif args.action == "append_revision":
        res = DocumentTamperer.append_incremental_revision(src, dst)
    else:
        print(f"[ERROR] Unknown PDF action: {args.action}", file=sys.stderr)
        sys.exit(1)

    print_file_diff(src, dst, res)

def handle_audit(args):
    target = os.path.abspath(args.file)
    if not os.path.exists(target):
        print(f"[ERROR] File not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Running AegisForensics audit engine on: {target}")

    from backend.engine.magic_validator import detect_file_signature
    from backend.engine.hasher import compute_hashes_and_entropy
    from backend.engine.image_forensics import full_image_forensic_audit
    from backend.engine.video_forensics import full_video_forensic_audit
    from backend.engine.audio_forensics import analyze_voice_authenticity
    from backend.engine.document_forensics import analyze_pdf_document

    hashes = compute_hashes_and_entropy(target)
    magic = detect_file_signature(target)
    mime = magic.get("detected_mime", "")
    ext = magic.get("declared_extension", "")

    out_dir = os.path.join(ROOT_DIR, "output", "static")
    os.makedirs(out_dir, exist_ok=True)

    report = None
    if mime.startswith("image/") or ext in ["jpg", "jpeg", "png", "bmp", "webp"]:
        report = full_image_forensic_audit(target, out_dir)
    elif mime.startswith("video/") or ext in ["mp4", "mkv", "avi", "mov"]:
        report = full_video_forensic_audit(target, out_dir)
    elif mime.startswith("audio/") or ext in ["mp3", "wav", "aac", "ogg", "flac"]:
        report = analyze_voice_authenticity(target, out_dir)
    elif mime == "application/pdf" or ext == "pdf":
        report = analyze_pdf_document(target)
    else:
        report = {
            "verdict": "UNVERIFIED FORMAT",
            "risk_score": 50 if magic.get("is_mismatch") else 0,
            "forensic_flags": [f"MIME Mismatch: {magic.get('reason')}"] if magic.get("is_mismatch") else []
        }

    print("\n" + "="*70)
    print(" FORENSIC EXAMINATION REPORT")
    print("="*70)
    print(f"[*] Target File        : {target}")
    print(f"[*] SHA-256            : {hashes['sha256']}")
    print(f"[*] MIME / Format      : {mime} (Declared: .{ext})")
    print(f"[*] Official Verdict   : {report.get('verdict')}")
    print(f"[*] Tampering Risk     : {report.get('risk_score')}%")
    print(f"[*] Flags Triggered    : {len(report.get('forensic_flags', []))}")
    for idx, flag in enumerate(report.get('forensic_flags', []), 1):
        print(f"    {idx}. {flag}")
    print("="*70 + "\n")

def handle_evaluate(args):
    base = os.path.abspath(args.baseline)
    tamp = os.path.abspath(args.tampered)

    if not os.path.exists(base):
        print(f"[ERROR] Baseline file not found: {base}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(tamp):
        print(f"[ERROR] Tampered file not found: {tamp}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Evaluating Baseline ({base}) vs Tampered ({tamp})...")
    # Audit baseline
    from backend.engine.image_forensics import full_image_forensic_audit
    out_dir = os.path.join(ROOT_DIR, "output", "static")
    b_rep = full_image_forensic_audit(base, out_dir)
    t_rep = full_image_forensic_audit(tamp, out_dir)

    caught = t_rep["risk_score"] >= 45 or len(t_rep["forensic_flags"]) > len(b_rep["forensic_flags"])

    print("\n" + "="*70)
    print(" ADVERSARIAL VERIFICATION SCORECARD")
    print("="*70)
    print(f"Baseline Verdict      : {b_rep['verdict']} (Risk: {b_rep['risk_score']}%)")
    print(f"Tampered Verdict      : {t_rep['verdict']} (Risk: {t_rep['risk_score']}%)")
    print(f"Risk Transition       : {b_rep['risk_score']}% ➔ {t_rep['risk_score']}% (Δ +{t_rep['risk_score'] - b_rep['risk_score']}%)")
    print(f"Detection Successful  : {'YES (TAMPERING CAUGHT)' if caught else 'NO (EVADED)'}")
    print("-" * 70)
    print("Tampered Flags Triggered:")
    for fl in t_rep["forensic_flags"]:
        print(f"  • {fl}")
    print("="*70 + "\n")

def list_attacks():
    print("""
Available Tampering Vectors by Modality:
----------------------------------------
1. IMAGE:
   - strip_metadata   : Removes EXIF, zeros DPI (Windows Shell signature), strips camera tags.
   - forge_metadata   : Injects Photoshop software tag, creates timestamp discrepancy, fakes camera make.
   - clone_region     : Clones textured object region to create coherent copy-move duplication (CMFD).
   - splice_object    : Splices external graphic pre-compressed at low Q to cause compression ghosting.
   - double_compress  : Runs multi-generation JPEG re-compression to warp Benford's Law and DQT tables.

2. VIDEO:
   - cut_segment      : Excises temporal segment (e.g. seconds 10-15), disrupting GOP and burned-in clock.
   - night_theme      : Applies desaturation filter to alter visual conditions.
   - inject_nle       : Injects Clipchamp / Premiere NLE container metadata tags.

3. AUDIO:
   - splice_speech    : Excises speech segment and joins waveforms to create phase cut.
   - synthesize_vocoder: Injects high-frequency noise floor (>7.5kHz) and spectral smoothing (AI voice deepfake).

4. PDF:
   - forge_trailer    : Alters ISO 32000-1 trailer ID array so ID0 != ID1 (proof of alteration).
   - append_revision  : Appends unauthorized incremental post-signature revision block.
    """)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="AegisForensics Physical Multi-Modal Tampering & Verification Toolkit"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Image parser
    img_parser = subparsers.add_parser("image", help="Physical image tampering operations")
    img_parser.add_argument("--action", required=True, choices=["strip_metadata", "forge_metadata", "clone_region", "splice_object", "double_compress"])
    img_parser.add_argument("--input", "-i", required=True, help="Input source image path")
    img_parser.add_argument("--output", "-o", required=True, help="Output tampered image path")
    img_parser.add_argument("--mode", default="windows_shell", choices=["windows_shell", "total_purge", "skeleton"])
    img_parser.add_argument("--software", default="Adobe Photoshop 2026 (Windows)")
    img_parser.add_argument("--make", default="Canon")
    img_parser.add_argument("--model", default="EOS 5D Mark IV")
    img_parser.add_argument("--date_original", default="2026:04:10 09:15:00")
    img_parser.add_argument("--modify_date", default="2026:05:01 14:22:10")
    img_parser.add_argument("--watermark", default="FORGED EVIDENCE 14:30")
    img_parser.add_argument("--patch_quality", type=int, default=50)
    img_parser.add_argument("--output_quality", type=int, default=92)
    img_parser.add_argument("--q1", type=int, default=65)
    img_parser.add_argument("--q2", type=int, default=90)
    img_parser.set_defaults(func=handle_image)

    # Video parser
    vid_parser = subparsers.add_parser("video", help="Physical video tampering operations")
    vid_parser.add_argument("--action", required=True, choices=["cut_segment", "night_theme", "inject_nle"])
    vid_parser.add_argument("--input", "-i", required=True, help="Input source video path")
    vid_parser.add_argument("--output", "-o", required=True, help="Output tampered video path")
    vid_parser.add_argument("--start", type=float, default=10.0, help="Cut start time in seconds")
    vid_parser.add_argument("--end", type=float, default=15.0, help="Cut end time in seconds")
    vid_parser.add_argument("--saturation", type=float, default=0.20, help="Desaturation level")
    vid_parser.add_argument("--editor", default="Clipchamp Video Processor", help="NLE editor name")
    vid_parser.set_defaults(func=handle_video)

    # Audio parser
    aud_parser = subparsers.add_parser("audio", help="Physical audio tampering operations")
    aud_parser.add_argument("--action", required=True, choices=["splice_speech", "synthesize_vocoder"])
    aud_parser.add_argument("--input", "-i", required=True, help="Input source audio path")
    aud_parser.add_argument("--output", "-o", required=True, help="Output tampered audio path")
    aud_parser.add_argument("--start", type=float, default=1.0, help="Cut start time in seconds")
    aud_parser.add_argument("--end", type=float, default=2.5, help="Cut end time in seconds")
    aud_parser.set_defaults(func=handle_audio)

    # PDF parser
    pdf_parser = subparsers.add_parser("pdf", help="Physical document tampering operations")
    pdf_parser.add_argument("--action", required=True, choices=["forge_trailer", "append_revision"])
    pdf_parser.add_argument("--input", "-i", required=True, help="Input source PDF path")
    pdf_parser.add_argument("--output", "-o", required=True, help="Output tampered PDF path")
    pdf_parser.set_defaults(func=handle_pdf)

    # Direct Audit parser
    aud_sub = subparsers.add_parser("audit", help="Run forensic audit engine on any file")
    aud_sub.add_argument("--file", "-f", required=True, help="File to audit")
    aud_sub.set_defaults(func=handle_audit)

    # Evaluate parser
    eval_sub = subparsers.add_parser("evaluate", help="Adversarial evaluation of baseline vs tampered pair")
    eval_sub.add_argument("--baseline", "-b", required=True, help="Baseline authentic file")
    eval_sub.add_argument("--tampered", "-t", required=True, help="Tampered file")
    eval_sub.set_defaults(func=handle_evaluate)

    # List parser
    list_sub = subparsers.add_parser("list", help="List all tampering vectors")
    list_sub.set_defaults(func=lambda _: list_attacks())

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
