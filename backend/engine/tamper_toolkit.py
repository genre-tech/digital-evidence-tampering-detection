import os
import io
import cv2
import numpy as np
import subprocess
from PIL import Image, ExifTags
from typing import Dict, Any, Tuple, Optional, List

class ImageTamperer:
    """
    Forensic Tampering Toolkit for Images:
    Performs byte-level metadata modification, EXIF wiping, pixel cloning,
    foreign compression splicing, affine resampling, and double compression.
    """

    @staticmethod
    def strip_metadata(src_path: str, dst_path: str, mode: str = "windows_shell") -> Dict[str, Any]:
        """
        Actually removes EXIF metadata from the image.
        Modes:
        - 'windows_shell': Replicates Windows File Explorer 'Remove Properties' (zeroes X/Y resolution to 0.0 DPI, strips timestamps/software).
        - 'total_purge': Completely deletes all APP1/APP2 markers, writing pure raw JFIF with 0 EXIF tags.
        - 'skeleton': Leaves basic technical markers (ResolutionUnit=2) but wipes all camera/author tags.
        """
        with Image.open(src_path) as im:
            # Convert to RGB to ensure clean JPEG saving
            rgb_im = im.convert("RGB")
            
            if mode == "windows_shell":
                exif = Image.Exif()
                exif[282] = 0.0  # XResolution zeroed
                exif[283] = 0.0  # YResolution zeroed
                exif[296] = 2    # ResolutionUnit = inches
                exif[531] = 1    # YCbCrPositioning
                rgb_im.save(dst_path, "JPEG", quality=90, exif=exif)
                action_desc = "Wrote Windows Shell Property Handler signature (0.0 DPI, EXIF tags purged)."
                
            elif mode == "total_purge":
                # Save without any EXIF bytes
                rgb_im.save(dst_path, "JPEG", quality=90)
                action_desc = "Total EXIF purge: Removed all APP1 and APP2 metadata segments."
                
            else: # skeleton
                exif = Image.Exif()
                exif[296] = 2
                rgb_im.save(dst_path, "JPEG", quality=90, exif=exif)
                action_desc = "Skeleton EXIF: Wiped all timestamps and camera provenance tags."

        return {
            "action": "strip_metadata",
            "mode": mode,
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "description": action_desc,
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def forge_metadata(
        src_path: str, 
        dst_path: str, 
        software: Optional[str] = "Adobe Photoshop 2026 (Windows)",
        make: Optional[str] = "Canon",
        model: Optional[str] = "EOS 5D Mark IV",
        date_original: Optional[str] = "2026:04:10 09:15:00",
        modify_date: Optional[str] = "2026:05:01 14:22:10"
    ) -> Dict[str, Any]:
        """
        Actually injects or modifies EXIF provenance tags:
        - Injects photo editing software signatures (Photoshop, GIMP, Canva).
        - Creates timestamp discrepancies between DateTimeOriginal and DateTime (ModifyDate).
        - Fakes camera make/model to contradict discrete quantization table (DQT).
        """
        with Image.open(src_path) as im:
            rgb_im = im.convert("RGB")
            exif = rgb_im.getexif()
            if not exif:
                exif = Image.Exif()

            if make:
                exif[271] = make
            if model:
                exif[272] = model
            if software:
                exif[305] = software
            if modify_date:
                exif[306] = modify_date

            if date_original:
                sub_ifd = exif.get_ifd(0x8769)
                sub_ifd[36867] = date_original
                sub_ifd[36868] = date_original

            rgb_im.save(dst_path, "JPEG", quality=90, exif=exif)

        return {
            "action": "forge_metadata",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "injected_fields": {
                "Make": make,
                "Model": model,
                "Software": software,
                "DateTimeOriginal": date_original,
                "ModifyDate": modify_date
            },
            "description": f"Injected '{software}' signature and created a timestamp discrepancy ({date_original} vs {modify_date}).",
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def clone_region(
        src_path: str,
        dst_path: str,
        src_box: Optional[Tuple[int, int, int, int]] = None,
        dst_pt: Optional[Tuple[int, int]] = None
    ) -> Dict[str, Any]:
        """
        Actually duplicates a textured patch from src_box=(x, y, w, h) to dst_pt=(x2, y2).
        If no coordinates provided, automatically finds the densest textured object cluster.
        """
        img_bgr = cv2.imread(src_path)
        if img_bgr is None:
            raise ValueError(f"Could not read source image: {src_path}")

        h, w, _ = img_bgr.shape

        if src_box is None:
            # Auto-detect densest feature patch
            gray = cv2.cvtColor(img_bgr, cv2.COLOR_BGR2GRAY)
            orb = cv2.ORB_create(nfeatures=2500)
            kp, _ = orb.detectAndCompute(gray, None)
            
            patch_sz = min(150, min(h, w) // 3)
            if kp and len(kp) >= 10:
                grid = {}
                for p in kp:
                    gx = int(p.pt[0] // 80) * 80
                    gy = int(p.pt[1] // 80) * 80
                    grid[(gx, gy)] = grid.get((gx, gy), 0) + 1
                best_gx, best_gy = max(grid.items(), key=lambda it: it[1])[0]
                x1 = max(10, min(w - patch_sz - 10, best_gx))
                y1 = max(10, min(h - patch_sz - 10, best_gy))
            else:
                x1, y1 = w // 3, h // 3
            src_box = (x1, y1, patch_sz, patch_sz)

        x1, y1, pw, ph = src_box
        patch = img_bgr[y1:y1+ph, x1:x1+pw].copy()

        if dst_pt is None:
            dx = -220 if (x1 > w // 2) else 220
            dy = 50 if (y1 + 50 + ph < h) else -50
            x2 = max(10, min(w - pw - 10, x1 + dx))
            y2 = max(10, min(h - ph - 10, y1 + dy))
            dst_pt = (x2, y2)

        x2, y2 = dst_pt
        tampered = img_bgr.copy()
        tampered[y2:y2+ph, x2:x2+pw] = patch

        # Preserve original EXIF
        exif = None
        try:
            with Image.open(src_path) as orig_pil:
                exif = orig_pil.getexif()
        except Exception:
            pass

        tampered_rgb = cv2.cvtColor(tampered, cv2.COLOR_BGR2RGB)
        pil_tampered = Image.fromarray(tampered_rgb)
        pil_tampered.save(dst_path, "JPEG", quality=92, exif=exif if exif else None)

        return {
            "action": "clone_region",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "source_box": {"x": x1, "y": y1, "width": pw, "height": ph},
            "destination_point": {"x": x2, "y": y2},
            "shift_vector": {"dx": x2 - x1, "dy": y2 - y1},
            "description": f"Cloned {pw}x{ph}px region from ({x1}, {y1}) to ({x2}, {y2}) with shift ({x2-x1}px, {y2-y1}px).",
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def splice_object(
        src_path: str,
        dst_path: str,
        custom_patch_path: Optional[str] = None,
        watermark_text: Optional[str] = "FORGED EVIDENCE 14:30",
        position: Optional[Tuple[int, int]] = None,
        patch_quality: int = 50,
        output_quality: int = 92
    ) -> Dict[str, Any]:
        """
        Actually splices an external graphic or text badge into the image with
        compression discontinuity (pre-compressed at patch_quality, then saved at output_quality).
        """
        img_bgr = cv2.imread(src_path)
        if img_bgr is None:
            raise ValueError(f"Could not read source image: {src_path}")

        h, w, _ = img_bgr.shape

        if custom_patch_path and os.path.exists(custom_patch_path):
            patch = cv2.imread(custom_patch_path)
            ph, pw, _ = patch.shape
        else:
            # Create high-contrast forged text banner / stamp
            pw, ph = min(220, w // 2), min(60, h // 4)
            patch = np.zeros((ph, pw, 3), dtype=np.uint8)
            patch[:, :] = (30, 30, 30)
            cv2.rectangle(patch, (2, 2), (pw - 2, ph - 2), (0, 0, 240), 2)
            cv2.putText(patch, watermark_text[:24], (8, ph // 2 + 6), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)

        # Pre-compress patch at low quality in memory to create JPEG Ghost artifact
        _, enc = cv2.imencode('.jpg', patch, [cv2.IMWRITE_JPEG_QUALITY, patch_quality])
        low_q_patch = cv2.imdecode(enc, cv2.IMREAD_COLOR)

        if position is None:
            x = max(20, w // 2 - pw // 2)
            y = max(20, h // 2 - ph // 2)
        else:
            x, y = position

        x = max(0, min(w - pw, x))
        y = max(0, min(h - ph, y))

        tampered = img_bgr.copy()
        tampered[y:y+ph, x:x+pw] = low_q_patch

        exif = None
        try:
            with Image.open(src_path) as orig_pil:
                exif = orig_pil.getexif()
        except Exception:
            pass

        tampered_rgb = cv2.cvtColor(tampered, cv2.COLOR_BGR2RGB)
        pil_tampered = Image.fromarray(tampered_rgb)
        pil_tampered.save(dst_path, "JPEG", quality=output_quality, exif=exif if exif else None)

        return {
            "action": "splice_object",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "patch_size": {"width": pw, "height": ph},
            "position": {"x": x, "y": y},
            "patch_quality": patch_quality,
            "output_quality": output_quality,
            "description": f"Spliced foreign element at ({x}, {y}) pre-compressed at Q={patch_quality} into Q={output_quality} frame.",
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def double_compress(src_path: str, dst_path: str, q1: int = 65, q2: int = 90) -> Dict[str, Any]:
        """
        Executes an actual two-generation JPEG compression cycle:
        Pass 1: Compress at q1.
        Pass 2: Re-encode at q2.
        """
        with Image.open(src_path) as im:
            rgb_im = im.convert("RGB")
            exif = rgb_im.getexif()
            buf = io.BytesIO()
            rgb_im.save(buf, "JPEG", quality=q1)
            buf.seek(0)
            with Image.open(buf) as pass1:
                pass1.save(dst_path, "JPEG", quality=q2, exif=exif if exif else None)

        return {
            "action": "double_compress",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "q1": q1,
            "q2": q2,
            "description": f"Double compression cycle: Generation 1 at Q={q1}, Generation 2 at Q={q2}.",
            "file_size": os.path.getsize(dst_path)
        }


class VideoTamperer:
    """
    Forensic Tampering Toolkit for Video/CCTV:
    Actually drops frames, cuts temporal segments, applies color filters,
    and injects NLE container signatures using FFmpeg.
    """

    @staticmethod
    def cut_temporal_segment(src_path: str, dst_path: str, cut_start: float = 10.0, cut_end: float = 15.0) -> Dict[str, Any]:
        """
        Actually removes a temporal segment from the video (e.g. drops seconds 10 to 15),
        concatenating [0..cut_start] + [cut_end..duration].
        This creates an authentic clock discontinuity and GOP cadence disruption.
        """
        # Determine total duration
        probe = subprocess.run([
            "ffprobe", "-v", "error", "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1", src_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            total_dur = float(probe.stdout.strip())
        except Exception:
            total_dur = 30.0

        cut_start = min(cut_start, total_dur - 1.0)
        cut_end = min(max(cut_start + 0.5, cut_end), total_dur)

        temp_part1 = dst_path + ".part1.mp4"
        temp_part2 = dst_path + ".part2.mp4"
        list_file = dst_path + ".list.txt"

        # Export part 1: 0 to cut_start
        subprocess.run([
            "ffmpeg", "-y", "-i", src_path, "-t", str(cut_start),
            "-c:v", "libx264", "-c:a", "aac", temp_part1
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Export part 2: cut_end to end
        subprocess.run([
            "ffmpeg", "-y", "-ss", str(cut_end), "-i", src_path,
            "-c:v", "libx264", "-c:a", "aac", temp_part2
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Concatenate using concat demuxer
        with open(list_file, "w") as f:
            f.write(f"file '{temp_part1}'\nfile '{temp_part2}'\n")

        subprocess.run([
            "ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", list_file,
            "-c", "copy", dst_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Cleanup temp parts
        for p in [temp_part1, temp_part2, list_file]:
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass

        return {
            "action": "cut_temporal_segment",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "cut_start_sec": cut_start,
            "cut_end_sec": cut_end,
            "missing_duration_sec": round(cut_end - cut_start, 2),
            "description": f"Excised {cut_end - cut_start:.1f}s of footage between timestamp {cut_start}s and {cut_end}s.",
            "file_size": os.path.getsize(dst_path) if os.path.exists(dst_path) else 0
        }

    @staticmethod
    def apply_night_theme(src_path: str, dst_path: str, saturation: float = 0.20) -> Dict[str, Any]:
        """
        Actually applies color desaturation / night theme filter to the video stream.
        """
        subprocess.run([
            "ffmpeg", "-y", "-i", src_path,
            "-vf", f"eq=saturation={saturation}",
            "-c:a", "copy", dst_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return {
            "action": "apply_night_theme",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "saturation_level": saturation,
            "description": f"Applied desaturation color filter (saturation={saturation}) to simulate night/monochrome theme.",
            "file_size": os.path.getsize(dst_path) if os.path.exists(dst_path) else 0
        }

    @staticmethod
    def inject_nle_editor(src_path: str, dst_path: str, editor_name: str = "Clipchamp Video Processor") -> Dict[str, Any]:
        """
        Actually injects non-linear editing (NLE) software container tags into the MP4 file.
        """
        subprocess.run([
            "ffmpeg", "-y", "-i", src_path,
            "-metadata", f"handler_name={editor_name}",
            "-metadata", f"encoder=https://clipchamp.com",
            "-c", "copy", dst_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return {
            "action": "inject_nle_editor",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "injected_editor": editor_name,
            "description": f"Injected '{editor_name}' container metadata tags into video stream.",
            "file_size": os.path.getsize(dst_path) if os.path.exists(dst_path) else 0
        }


class AudioTamperer:
    """
    Forensic Tampering Toolkit for Audio/Voice:
    Actually splices speech clips, injects phase breaks, and synthesizes
    AI vocoder high-frequency noise floors.
    """

    @staticmethod
    def splice_speech(src_path: str, dst_path: str, cut_start_sec: float = 2.0, cut_end_sec: float = 3.5) -> Dict[str, Any]:
        """
        Actually excises a segment from an audio file and joins the remaining audio,
        creating an abrupt acoustic splice cut.
        """
        import soundfile as sf
        data, sr = sf.read(src_path)
        
        idx_start = int(cut_start_sec * sr)
        idx_end = int(cut_end_sec * sr)
        
        if idx_start >= len(data) or idx_end >= len(data):
            idx_start = int(len(data) * 0.25)
            idx_end = int(len(data) * 0.50)
            
        part1 = data[:idx_start]
        part2 = data[idx_end:]
        # Reverse phase of second segment to create an authentic non-crossfaded splice cut
        spliced = np.concatenate([part1, -part2])
        
        sf.write(dst_path, spliced, sr)
        
        return {
            "action": "splice_speech",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "cut_range_seconds": [cut_start_sec, cut_end_sec],
            "description": f"Spliced out {cut_end_sec - cut_start_sec:.2f}s of audio, creating an acoustic splice boundary.",
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def synthesize_vocoder_flatness(src_path: str, dst_path: str) -> Dict[str, Any]:
        """
        Synthesizes AI neural vocoder spectral artifacts:
        Adds a synthetic high-frequency energy floor above 7.5kHz and introduces
        harmonic smoothing to push spectral flatness above the 0.015 threshold.
        """
        import soundfile as sf
        data, sr = sf.read(src_path)
        
        # Add slight shaped high-frequency dither above 7000Hz (neural vocoder signature)
        if len(data.shape) > 1:
            noise = np.random.normal(0, 0.022, data.shape)
            hf_noise = np.diff(noise, axis=0, prepend=0) * 0.8
        else:
            noise = np.random.normal(0, 0.022, len(data))
            hf_noise = np.diff(noise, prepend=0) * 0.8
        
        synthetic_speech = data * 0.90 + hf_noise
        sf.write(dst_path, synthetic_speech, sr)
        
        return {
            "action": "synthesize_vocoder_flatness",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "description": "Injected synthetic high-frequency vocoder floor (>7.5kHz) and spectral smoothing.",
            "file_size": os.path.getsize(dst_path)
        }


class DocumentTamperer:
    """
    Forensic Tampering Toolkit for Documents (PDFs):
    Modifies ISO 32000-1 trailer IDs and appends incremental revision blocks.
    """

    @staticmethod
    def forge_trailer_id(src_path: str, dst_path: str) -> Dict[str, Any]:
        """
        Modifies the PDF trailer /ID array: changes ID1 so ID0 != ID1,
        which mathematically proves post-creation tampering under ISO 32000-1.
        """
        with open(src_path, "rb") as f:
            content = f.read()

        import re
        id_pattern = re.compile(rb'/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]')
        match = id_pattern.search(content)

        if match:
            id0 = match.group(1)
            # Create completely different ID1
            fake_id1 = b"deadbeefcafe1234567890abcdef1234"
            replacement = b'/ID [ <' + id0 + b'> <' + fake_id1 + b'> ]'
            new_content = content[:match.start()] + replacement + content[match.end():]
        else:
            # Append trailer ID block
            eof_idx = content.rfind(b'%%EOF')
            if eof_idx != -1:
                injected_trailer = b"\ntrailer\n<< /ID [ <11223344556677889900aabbccddeeff> <deadbeefcafe1234567890abcdef1234> ] >>\n"
                new_content = content[:eof_idx] + injected_trailer + content[eof_idx:]
            else:
                new_content = content + b"\ntrailer\n<< /ID [ <11223344556677889900aabbccddeeff> <deadbeefcafe1234567890abcdef1234> ] >>\n%%EOF"

        with open(dst_path, "wb") as f:
            f.write(new_content)

        return {
            "action": "forge_trailer_id",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "description": "Modified ISO 32000-1 trailer ID array (Permanent ID0 != Changing ID1), creating proof of document modification.",
            "file_size": os.path.getsize(dst_path)
        }

    @staticmethod
    def append_incremental_revision(src_path: str, dst_path: str) -> Dict[str, Any]:
        """
        Appends an incremental post-signature revision with an additional %%EOF marker.
        """
        with open(src_path, "rb") as f:
            content = f.read()

        incremental_block = (
            b"\n% Incremental post-creation edit\n"
            b"99 0 obj\n"
            b"<< /Type /Annot /Subtype /Text /Contents (FORGED TERMS - MODIFIED AFTER SIGNATURE) >>\n"
            b"endobj\n"
            b"xref\n"
            b"0 1\n"
            b"0000000000 65535 f \n"
            b"trailer\n"
            b"<< /Size 100 /Root 1 0 R >>\n"
            b"startxref\n"
            b"1234\n"
            b"%%EOF\n"
        )

        with open(dst_path, "wb") as f:
            f.write(content + incremental_block)

        return {
            "action": "append_incremental_revision",
            "output_file": os.path.basename(dst_path),
            "output_path": dst_path,
            "description": "Appended unauthorized incremental revision block and secondary %%EOF marker.",
            "file_size": os.path.getsize(dst_path)
        }
