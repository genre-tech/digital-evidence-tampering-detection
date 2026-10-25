# AegisForensics (PS-05)
### Digital Evidence Authenticity & Multi-Modal Tampering Verification Engine
**Compliant with ISO/IEC 27037 & BSA Section 63 Digital Forensics Standards**

[![Forensic Accuracy](https://img.shields.io/badge/Forensic%20Accuracy-100.0%25-brightgreen.svg)](#benchmark-verification)
[![Adversarial Catch Rate](https://img.shields.io/badge/Adversarial%20Catch%20Rate-100.0%25-brightgreen.svg)](#adversarial-stress-testing)
[![Standard](https://img.shields.io/badge/Standard-ISO%2FIEC%2027037-blue.svg)](#court-admissibility)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](#quickstart)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%2B%20Vite-61dafb.svg)](#web-dashboard)

AegisForensics is a multi-modal digital evidence examination and adversarial tampering verification platform developed for Problem Statement **PS-05**. It delivers non-destructive evidentiary acquisition, automated multi-layered forensic auditing, physical file tampering engines for adversarial testing, and 1-click court-admissible PDF reports.

---

## 🏛️ Key Capabilities & Multi-Modal Forensic Engines

### 1. Image Forensics
- **Error Level Analysis (ELA)**: Resaves at 90% quality and computes localized compression residuals. Employs both scaled residual edge inspection and a thermal heatmap overlay (`cv2.COLORMAP_JET` at 60% alpha) to reveal spliced foreign patches.
- **Copy-Move Forgery Detection (CMFD)**: Extracts ORB/SIFT descriptors, cross-checks $k$-NN matches, and groups spatial translation shift vectors $(\Delta x, \Delta y)$ within a Euclidean clustering space. Filters out collinear text fonts using 2D spatial variance thresholds ($\sigma_x \ge 8\text{px}, \sigma_y \ge 8\text{px}$) and renders arrowed vector lines directly onto the evidence image.
- **Discrete Quantization Table (DQT) Profile Matching**: Extracts quantization tables from JPEG DQT markers, computes Mean Squared Error (MSE) against standard camera profiles (Canon, Nikon, Sony, Apple, Samsung) vs software encoders (libjpeg/IJG, Photoshop, GIMP, Canva, WhatsApp, Chrome/Skia), and flags software re-compression.
- **Benford's Law (AC DCT Distribution)**: Analyzes first-digit distribution across 63 AC coefficients in $8 \times 8$ block DCT space. Verifies monotonic decay against $\log_{10}(1 + 1/d)$ ($p < 0.05$ Pearson correlation and $\chi^2$ divergence).
- **Anti-Forensic Metadata Deletion Audit**: Conclusively flags sanitization fingerprints, including the Windows Shell Property Handler signature (zeroed $0.0\text{ DPI}$ with stripped acquisition timestamps and an 86-byte skeleton APP1 header).

### 2. CCTV Video Forensics
- **Burned-In Clock OCR**: Crops corner regions, applies 2x super-resolution upscaling, CLAHE contrast equalization, and EasyOCR digit parsing to detect missing temporal segments (e.g., missing seconds 10–15).
- **Container Metadata & NLE Signature Detection**: Parses MP4 atom trees (`moov`, `trak`, `udta`) for editing tags (`Lavf`, Clipchamp, Adobe Premiere, FFmpeg).
- **Temporal Splicing & Color Grade Filtering**: Detects abrupt inter-frame histogram divergence and monochrome/night-theme desaturation ($S_{\text{mean}} < 28.0$).

### 3. Voice & Audio Deepfake Forensics
- **Neural Vocoder Detection**: Analyzes STFT spectral flatness and high-frequency persistence ($>7.5\text{ kHz}$). Flags diffusion/GAN vocoders (HiFi-GAN, WaveGlow, Tortoise-TTS) whose acoustic noise floor diverges from natural human vocal resonance ($>0.007$ flatness vs $<0.003$ organic speech).
- **Time-Domain & Spectral Splice Auditing**: Pinpoints abrupt phase step discontinuities ($z > 18.0$) and spectral flux jumps at un-crossfaded speech cut points.
- **Audacity-Style Spectrogram Generation**: Generates calibrated logarithmic power spectrograms pinpointing splice frequencies.

### 4. Document & Magic Byte Validation
- **Cryptographic File Signature Matching**: Compares binary header magic bytes against declared file extensions (detects ZIP archives masked as JPG/MP4, MP4 videos masked as XLS, JPEG images masked as PDF, and empty 0-byte corruptions).
- **ISO 32000-1 PDF Tampering Audit**: Compares permanent trailer ID ($ID_0$) against changing trailer ID ($ID_1$). Flags unauthorized post-signature incremental updates and duplicate `%%EOF` markers.

---

## 🛠️ Physical Multi-Modal Tamper Toolkit (`tamper_cli.py`)

Rather than synthetic simulation, AegisForensics features a physical byte-level tampering engine that writes actual modified artifacts to disk.

```powershell
# List all tampering vectors
python tamper_cli.py list

# Image Tampering
python tamper_cli.py image --action strip_metadata -i baseline.jpg -o tampered_stripped.jpg
python tamper_cli.py image --action forge_metadata -i baseline.jpg -o tampered_ps.jpg --software "Adobe Photoshop 2026"
python tamper_cli.py image --action clone_region -i baseline.jpg -o tampered_cloned.jpg
python tamper_cli.py image --action splice_object -i baseline.jpg -o tampered_spliced.jpg
python tamper_cli.py image --action double_compress -i baseline.jpg -o tampered_q65_q90.jpg

# CCTV Video Tampering
python tamper_cli.py video --action cut_segment -i cctv.mp4 -o tampered_cut.mp4 --start 5.0 --end 10.0
python tamper_cli.py video --action night_theme -i cctv.mp4 -o tampered_night.mp4 --saturation 0.20
python tamper_cli.py video --action inject_nle -i cctv.mp4 -o tampered_clipchamp.mp4

# Audio Tampering
python tamper_cli.py audio --action splice_speech -i human_voice.wav -o tampered_splice.wav --start 1.0 --end 2.5
python tamper_cli.py audio --action synthesize_vocoder -i human_voice.wav -o tampered_ai_voice.wav

# PDF Document Tampering
python tamper_cli.py pdf --action forge_trailer -i contract.pdf -o tampered_trailer.pdf
python tamper_cli.py pdf --action append_revision -i contract.pdf -o tampered_revision.pdf

# Direct Forensic Examination & Adversarial Verification
python tamper_cli.py audit --file tampered_cloned.jpg
python tamper_cli.py evaluate --baseline baseline.jpg --tampered tampered_cloned.jpg
```

---

## 📊 Verification & Benchmark Performance

### Official PS-05 Benchmark Dataset (16 / 16 Passed — 100.0%)
```powershell
python run_benchmark.py
```
- **Category 1 (File Signature Mismatch)**: 5 / 5 Passed (100%)
- **Category 2 (Audio & Voice Deepfake)**: 6 / 6 Passed (100% — AI voice vs authentic real human speech)
- **Category 3 (Image Metadata & ELA)**: 3 / 3 Passed (100%)
- **Category 4 (CCTV Video Integrity)**: 2 / 2 Passed (100% — Clipped 10–15s and night theme filter)

### Adversarial Multi-Modal Round-Trip Suite (11 / 11 Caught — 100.0%)
```powershell
python backend/tests/adversarial_evaluation_suite.py
```
1. Image: Anti-Forensic Metadata Deletion (0.0 DPI Purge) ➔ **CAUGHT (65% Risk)**
2. Image: Metadata Provenance Forgery & Photoshop Injection ➔ **CAUGHT (100% Risk)**
3. Image: Coherent Copy-Move Object Cloning (CMFD) ➔ **CAUGHT (75% Risk)**
4. Image: Foreign Graphic Splicing & ELA Thermal Ghosting ➔ **CAUGHT (100% Risk)**
5. Image: Multi-Generation Double Compression Cycle ➔ **CAUGHT (Benford Anomaly)**
6. Audio: Acoustic Speech Phase Cut & Splicing ➔ **CAUGHT (30% Risk)**
7. Audio: AI Neural Vocoder Deepfake Floor Injection ➔ **CAUGHT (75% Risk)**
8. Document: ISO 32000-1 Trailer ID Tampering ➔ **CAUGHT (45% Risk)**
9. Document: Post-Signature Incremental Revision Block ➔ **CAUGHT (35% Risk)**
10. Video: Night Theme / Monochrome Desaturation Filter ➔ **CAUGHT (100% Risk)**
11. Video: Container Metadata NLE Processor Tag Injection ➔ **CAUGHT (80% Risk)**

---

## 🚀 Quickstart Guide

### 1. Installation
Clone the repository and install dependencies:
```powershell
git clone https://github.com/<your-account>/digital-evidence-tampering-detection.git
cd digital-evidence-tampering-detection
pip install -r requirements.txt
```

*(Optional) Ensure FFmpeg is installed on your system PATH for video/audio temporal splicing.*

### 2. Launch Forensic Web Dashboard
```powershell
python start_server.py
```
Open **`http://127.0.0.1:8000`** in your browser:
- **Evidence Analysis**: Upload CCTV videos, images, audio clips, or documents.
- **PS-05 Benchmark Suite**: 1-click execution across the 16 dataset ground-truth cases.
- **Tamper & Debug Studio**: Interactively select baselines, trigger physical tampering, download artifacts, and review side-by-side verification scorecards.

### 3. Automated Test Execution
```powershell
# Run the dataset benchmark
python run_benchmark.py

# Run adversarial evaluation
python backend/tests/adversarial_evaluation_suite.py

# Run unit tests
pytest backend/tests
```

---

## ⚖️ Court-Admissible Forensic Reports
Every analysis produces an ISO/IEC 27037 & BSA Section 63 compliant digital forensic PDF:
- Non-destructive acquisition with SHA-256 and MD5 cryptographic hashes.
- Mathematical metrics: ELA peak anomaly ratios, noise variance, CMFD vector counts, spectral flatness, and DQT MSE.
- High-resolution visual proof panels (Thermal ELA overlays, CMFD clone vectors, Audacity spectrograms).
- Official Forensic Examiner sign-off and digital seal.

---

## 📄 License & Compliance
This software is built for forensic investigation, academic research, and lawful evidential integrity verification under ISO/IEC 27037 standards.
