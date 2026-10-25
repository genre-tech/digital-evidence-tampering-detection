import os
import datetime
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Adds formal legal running footer with page numbers and timestamp."""
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            super(NumberedCanvas, self).showPage()
        super(NumberedCanvas, self).save()

    def draw_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 35, 572, 35)
        
        # Left footer: confidentiality
        self.drawString(40, 24, "CONFIDENTIAL // LAW ENFORCEMENT & JUDICIAL ADMISSIBILITY ONLY")
        # Right footer: page count
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 24, page_str)
        self.restoreState()

def generate_court_admissible_pdf(report_data: Dict[str, Any], output_pdf_path: str) -> str:
    """
    Generates a formal, court-admissible forensic examination report in PDF format
    with cryptographic chain of custody, detailed technical findings, and examiner signature block.
    """
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()
    
    # Custom forensic styling palette
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2563eb")
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    bold_label = ParagraphStyle(
        'BoldLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a")
    )
    verdict_style = ParagraphStyle(
        'VerdictText',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#b91c1c") if report_data.get("risk_score", 0) >= 50 else colors.HexColor("#15803d")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("FORENSIC DIGITAL EVIDENCE EXAMINATION REPORT", title_style))
    story.append(Paragraph("CHAIN OF CUSTODY & INTEGRITY VERIFICATION // ADMISSIBILITY COMPLIANT", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f172a"), spaceBefore=0, spaceAfter=10))

    # 2. Case & File Metadata Table
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    case_table_data = [
        [
            Paragraph("<b>Case Reference:</b>", bold_label),
            Paragraph(f"EVID-PS05-{int(datetime.datetime.now().timestamp()) % 100000:05d}", body_style),
            Paragraph("<b>Examination Date:</b>", bold_label),
            Paragraph(now_str, body_style)
        ],
        [
            Paragraph("<b>Target File Name:</b>", bold_label),
            Paragraph(report_data.get("filename", "evidence_artifact"), body_style),
            Paragraph("<b>File Size:</b>", bold_label),
            Paragraph(f"{report_data.get('hashes', {}).get('file_size', 0):,} bytes", body_style)
        ],
        [
            Paragraph("<b>Detected MIME:</b>", bold_label),
            Paragraph(report_data.get("magic", {}).get("detected_mime", "application/octet-stream"), body_style),
            Paragraph("<b>Declared Ext:</b>", bold_label),
            Paragraph(f".{report_data.get('magic', {}).get('declared_extension', 'unknown')}", body_style)
        ]
    ]

    t_case = Table(case_table_data, colWidths=[105, 160, 110, 157])
    t_case.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 10))

    # 3. Chain of Custody Cryptographic Block
    story.append(Paragraph("1. Cryptographic Chain of Custody", heading_style))
    hashes = report_data.get("hashes", {})
    crypto_data = [
        [Paragraph("<b>SHA-256 Hash:</b>", bold_label), Paragraph(hashes.get("sha256", "N/A"), ParagraphStyle('Mono', fontName='Courier', fontSize=8, textColor=colors.HexColor("#0f172a")))],
        [Paragraph("<b>MD5 Hash:</b>", bold_label), Paragraph(hashes.get("md5", "N/A"), ParagraphStyle('Mono', fontName='Courier', fontSize=8, textColor=colors.HexColor("#0f172a")))],
        [Paragraph("<b>Shannon Entropy:</b>", bold_label), Paragraph(f"{hashes.get('entropy', 0.0)} / 8.00 (High compressibility/structure)", body_style)],
        [Paragraph("<b>Header Hex Signature:</b>", bold_label), Paragraph(hashes.get("header_hex", "N/A")[:48] + "...", ParagraphStyle('Mono', fontName='Courier', fontSize=8, textColor=colors.HexColor("#475569")))],
    ]
    t_crypto = Table(crypto_data, colWidths=[130, 402])
    t_crypto.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_crypto)
    story.append(Spacer(1, 10))

    # 4. Executive Forensic Verdict & Confidence Score
    story.append(Paragraph("2. Forensic Examination Verdict", heading_style))
    verdict = report_data.get("verdict", "INCONCLUSIVE")
    risk_score = report_data.get("risk_score", 0)
    auth_score = report_data.get("authenticity_confidence", 100 - risk_score)
    
    verdict_box_data = [
        [
            Paragraph(f"FINAL DETERMINATION:<br/><b>{verdict}</b>", verdict_style),
            Paragraph(f"<b>Authenticity Confidence:</b> {auth_score}%<br/><b>Calculated Tampering Risk:</b> {risk_score}%", body_style)
        ]
    ]
    t_verdict = Table(verdict_box_data, colWidths=[332, 200])
    v_bg = colors.HexColor("#fef2f2") if risk_score >= 50 else (colors.HexColor("#fffbeb") if risk_score >= 25 else colors.HexColor("#f0fdf4"))
    v_border = colors.HexColor("#f87171") if risk_score >= 50 else (colors.HexColor("#fde047") if risk_score >= 25 else colors.HexColor("#86efac"))
    t_verdict.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), v_bg),
        ('BOX', (0,0), (-1,-1), 1.5, v_border),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_verdict)
    story.append(Spacer(1, 10))

    # 5. Detected Anomalies & Forensic Findings
    story.append(Paragraph("3. Specific Evidentiary Flags & Irregularities", heading_style))
    flags = report_data.get("forensic_flags", [])
    if not flags:
        story.append(Paragraph("• No significant anomalies, compression gaps, or structural alterations detected.", body_style))
    else:
        for f in flags:
            story.append(Paragraph(f"• <b>[FINDING]</b> {f}", body_style))
            story.append(Spacer(1, 3))
    story.append(Spacer(1, 8))

    # 6. Modality-Specific Details (Image, Video, or Audio)
    modality = report_data.get("modality", "generic")
    if modality == "image" and "metadata_table" in report_data:
        story.append(Paragraph("4. Technical Image Metadata (Metadata details.docx Schema)", heading_style))
        m = report_data["metadata_table"]
        meta_rows = [
            [Paragraph("<b>Field Name</b>", bold_label), Paragraph("<b>Forensic Value</b>", bold_label)],
            [Paragraph("File Name / Type", body_style), Paragraph(f"{m.get('File Name')} ({m.get('File Type')})", body_style)],
            [Paragraph("Resolution", body_style), Paragraph(f"{m.get('Image Width')} x {m.get('Image Height')} pixels", body_style)],
            [Paragraph("Date Time Original", body_style), Paragraph(str(m.get('Date Time Original')), body_style)],
            [Paragraph("Create / Modify Date", body_style), Paragraph(f"Create: {m.get('CreateDate')}<br/>Modify: {m.get('ModifyDate')}", body_style)],
            [Paragraph("GPS Coordinates", body_style), Paragraph(f"Lat: {m.get('GPSLatitude')}, Lon: {m.get('GPSLongitude')}", body_style)],
            [Paragraph("Camera Make / Model", body_style), Paragraph(f"{m.get('Make')} - {m.get('Model')}", body_style)],
            [Paragraph("Software Fingerprint", body_style), Paragraph(str(m.get('Software')), body_style)],
            [Paragraph("Description / Artist", body_style), Paragraph(f"{m.get('Description')} / {m.get('Artist')}", body_style)],
            [Paragraph("DQT Quantization Profile", body_style), Paragraph(str(report_data.get('dqt_analysis', {}).get('quantization_profile', 'N/A')), body_style)],
            [Paragraph("Benford's Law (DCT)", body_style), Paragraph(f"Correlation: {report_data.get('benford_analysis', {}).get('correlation_with_benford', 'N/A')} (Chi2: {report_data.get('benford_analysis', {}).get('chi2_divergence', 'N/A')})", body_style)],
            [Paragraph("Noise Variance Ratio", body_style), Paragraph(f"{report_data.get('noise_analysis', {}).get('variance_ratio', 'N/A')}x (Threshold: 6.0)", body_style)],
            [Paragraph("ELA Compression Peak", body_style), Paragraph(f"Peak Ratio: {report_data.get('ela', {}).get('peak_anomaly_ratio', 'N/A')}x (Max Diff: {report_data.get('ela', {}).get('max_error', 'N/A')})", body_style)],
            [Paragraph("Copy-Move Cloning", body_style), Paragraph(f"{'CONFIRMED TAMPERING (' + str(report_data.get('copy_move', {}).get('clone_cluster_matches', 0)) + ' matched points)' if report_data.get('copy_move', {}).get('copy_move_detected') else 'No coherent clone clusters'}", body_style)],
            [Paragraph("Resampling Periodicity", body_style), Paragraph(f"FFT p-spectrum peak: {report_data.get('resampling_analysis', {}).get('peak_ratio', 'N/A')} ({'Resampled/Scaled' if report_data.get('resampling_analysis', {}).get('resampling_detected') else 'Natural spectrum'})", body_style)],
        ]
        t_meta = Table(meta_rows, colWidths=[150, 382])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_meta)

    elif modality == "video" and "cctv_ocr_analysis" in report_data:
        story.append(Paragraph("4. CCTV Stream & Temporal Integrity Examination", heading_style))
        v_ocr = report_data["cctv_ocr_analysis"]
        v_vis = report_data.get("visual_analysis", {})
        v_stream = report_data.get("stream_analysis", {})
        v_meta = report_data.get("container_metadata", {})
        vid_rows = [
            [Paragraph("<b>Parameter</b>", bold_label), Paragraph("<b>Forensic Value</b>", bold_label)],
            [Paragraph("Playback Stream Duration", body_style), Paragraph(f"{v_vis.get('duration_seconds')}s ({v_vis.get('total_frames')} frames @ {v_vis.get('fps')} FPS)", body_style)],
            [Paragraph("CCTV Burned Clock Clipping", body_style), Paragraph("CONFIRMED TAMPERING (Footage Clipped)" if v_ocr.get("cctv_clipping_detected") else "No clock discontinuity detected", body_style)],
            [Paragraph("GOP Cadence & Regularity", body_style), Paragraph(f"Nominal {v_stream.get('nominal_gop_size')} frames (Std: {v_stream.get('gop_variance')}) - {'IRREGULAR / SPLICED' if v_stream.get('is_gop_irregular') else 'Consistent Hardware GOP'}", body_style)],
            [Paragraph("Container NLE Editor Tag", body_style), Paragraph(str(v_meta.get('editor_name') or 'Direct Stream Capture (No NLE Tag)'), body_style)],
            [Paragraph("Color Filter / Night Theme", body_style), Paragraph("DETECTED (Desaturated/Monochrome)" if v_vis.get("is_night_theme_detected") else "Standard Color Spectrum", body_style)],
            [Paragraph("Stream Packet Dropouts", body_style), Paragraph(str(len(v_stream.get('pts_gaps', []))) + " PTS packet jumps", body_style)],
        ]
        t_vid = Table(vid_rows, colWidths=[170, 362])
        t_vid.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_vid)

    elif modality == "audio":
        story.append(Paragraph("4. Acoustic & Synthetic Voice Spectral Analysis", heading_style))
        feat = report_data.get("features", {})
        aud_rows = [
            [Paragraph("<b>Acoustic Parameter</b>", bold_label), Paragraph("<b>Measurement</b>", bold_label), Paragraph("<b>Baseline Expectation</b>", bold_label)],
            [Paragraph("Voice Classification", body_style), Paragraph(f"<b>{report_data.get('voice_type')}</b>", body_style), Paragraph("Organic Human Vocal Tract", body_style)],
            [Paragraph("Spectral Flatness", body_style), Paragraph(str(feat.get("spectral_flatness", "N/A")), body_style), Paragraph("< 0.005 for natural resonance", body_style)],
            [Paragraph("High-Frequency (>7.5kHz) Ratio", body_style), Paragraph(str(feat.get("high_freq_ratio", "N/A")), body_style), Paragraph("< 0.025 for authentic speech", body_style)],
            [Paragraph("MFCC Variance", body_style), Paragraph(str(feat.get("mfcc_variance", "N/A")), body_style), Paragraph("Natural phonetic variance", body_style)],
            [Paragraph("Splice Discontinuities", body_style), Paragraph(f"{len(report_data.get('splice_events', []))} cuts", body_style), Paragraph("0 abrupt phase breaks", body_style)],
        ]
        t_aud = Table(aud_rows, colWidths=[150, 160, 222])
        t_aud.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_aud)

    elif modality == "document":
        story.append(Paragraph("4. ISO 32000-1 Document Structure & Revision Audit", heading_style))
        meta = report_data.get("metadata", {})
        doc_rows = [
            [Paragraph("<b>Audit Parameter</b>", bold_label), Paragraph("<b>Forensic Finding</b>", bold_label)],
            [Paragraph("ISO 32000-1 Trailer ID Match", body_style), Paragraph("ALTERATION DETECTED (Permanent ID != Changing ID)" if report_data.get("id_mismatch") else "Consistent Creation Identifier", body_style)],
            [Paragraph("Incremental Revision Count", body_style), Paragraph(f"{report_data.get('revision_count', 1)} revision(s) (%%EOF markers)", body_style)],
            [Paragraph("Producer / Editing Tool", body_style), Paragraph(str(meta.get("Producer", "N/A")), body_style)],
            [Paragraph("Creator Application", body_style), Paragraph(str(meta.get("Creator", "N/A")), body_style)],
            [Paragraph("Creation vs Modification Date", body_style), Paragraph(f"Created: {meta.get('CreationDate', 'N/A')}<br/>Modified: {meta.get('ModDate', 'N/A')}", body_style)],
        ]
        t_doc = Table(doc_rows, colWidths=[170, 362])
        t_doc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_doc)

    story.append(Spacer(1, 15))

    # 7. Investigator Legal Certification & Signature Block
    cert_text = (
        "<b>CERTIFICATE OF FORENSIC EXAMINATION:</b><br/>"
        "I hereby certify that this examination was performed using forensically sound, reproducible, and "
        "scientifically accepted methodologies in accordance with ISO/IEC 27037 standards. "
        "The cryptographic hashes and anomalies recorded herein constitute true and verified findings from the unaltered evidentiary source file."
    )
    sig_block = [
        [Paragraph(cert_text, body_style)],
        [Spacer(1, 15)],
        [
            Table([
                [Paragraph("<b>Examined By:</b> Principal Forensic Examiner, Digital Evidence Lab", body_style), Paragraph("<b>Signature:</b> ___________________________", body_style)],
                [Paragraph(f"<b>Date Certified:</b> {now_str[:10]}", body_style), Paragraph("<b>Official Stamp:</b> [SEAL // VERIFIED]", body_style)]
            ], colWidths=[270, 262], style=[('VALIGN', (0,0), (-1,-1), 'MIDDLE')])
        ]
    ]
    t_sig = Table(sig_block, colWidths=[532])
    t_sig.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#94a3b8")),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    
    story.append(KeepTogether(t_sig))

    # Build PDF with dynamic header/footer
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_pdf_path
