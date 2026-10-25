import os
from backend.engine.image_forensics import full_image_forensic_audit

test_cases = [
    ('Authentic Laptop Webcam', 'output/uploads/02aa7ba8_WIN_20261026_01_34_17_Pro.jpg'),
    ('Authentic Laptop Webcam 2', 'output/uploads/ed0d8eb8_WIN_20261026_02_31_49_Pro.jpg'),
    ('Authentic WhatsApp Transfer', 'output/uploads/ba077456_WhatsApp Image.jpeg'),
    ('Tampered Cloned Image', 'output/uploads/ea6c2fd3_exp9.png'),
    ('Tampered Screenshot Graphic', 'output/uploads/f0cef109_card.png'),
    ('Official Dataset Image-1', 'dataset/PS-05.Digital evidence tampering detection system/Image data/Image-1 copy.jpg'),
    ('Official Dataset Image-3', 'dataset/PS-05.Digital evidence tampering detection system/Image data/Image-3 copy.png'),
    ('Official Dataset Image-5', 'dataset/PS-05.Digital evidence tampering detection system/Image data/Image-5 copy.png')
]

for label, path in test_cases:
    if os.path.exists(path):
        res = full_image_forensic_audit(path, 'output/static')
        print('========================================')
        print(f"Test: {label} ({os.path.basename(path)})")
        print(f"Verdict: {res['verdict']} | Risk: {res['risk_score']}% | Auth Conf: {res['authenticity_confidence']}%")
        print(f"Copy-Move: {res['copy_move']['copy_move_detected']} (Matches: {res['copy_move']['clone_cluster_matches']})")
        print(f"ELA Suspicious: {res['ela']['is_ela_suspicious']} (Peak: {res['ela']['peak_anomaly_ratio']}x, Max: {res['ela']['max_error']})")
        print(f"Noise Inconsistent: {res['noise_analysis']['noise_inconsistent']} (Ratio: {res['noise_analysis']['variance_ratio']})")
        print(f"Flags ({len(res['forensic_flags'])}): {res['forensic_flags']}")
