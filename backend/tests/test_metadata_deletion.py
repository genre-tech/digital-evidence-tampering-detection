import os
from backend.engine.image_forensics import full_image_forensic_audit

files = [
    ('User Stripped File 1 (Windows Properties Cleaned)', 'output/uploads/03a9cc14_WIN_20261026_01_34_17_Pro.jpg'),
    ('User Stripped File 2 (Tags Deleted)', 'output/uploads/cf5ce14f_WIN_20261026_02_31_43_Pro - Copy.jpg'),
    ('Untouched Original Camera File', 'output/uploads/02aa7ba8_WIN_20261026_01_34_17_Pro.jpg')
]

for label, f in files:
    if os.path.exists(f):
        res = full_image_forensic_audit(f, 'output/static')
        print('========================================')
        print(f"{label}: {os.path.basename(f)}")
        print(f"Verdict: {res['verdict']} | Risk Score: {res['risk_score']}%")
        print('Flags:')
        for flag in res['forensic_flags']:
            print(f"  • {flag}")
        print('Metadata Table Sample:')
        for k in ['Date Time Original', 'CreateDate', 'Make', 'Software']:
            print(f"  {k}: {res['metadata_table'].get(k)}")
