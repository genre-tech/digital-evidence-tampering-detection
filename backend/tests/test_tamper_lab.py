import os
from backend.engine.tamper_lab import (
    simulate_strip_metadata, simulate_forge_metadata,
    simulate_copy_move_cloning, simulate_foreign_splicing,
    simulate_double_compression
)
from backend.engine.image_forensics import full_image_forensic_audit

src = 'output/uploads/02aa7ba8_WIN_20261026_01_34_17_Pro.jpg'
out_dir = 'output/static'

attacks = [
    ('1. Anti-Forensic Metadata Strip', simulate_strip_metadata, 'sim_strip.jpg'),
    ('2. Metadata Forgery (Photoshop tag & date discrepancy)', simulate_forge_metadata, 'sim_forge.jpg'),
    ('3. Copy-Move Region Cloning', simulate_copy_move_cloning, 'sim_copymove.jpg'),
    ('4. Foreign Graphic Splicing & Ghosting', simulate_foreign_splicing, 'sim_splice.jpg'),
    ('5. Double JPEG Compression Cycle', simulate_double_compression, 'sim_double_q.jpg')
]

for title, fn, out_name in attacks:
    dst = os.path.join(out_dir, out_name)
    atk_info = fn(src, dst)
    res = full_image_forensic_audit(dst, out_dir)
    print('========================================')
    print(f"ATTACK: {title}")
    print(f"Verdict: {res['verdict']} | Risk: {res['risk_score']}%")
    print('Flags:')
    for fl in res['forensic_flags']:
        print(f"  • {fl}")
