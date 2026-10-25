import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.engine.video_forensics import full_video_forensic_audit

def test_video_forensics():
    vdir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "dataset",
        "PS-05.Digital evidence tampering detection system",
        "Video data"
    )
    assert os.path.exists(vdir), f"Directory missing: {vdir}"

    print("\n=== Testing Video 1 (Clipped at 10-15s) ===")
    v1_path = os.path.join(vdir, "Video-1(10-15 -).mp4")
    res1 = full_video_forensic_audit(v1_path)
    print(f"Verdict: {res1['verdict']} (Risk: {res1['risk_score']}%)")
    for f in res1["forensic_flags"]:
        print(f"  [FLAG] {f}")
    assert res1["cctv_ocr_analysis"]["cctv_clipping_detected"] is True, "Failed to detect clipping in Video 1!"
    print("Video 1 clipping accurately verified!")

    print("\n=== Testing Video 3 (Night theme applied) ===")
    v3_path = os.path.join(vdir, "video-3.mp4")
    res3 = full_video_forensic_audit(v3_path)
    print(f"Verdict: {res3['verdict']} (Risk: {res3['risk_score']}%)")
    for f in res3["forensic_flags"]:
        print(f"  [FLAG] {f}")
    assert res3["visual_analysis"]["is_night_theme_detected"] is True, "Failed to detect night theme in Video 3!"
    print("Video 3 night theme accurately verified!")

    print("\n=== Testing Video 4 (Original) ===")
    v4_path = os.path.join(vdir, "video-4.mp4")
    res4 = full_video_forensic_audit(v4_path)
    print(f"Verdict: {res4['verdict']} (Risk: {res4['risk_score']}%)")
    for f in res4["forensic_flags"]:
        print(f"  [FLAG] {f}")
    assert res4["cctv_ocr_analysis"]["cctv_clipping_detected"] is False, "False positive clipping in original Video 4!"
    print("Video 4 original status verified!")

    print("\nAll video forensic tests passed successfully!")

if __name__ == "__main__":
    test_video_forensics()
