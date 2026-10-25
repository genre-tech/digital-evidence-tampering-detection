import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.engine.magic_validator import detect_file_signature

def test_mismatched_extensions():
    dataset_dir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "dataset",
        "PS-05.Digital evidence tampering detection system",
        "Mismatched extension"
    )
    assert os.path.exists(dataset_dir), f"Dataset directory missing: {dataset_dir}"

    expected_results = {
        "Audio.mp3": ("EMPTY", True),
        "data.xls": ("MP4", True),
        "Doc.pdf": ("JPEG", True),
        "Image.jpg": ("ZIP", True),
        "Video.mp4": ("ZIP", True),
    }

    print("\n--- Testing Mismatched Extension Detection ---")
    for fname, (expected_type, expected_mismatch) in expected_results.items():
        fpath = os.path.join(dataset_dir, fname)
        assert os.path.exists(fpath), f"File missing: {fpath}"
        res = detect_file_signature(fpath)
        print(f"[{fname}] -> Detected: {res['detected_type']} | Mismatch: {res['is_mismatch']} | Reason: {res['reason']}")
        assert res["detected_type"] == expected_type, f"Expected {expected_type}, got {res['detected_type']} for {fname}"
        assert res["is_mismatch"] == expected_mismatch, f"Expected mismatch={expected_mismatch} for {fname}"

    print("All mismatched extension tests passed 100%!")

if __name__ == "__main__":
    test_mismatched_extensions()
