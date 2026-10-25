import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.engine.audio_forensics import analyze_voice_authenticity

def test_audio_forensics():
    vdir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "dataset",
        "PS-05.Digital evidence tampering detection system",
        "Voice data"
    )
    assert os.path.exists(vdir), f"Directory missing: {vdir}"

    # Ground truth: Clips 1-5 are AI voice generated; Clip 6 is real.
    ground_truth = {
        "AMIT voice 1.mp3": True,
        "Female Voice 2.mp3": True,
        "Apk voice 3.mp3": True,
        "Murder voice 4.mp3": True,
        "Customercare voice 5.mp3": True,
        "Cyber voice 6 .wav": False,
    }

    print("\n=== Testing Audio / Voice Tampering & AI Voice Detection ===")
    all_matched = True

    for fname, should_be_ai in ground_truth.items():
        fpath = os.path.join(vdir, fname)
        assert os.path.exists(fpath), f"File missing: {fpath}"
        
        res = analyze_voice_authenticity(fpath)
        is_ai = res["is_ai_generated"]
        expected_label = "AI-GENERATED" if should_be_ai else "REAL/AUTHENTIC"
        detected_label = "AI-GENERATED" if is_ai else "REAL/AUTHENTIC"
        
        status = "MATCH" if (is_ai == should_be_ai) else "MISMATCH"
        if is_ai != should_be_ai:
            all_matched = False

        print(f"[{status}] {fname:<25} | Expected: {expected_label:<14} | Got: {detected_label:<14} | Score: {res['authenticity_confidence']}%")
        print(f"       Flatness: {res['features']['spectral_flatness']:.6f} | HighFreqRatio: {res['features']['high_freq_ratio']:.4f}")

    assert all_matched, "Not all voice clips matched the ground truth!"
    print("\n100% of audio clips correctly classified against ground truth!")

if __name__ == "__main__":
    test_audio_forensics()
