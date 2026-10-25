import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.engine.image_forensics import full_image_forensic_audit

def test_image_forensics():
    dataset_img_dir = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "dataset",
        "PS-05.Digital evidence tampering detection system",
        "Image data"
    )
    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "output", "test_images")
    os.makedirs(output_dir, exist_ok=True)

    test_file = os.path.join(dataset_img_dir, "Image-1 copy.jpg")
    assert os.path.exists(test_file), f"Test image missing: {test_file}"

    report = full_image_forensic_audit(test_file, output_dir)
    print("\n--- Image-1 copy.jpg Forensic Report ---")
    print("Metadata Table:")
    for k, v in report["metadata_table"].items():
        if k != "anomalies":
            print(f"  {k:<20}: {v}")
    
    print("\nForensic Flags:")
    for flag in report["forensic_flags"]:
        print(f"  [FLAG] {flag}")

    print(f"\nVerdict: {report['verdict']} (Risk Score: {report['risk_score']}%, Authenticity: {report['authenticity_confidence']}%)")
    assert os.path.exists(report["ela"]["ela_image_path"]), "ELA image was not generated!"
    assert report["metadata_table"]["File Name"] == "Image-1 copy.jpg"
    assert report["metadata_table"]["Make"] == "CCSU"
    print("\nImage forensics test passed successfully!")

if __name__ == "__main__":
    test_image_forensics()
