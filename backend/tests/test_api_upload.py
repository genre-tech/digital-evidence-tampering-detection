import urllib.request
import json
import os

def test_upload():
    boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
    fpath = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "dataset",
        "PS-05.Digital evidence tampering detection system",
        "Image data",
        "Image-1 copy.jpg"
    )
    with open(fpath, 'rb') as f:
        content = f.read()

    headers_part = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="Image-1 copy.jpg"\r\n'
        f'Content-Type: image/jpeg\r\n\r\n'
    ).encode('utf-8')
    footer_part = f'\r\n--{boundary}--\r\n'.encode('utf-8')
    body = headers_part + content + footer_part

    req = urllib.request.Request(
        'http://127.0.0.1:8000/api/analyze/file',
        data=body,
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
    )

    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode('utf-8'))
        print("Analysis ID:", data["analysis_id"])
        print("Verdict:", data["verdict"])
        print("Risk Score:", data["risk_score"])
        print("Authenticity:", data["authenticity_confidence"])
        print("PDF URL:", data.get("pdf_report_url"))
        print("Forensic Flags:", data.get("forensic_flags"))

        # Verify PDF download
        pdf_url = f"http://127.0.0.1:8000{data['pdf_report_url']}"
        with urllib.request.urlopen(pdf_url) as pdf_resp:
            pdf_bytes = pdf_resp.read()
            print(f"Downloaded generated PDF report: {len(pdf_bytes):,} bytes (Starts with: {pdf_bytes[:4]})")
            assert pdf_bytes.startswith(b'%PDF'), "PDF did not start with %PDF!"

    print("HTTP API file upload & PDF generation verified 100%!")

if __name__ == "__main__":
    test_upload()
