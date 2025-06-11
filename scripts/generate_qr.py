# scripts/generate_qr.py
import qrcode, os

ids = [f"MAT-{i:03d}" for i in range(1, 21)]
out = "../frontend/qr_codes"
os.makedirs(out, exist_ok=True)

for mat_id in ids:
    img = qrcode.make(mat_id)
    img.save(f"{out}/{mat_id}.png")
