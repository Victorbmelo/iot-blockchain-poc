import time
import requests

URL = "http://127.0.0.1:5000/scan"

def measure_one(id_str, location="GateA"):
    payload = {"id": id_str, "location": location}
    start = time.time()
    resp = requests.post(URL, json=payload)
    end = time.time()
    if resp.status_code == 200:
        return (end - start) * 1000  # milliseconds
    else:
        return None

latencies = []
for i in range(1, 11):
    mat_id = f"MAT-{i:03d}"
    ms = measure_one(mat_id)
    print(f"{mat_id}: {ms:.2f} ms")
    latencies.append(ms)

avg = sum(latencies) / len(latencies)
print(f"Avg latency: {avg:.2f} ms")
