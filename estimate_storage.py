import os, json
from datetime import datetime
from google.cloud import firestore

PROJECT_ID = (os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
db = firestore.Client(project=PROJECT_ID) if PROJECT_ID else firestore.Client()
coll = db.collection("articles")

total_bytes = 0
count = 0

for doc in coll.stream():
    d = doc.to_dict() or {}
    # Convert datetimes so we can measure payload size
    for k, v in list(d.items()):
        if hasattr(v, "isoformat"):
            d[k] = v.isoformat()
    total_bytes += len(json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    count += 1

mb = total_bytes / (1024 * 1024)
gb = total_bytes / (1024 * 1024 * 1024)

print(f"Docs: {count}")
print(f"Approx document payload: {mb:.2f} MiB ({gb:.4f} GiB)")
print("Note: Official billed storage is larger (indexes + metadata). Check Firestore → Usage in Cloud Console for the exact number.")
