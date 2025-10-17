# scripts/ingest.py
import os, time, logging, json
from google.cloud import firestore

def fetch_articles():
    """Dummy data for now — replace later with real feed fetching."""
    return [
        {"title": "Radiant Waves heartbeat", "url": "https://radiant-waves.onrender.com", "ts": int(time.time())}
    ]

def main():
    logging.basicConfig(level=logging.INFO)
    db = firestore.Client(project=os.getenv("GOOGLE_CLOUD_PROJECT"))
    col = db.collection("articles")
    items = fetch_articles()
    for it in items:
        doc_id = str(it["ts"])
        col.document(doc_id).set(it, merge=True)
    print(json.dumps({"ingested": len(items)}))

if __name__ == "__main__":
    main()
