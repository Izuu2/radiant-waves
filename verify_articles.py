from google.cloud import firestore

PROJECT_ID = "radiant-waves"
db = firestore.Client(project=PROJECT_ID)
coll = db.collection("articles")

print("Latest 5 articles:")
for doc in coll.order_by("publishedAt", direction=firestore.Query.DESCENDING).limit(5).stream(): d = doc.to_dict(); print("-", d.get("publishedAt"), "-", d.get("feed"), "-", d.get("title"))

print("If you see rows above, Firestore is populated.")
