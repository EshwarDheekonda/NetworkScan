import feedparser
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

class SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'tolist'):
            return obj.tolist()
        if isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        return super().default(obj)

def generate_tags(text, profile):
    tokens = text.lower()
    tags = []

    for tech in profile["technologies"]:
        if tech.lower() in tokens:
            tags.append(tech)

    for concern in profile["security_concerns"]:
        if concern.lower() in tokens:
            tags.append(concern)

    return tags

# Load tech stack
with open("tech_stack.json") as f:
    profile = json.load(f)

profile_text = "Technologies: " + ", ".join(profile["technologies"]) + \
               ". Concerns: " + ", ".join(profile["security_concerns"])

# Embed profile
model = SentenceTransformer('all-MiniLM-L6-v2')
profile_vec = model.encode(profile_text)

# Load feed endpoints
with open("feed.json") as file:
    endpoints = json.load(file)

import os
from datetime import datetime

# Load existing threat DB if it exists
if os.path.exists("threat_db.json"):
    with open("threat_db.json") as f:
        existing_articles = json.load(f)
else:
    existing_articles = []

# Create a set of existing titles or links for deduplication
existing_keys = {article["title"] for article in existing_articles}

# Append new articles
for ep in endpoints["endpoints"]:
    feed = feedparser.parse(ep)
    if feed.entries:
        for entry in feed.entries[:10]:
            summary = entry.title + " " + entry.summary
            summary_vec = model.encode(summary)
            score = cosine_similarity([profile_vec], [summary_vec])[0][0]

            if score > 0.4 and entry.title not in existing_keys:
                pub_date = entry.get("published", "unknown")
                try:
                    parsed = datetime(*entry.published_parsed[:6])
                    pub_date = parsed.strftime("%Y-%m-%d")
                except:
                    pass

                tags = generate_tags(summary, profile)

                new_article = {
                    "title": entry.title,
                    "link": entry.link,
                    "published": pub_date,
                    "summary": entry.summary,
                    "source": ep,
                    "score": float(round(score, 3)),
                    "tags": tags
                }
                existing_articles.append(new_article)
                existing_keys.add(entry.title)

# Save updated threat DB
with open("threat_db.json", "w") as f:
    json.dump(existing_articles, f, indent=2)

print(f"\n Appended {len(existing_articles)} total articles to threat_db.json")
