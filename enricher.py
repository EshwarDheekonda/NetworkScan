import json
import requests
import time
import re

with open("cred.json","r") as file:
    GROQ_API_KEY = json.load(file)["GROQ_API_KEY"]
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"

def extract_json_block(text):
    # Extract JSON block from Markdown-style response
    match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    # Fallback: try to find any JSON-looking block
    match = re.search(r"(\{.*?\})", text, re.DOTALL)
    return match.group(1) if match else None

def enrich_article(summary):
    prompt = f"""
You are a cybersecurity assistant. Given the following threat article summary, extract actionable insights relevant to preventing attacks. Include:

- Attack vectors or techniques mentioned
- Defensive recommendations
- Relevant MITRE ATT&CK tactics
- Relevant devices (choose from: email, network, endpoint, cloud)

Summary:
\"\"\"
{summary}
\"\"\"

Respond in structured JSON with fields:
"attack_vectors", "defensive_measures", "mitre_tactics", "relevant_devices"
Don't add anything that would cause a JSONDecodeError to be triggered
"""

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3
    }

    response = requests.post(GROQ_ENDPOINT, headers=headers, json=payload)
    result = response.json()
    content = result["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        try:
            return json.loads(extract_json_block(content))
        except json.JSONDecodeError:
            print("⚠️ Could not parse response as JSON:")
            print(content)
            return {}

# Load threat DB
with open("threat_db.json") as f:
    articles = json.load(f)

# Enrich each article
for article in articles:
    if all(k not in article for k in ["attack_vectors", "defensive_measures", "mitre_tactics", "relevant_devices"]):
        print(f"🔍 Enriching: {article['title']}")
        insights = enrich_article(article["summary"])
        article.update(insights)
        time.sleep(1.5)  # Respectful pacing

# Save enriched DB
with open("threat_db.json", "w") as f:
    json.dump(articles, f, indent=2)

print(f"\n✅ Enriched {len(articles)} articles with actionable insights.")

