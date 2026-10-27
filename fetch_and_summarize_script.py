import os
import json
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime

# ==========================================
# Configuration & Constants
# ==========================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OUTPUT_FILE = "security_news_data.json"

# List of RSS / JSON Feeds to monitor
FEEDS = [
    {
        "name": "JVN (Japan Vulnerability Notes)",
        "type": "rss",
        "url": "https://jvndb.jvn.jp/ja/rss/jvndb.rdf"
    },
    {
        "name": "CISA KEV (Known Exploited Vulnerabilities)",
        "type": "cisa_json",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    },
    {
        "name": "PHP Security Advisories",
        "type": "rss",
        "url": "https://www.php.net/news.rss"
    }
]

# ==========================================
# Helper Functions
# ==========================================

def fetch_rss(url):
    """Fetch and parse standard RSS/RDF feeds."""
    items = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            xml_data = response.read()
            root = ET.fromstring(xml_data)
            
            # Simple RSS / RDF parser
            for elem in root.iter():
                if elem.tag.endswith('item'):
                    title = elem.find('{*}title')
                    link = elem.find('{*}link')
                    description = elem.find('{*}description')
                    pub_date = elem.find('{*}date') or elem.find('{*}pubDate')
                    
                    items.append({
                        "title": title.text if title is not None else "No Title",
                        "url": link.text if link is not None else "",
                        "description": description.text if description is not None else "",
                        "date": pub_date.text if pub_date is not None else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
    except Exception as e:
        print(f"[Error] Failed to fetch RSS from {url}: {e}")
    return items[:5] # Process top 5 recent entries per feed

def fetch_cisa_json(url):
    """Fetch CISA KEV JSON catalog."""
    items = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            vulns = data.get("vulnerabilities", [])
            for v in vulns[:5]:
                items.append({
                    "title": f"CISA KEV: {v.get('vulnerabilityName')} ({v.get('cveID')})",
                    "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                    "description": f"{v.get('shortDescription')} Remediation Note: {v.get('requiredAction')}",
                    "date": v.get('dateAdded', datetime.now().strftime('%Y-%m-%d'))
                })
    except Exception as e:
        print(f"[Error] Failed to fetch CISA KEV: {e}")
    return items

def analyze_with_gemini(raw_item, source_name):
    """Call Gemini API (gemini-3-flash-preview) to format and extract remediation actions."""
    if not GEMINI_API_KEY:
        print("[Warning] GEMINI_API_KEY is not set. Returning basic structured item.")
        return {
            "original_title": raw_item["title"],
            "url": raw_item["url"],
            "source": source_name,
            "published": raw_item["date"],
            "severity": "Medium",
            "affected_tech": ["Web Server", "CMS"],
            "tags": ["Security", "Patch"],
            "threat_overview": raw_item["description"][:150] + "...",
            "user_actions": ["管理画面からシステムやプラグインの更新を確認してください。"]
        }

    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key={GEMINI_API_KEY}"
    
    system_prompt = (
        "You are a senior cybersecurity expert. Analyze the given vulnerability information and return a JSON object with strictly these keys: "
        "'severity' (one of: Critical, High, Medium, Low), "
        "'affected_tech' (list of max 4 tech/software strings e.g., ['PHP 8.3', 'WordPress']), "
        "'tags' (list of 3 short relevant Japanese tags), "
        "'threat_overview' (concise 2-sentence summary in Japanese focusing on risk), "
        "'user_actions' (list of 2-3 specific, actionable Japanese emergency steps for web site admins/shared hosting users)."
    )

    user_query = f"Title: {raw_item['title']}\nDescription: {raw_item['description']}\nSource: {source_name}"

    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {
            "responseMimeType": "application/json"
        }
    }

    try:
        req = urllib.request.Request(
            api_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=15) as res:
            res_data = json.loads(res.read().decode('utf-8'))
            json_text = res_data['candidates'][0]['content']['parts'][0]['text']
            parsed = json.loads(json_text)

            return {
                "original_title": raw_item["title"],
                "url": raw_item["url"],
                "source": source_name,
                "published": raw_item["date"],
                "severity": parsed.get("severity", "Medium"),
                "affected_tech": parsed.get("affected_tech", ["Web"]),
                "tags": parsed.get("tags", ["脆弱性"]),
                "threat_overview": parsed.get("threat_overview", raw_item["description"]),
                "user_actions": parsed.get("user_actions", ["最新バージョンへのアップデートを行ってください。"])
            }
    except Exception as e:
        print(f"[Error] Gemini API failed for {raw_item['title']}: {e}")
        return {
            "original_title": raw_item["title"],
            "url": raw_item["url"],
            "source": source_name,
            "published": raw_item["date"],
            "severity": "Medium",
            "affected_tech": ["Web"],
            "tags": ["Security"],
            "threat_overview": raw_item["description"][:150],
            "user_actions": ["提供元アナウンスを確認し更新を実行してください。"]
        }

# ==========================================
# Main Workflow
# ==========================================

def main():
    print("Starting Security Feed Fetching...")
    all_raw_items = []

    for feed in FEEDS:
        print(f"Fetching: {feed['name']}...")
        if feed['type'] == 'rss':
            items = fetch_rss(feed['url'])
        elif feed['type'] == 'cisa_json':
            items = fetch_cisa_json(feed['url'])
        else:
            items = []

        for item in items:
            all_raw_items.append((item, feed['name']))

    print(f"Total raw feeds collected: {len(all_raw_items)}")
    
    # Process and summarize top entries
    processed_news = []
    for item, source_name in all_raw_items[:12]:
        print(f"Analyzing with Gemini: {item['title'][:30]}...")
        result = analyze_with_gemini(item, source_name)
        processed_news.append(result)

    # Save to JSON
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(processed_news, f, ensure_ascii=False, indent=2)

    print(f"Successfully generated {OUTPUT_FILE} with {len(processed_news)} records.")

if __name__ == "__main__":
    main()