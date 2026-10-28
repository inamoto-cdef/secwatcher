import os
import json
import datetime
import feedparser
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# スキーマ定義 (Geminiからの構造化出力用)
class SecurityAnalysis(BaseModel):
    threat_overview: str = Field(description="脅威の概要（100〜150文字程度）")
    severity: str = Field(description="'Critical', 'High', 'Medium', 'Low' のいずれか")
    affected_tech: list[str] = Field(description="影響を受ける技術・ツール (例: PHP, WordPress, Apache, OpenSSL)")
    user_actions: list[str] = Field(description="共有ホスティング・レンタルサーバー利用者が今すぐ実行できる応急対策案（2〜4項目）")

# RSSソース一覧
RSS_SOURCES = [
    {"name": "JVN (Japan Vulnerability Notes)", "url": "https://jvndb.jvn.jp/rss/jvndb.rdf"},
    {"name": "CISA KEV Catalog", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "PHP Security Advisories", "url": "https://www.php.net/news.rss"},
    {"name": "WordPress Security News", "url": "https://wordpress.org/news/category/security/feed/"}
]

def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY is not set.")
        return

    client = genai.Client(api_key=api_key)
    model = "gemini-2.5-flash"
    
    news_items = []

    for src in RSS_SOURCES:
        try:
            print(f"Fetching RSS feed from: {src['name']}")
            feed = feedparser.parse(src["url"])
            
            for entry in feed.entries[:3]: # 各ソース最新3件を取得
                title = entry.get("title", "")
                link = entry.get("link", "")
                published = entry.get("published", entry.get("updated", ""))
                summary = entry.get("summary", title)

                prompt = f"""
以下のセキュリティニュースを分析してください。
利用者は「レンタルサーバー（共有ホスティング）」でWebサイトやCMSを運用しています。
事業者によるパッチ適用待ちの間に、アプリ側・手前で今すぐ実行できる現実的な応急対策案（.htaccess設定、WAF有効化、プラグイン一時停止等）を含めて出力してください。

タイトル: {title}
概要: {summary}
"""
                config = types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=SecurityAnalysis,
                    safety_settings=[
                        types.SafetySetting(
                            category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                            threshold=types.HarmBlockThreshold.BLOCK_NONE,
                        )
                    ]
                )

                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=config
                )

                analysis = SecurityAnalysis.model_validate_json(response.text)

                news_items.append({
                    "original_title": title,
                    "url": link,
                    "source": src["name"],
                    "published": published,
                    "severity": analysis.severity,
                    "affected_tech": analysis.affected_tech,
                    "tags": [src["name"], analysis.severity],
                    "threat_overview": analysis.threat_overview,
                    "user_actions": analysis.user_actions
                })
        except Exception as e:
            print(f"Error processing {src['name']}: {e}")

    # 日本標準時 (JST: UTC+9) で現在の実行日時を取得
    jst = datetime.timezone(datetime.timedelta(hours=9))
    current_time_str = datetime.datetime.now(jst).strftime("%Y-%m-%d %H:%M:%S")

    # JSON保存用のデータ構造（データ収集日時 + ニュースリスト）
    output_data = {
        "last_updated": current_time_str,
        "items": news_items
    }

    # security_news_data.json の保存
    with open("security_news_data.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"Successfully updated security_news_data.json at {current_time_str} with {len(news_items)} items.")

if __name__ == "__main__":
    main()
