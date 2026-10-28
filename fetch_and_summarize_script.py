import os
import json
import datetime
import feedparser
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# スキーマ定義
class SecurityAnalysis(BaseModel):
    threat_overview: str = Field(description="脅威の概要（100〜150文字程度）")
    severity: str = Field(description="'Critical', 'High', 'Medium', 'Low' のいずれか")
    affected_tech: list[str] = Field(description="影響を受ける技術・ツール")
    user_actions: list[str] = Field(description="ユーザー側で今すぐ実行できる応急対策案")

# RSSソース一覧（安定度の高いフィードURL）
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
            print(f"Fetching: {src['name']}")
            feed = feedparser.parse(src["url"])
            entries = feed.entries[:10] # 各ソース最新10件までチェック
            
            print(f"  -> Found {len(entries)} entries")

            for entry in entries:
                title = entry.get("title", "")
                link = entry.get("link", "")
                published = entry.get("published", entry.get("updated", ""))
                summary = entry.get("summary", title)

                if not title:
                    continue

                # デフォルト値を用意（AI解析失敗時のフォールバック用）
                analysis_data = {
                    "threat_overview": summary[:150] if summary else title,
                    "severity": "Medium",
                    "affected_tech": ["Web Server", "PHP", "CMS"],
                    "user_actions": [
                        "サーバー管理画面でWAF設定が有効になっているか確認してください。",
                        "最新のセキュリティパッチ適用状況を確認し、CMSやプラグインを更新してください。"
                    ]
                }

                # Gemini API 解析
                try:
                    prompt = f"""
以下のセキュリティニュースを分析してください。
利用者は「レンタルサーバー（共有ホスティング）」でWebサイトやCMSを運用しています。
手前で今すぐ実行できる現実的な応急対策案を含めて出力してください。

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
                    analysis_data = {
                        "threat_overview": analysis.threat_overview,
                        "severity": analysis.severity,
                        "affected_tech": analysis.affected_tech,
                        "user_actions": analysis.user_actions
                    }
                except Exception as ai_err:
                    print(f"  -> AI Analysis Warning for '{title[:20]}...': {ai_err}")

                news_items.append({
                    "original_title": title,
                    "url": link,
                    "source": src["name"],
                    "published": published or datetime.datetime.now().strftime("%Y-%m-%d"),
                    "severity": analysis_data["severity"],
                    "affected_tech": analysis_data["affected_tech"],
                    "tags": [src["name"], analysis_data["severity"]],
                    "threat_overview": analysis_data["threat_overview"],
                    "user_actions": analysis_data["user_actions"]
                })
        except Exception as e:
            print(f"Error processing {src['name']}: {e}")

    # 日本標準時 (JST) の現在時刻を取得
    jst = datetime.timezone(datetime.timedelta(hours=9))
    current_time_str = datetime.datetime.now(jst).strftime("%Y-%m-%d %H:%M:%S")

    output_data = {
        "last_updated": current_time_str,
        "items": news_items
    }

    with open("security_news_data.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)

    print(f"Successfully saved {len(news_items)} items to security_news_data.json at {current_time_str}")

if __name__ == "__main__":
    main()
