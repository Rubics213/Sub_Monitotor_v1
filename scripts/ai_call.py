import json, os, sys, time, urllib.request, urllib.error

# Small delay between provider attempts so a 429/rate-limit on one key
# doesn't get hammered again immediately by the next key in the rotation.
RETRY_DELAY = 1.5


def ask_ai(prompt, output_file=None):
    gemini_keys = [os.environ.get(k) for k in ("GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3") if os.environ.get(k)]
    cohere_keys = [os.environ.get(k) for k in ("COHERE_API_KEY", "COHERE_API_KEY_2", "COHERE_API_KEY_3") if os.environ.get(k)]
    summary, provider = "", "none"

    # 1. Gemini rotation
    for idx, key in enumerate(gemini_keys, 1):
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={key}"
            payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
                cand = data.get("candidates", [])
                if cand:
                    parts = cand[0].get("content", {}).get("parts", [])
                    if parts and parts[0].get("text"):
                        summary = parts[0]["text"].strip()
                        provider = f"Gemini (key {idx})"
                        break
        except Exception:
            time.sleep(RETRY_DELAY)
            continue

    # 2. Cohere fallback
    if not summary:
        for idx, key in enumerate(cohere_keys, 1):
            try:
                url = "https://api.cohere.com/v2/chat"
                payload = json.dumps({"model": "command-a-03-2025", "messages": [{"role": "user", "content": prompt}]}).encode("utf-8")
                req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode("utf-8", "ignore"))
                    content = data.get("message", {}).get("content", [])
                    if content and content[0].get("text"):
                        summary = content[0]["text"].strip()
                        provider = f"Cohere (key {idx}, fallback)"
                        break
            except Exception:
                time.sleep(RETRY_DELAY)
                continue

    if output_file:
        with open(output_file, "w") as f:
            f.write(summary)
    print(f"PROVIDER:{provider}")
    return provider, summary


if __name__ == "__main__":
    prompt = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    out_file = sys.argv[2] if len(sys.argv) > 2 else None
    ask_ai(prompt, out_file)
