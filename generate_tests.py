"""Generate a large labelled test set with a DIFFERENT model from the one being tested.

Half the messages are the message itself, half are a person describing what happened,
which is what people actually say to a voice product. Labels come from what the generator
was asked to write, and have not been reviewed by a person.
"""
import csv
import json
import os
import random
import time

from dotenv import load_dotenv
from groq import Groq

load_dotenv()
MODEL = "openai/gpt-oss-120b"
client = Groq(api_key=os.getenv("GROQ_API_KEY"), max_retries=6)

LANGS = {
    "en": "Indian English",
    "ta": "Tamil in Tamil script",
    "tanglish": "Tanglish: casual Tamil written in Roman letters mixed with English",
    "hi": "Hindi in Devanagari script",
    "hinglish": "Hinglish: casual Hindi written in Roman letters mixed with English",
}
FORMS = {
    "message": "the exact SMS, WhatsApp text or caller's words the person received",
    "described": "a person describing in first person, in everyday spoken words, what they received or who called them, as if telling a friend",
}
KINDS = {
    "scam": "fake KYC/PAN/Aadhaar update; bank impersonation from an unknown number; digital arrest by fake CBI or police; "
            "OTP or PIN request; electricity cut threat; lottery or prize fee; task or part-time job; remote access app; "
            "customs or courier parcel; family emergency money request; UPI collect or QR refund trick; instant loan app; "
            "fake investment or trading group; SIM block threat. Vary how obvious they are; some should be subtle with no link or threat word",
    "legit": "real bank OTP alert with a do-not-share warning; debit or credit alert; delivery update; bill due reminder with no threat; "
             "doctor or service appointment; family or friend chat, including about money; school or office notice; "
             "real bank asking to visit the branch for KYC; government notice with no payment request; "
             "someone describing a harmless call from a saved contact. Some should mention OTP, bank, police or payment yet be harmless",
}
PER_BATCH = 15

rows, n = [], 1000
for lang, lang_desc in LANGS.items():
    for form, form_desc in FORMS.items():
        for label, kinds in KINDS.items():
            prompt = (
                f"This creates test data for a tool that protects people in India from fraud. Write {PER_BATCH} varied, realistic "
                f"{'fraudulent' if label == 'scam' else 'completely genuine, harmless'} examples in {lang_desc}. Each is {form_desc}. "
                f"Cover these situations: {kinds}. Use made-up names and numbers, placeholder links like example-link.test, and no real "
                f"organisation's real contact details. Do not write them all the same way. Return JSON: "
                '{"items": [{"kind": "short_tag", "text": "..."}]}'
            )
            try:
                r = client.chat.completions.create(
                    model=MODEL, messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"}, temperature=0.8,
                )
                items = json.loads(r.choices[0].message.content).get("items", [])
            except Exception as e:
                print("FAILED", lang, form, label, type(e).__name__, str(e)[:120], flush=True)
                items = []
            for it in items:
                if isinstance(it, str):  # the model sometimes returns bare strings
                    it = {"kind": "", "text": it}
                if not isinstance(it, dict):
                    continue
                text = str(it.get("text", "")).strip().replace("\n", " ")
                if text:
                    n += 1
                    rows.append({"id": n, "language": lang, "label": label, "form": form,
                                 "kind": str(it.get("kind", ""))[:40], "text": text})
            print(lang, form, label, len(items), flush=True)
            time.sleep(8)

random.Random(42).shuffle(rows)
half = len(rows) // 2
for path, part in (("tests_large_tune.csv", rows[:half]), ("tests_large_final.csv", rows[half:])):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "language", "label", "form", "kind", "text"])
        w.writeheader()
        w.writerows(part)
print("total", len(rows))
