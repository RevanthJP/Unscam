# Unscam

A voice-first scam checker for people in India. Say what happened on a strange call or message, in your own language, and get a verdict, the reasons, and what to do next, with no sign-up.

**Live demo:** https://unscam-theta.vercel.app

## Why

Scam calls and messages reach people who may not type comfortably in English, and who won't write a prompt for a chatbot while they're being pressured. Here the user just talks.

## How it works

1. **Speech to text:** Whisper large-v3, hosted on Groq.
2. **Red-flag checklist:** an open model (gpt-oss-20b on Groq, switching to another model if it hits its free daily limit) and hand-written phrase lists for English, Tamil, Tanglish, Hindi and Hinglish each look for 12 warning signs, such as an OTP request, an arrest threat or a remote-access app.
3. **Model verdict:** the same model call also says whether this looks like a scam.
4. **Rules decide:**
   - **Likely scam:** a serious sign, three or more signs, or the model says scam and there is a concrete sign.
   - **Not sure:** any single warning sign, a model that is unsure, or an AI check that failed.
   - **Looks genuine:** no warning signs and the model does not object. The page footer notes that the tool can be wrong.
5. **Result card:** verdict, reasons and next steps. Replies in Hindi for Hindi or Hinglish, Tamil for Tamil or Tanglish, otherwise English, with a one-tap switch to English.

Every reason shows how well it is backed: an official page, a reported advisory, or a common pattern with no specific source checked. If the model is unavailable, the app falls back to the phrase lists and says so.

## Results

Final test on 143 AI-generated messages that were held back while the rules and prompt were tuned (59 scams, 84 genuine), using gpt-oss-20b:

| | Scams called scam | Scams given any warning | Genuine called scam | Genuine given any warning |
|---|---|---|---|---|
| Model's own verdict, using our prompt | 57/59 | 58/59 | 8/84 | 15/84 |
| Phrase lists only | 8/59 | 34/59 | 0/84 | 13/84 |
| **Final app (model + rules)** | **56/59** | **58/59** | **11/84** | **41/84** |

**What this shows**
- The model does most of the detection. Phrase lists alone are weak.
- The app gave a warning on all but one scam, and on nearly half of genuine messages. This is deliberate: an unnecessary warning costs less than a missed scam, and "not sure" only asks people to verify. It is still too many, and it is the main thing to improve.
- The rules did not improve detection on this set, and they added false alarms compared with the model's own verdict. What they add is sourced reasons, consistent next steps, and a safety net that never reassures when the AI check fails.

**Limits of these numbers**
- They predate later fixes found through real voice testing, such as genuine OTP alerts, offers with links, invented words from silence, and wrong reasons. Those fixes have only been spot-checked.
- The messages and labels are AI-generated and unreviewed. They are not real scam data, and some "genuine" examples look suspicious even to a person.
- They test text only, so speech recognition errors are not included. Voice has only been tried on a few generated clips.
- Hindi and Hinglish have only 45 messages in this test (16 scams, 29 genuine). A larger Hindi run hit the free daily limit and was discarded.
- The Tamil, Hindi, Tanglish and Hinglish wording has not been reviewed by native speakers.

Reproduce with `python eval_compare.py openai/gpt-oss-20b tests_large_final.csv`. Per-message results are in `results/`.

## Run it

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
echo "GROQ_API_KEY=your-key" > .env
./.venv/bin/uvicorn server:app --port 8501
```

## Privacy and safety

- Voice and text go to Groq for processing. This app does not store them.
- Use only your own or synthetic examples in the demo.
- The tool can be wrong and doesn't replace your bank or the police. In India, call 1930 or report at cybercrime.gov.in.

## Next steps

- Check links against a phishing database.
- Test on real recordings from Tamil and Tanglish speakers, and on real, consented scam examples.
- A WhatsApp bot, so people can forward a message or send a voice note where scams actually arrive.
- Screenshot upload, replies in more languages, spoken replies, and sending a result to a family member.
