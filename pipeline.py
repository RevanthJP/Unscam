"""Speech -> text -> red-flag checklist -> rules -> verdict, using Groq for the AI parts."""
import json
import os
import re

from dotenv import load_dotenv

from rules import ALL_FEATURES, clean_model_features, detect_language, evaluate, is_plain_otp_alert, lexicon_features, mentions_otp_warning, merge_features

load_dotenv()

STT_MODEL = os.getenv("GROQ_STT_MODEL", "whisper-large-v3")
LLM_MODEL = os.getenv("GROQ_LLM_MODEL", "openai/gpt-oss-20b")
# Tried in order when the main model hits its free-tier daily token limit.
FALLBACK_MODELS = ["openai/gpt-oss-20b", "openai/gpt-oss-120b", "qwen/qwen3.8-27b"]

FEATURE_HELP = {
    "otp_request": "asks the person to share/tell/send an OTP, PIN, CVV, password or passcode (NOT a message that only warns 'do not share your OTP')",
    "arrest_threat": "explicitly threatens arrest, a police case, a warrant or legal action. An accusation alone does not count",
    "crime_accusation": "claims the person's Aadhaar, SIM, account or parcel is linked to a crime such as money laundering, drugs or anti-national activity",
    "remote_access_app": "asks to install a remote-control or screen-sharing app such as AnyDesk or TeamViewer",
    "safe_account_transfer": "asks to move money to a 'safe', 'verification' or 'RBI' account",
    "money_request": "asks the person to send, pay or transfer money, fees or charges",
    "install_app": "asks to install or download an app, APK or file",
    "link": "contains an actual URL, says a link was sent, or asks to click or open one. 'Linked to' meaning connected with something is NOT a link",
    "urgency": "pushes to act immediately, or threatens to block, cut, close or suspend something soon",
    "kyc_update": "mentions a KYC, PAN or Aadhaar update or expiry",
    "prize_job": "offers a prize, lottery, easy job, or guaranteed returns",
    "secrecy": "tells the person to hide this from family, the bank or police, or to stay on the call. A safety line like 'do not share your OTP' is NOT secrecy",
    "promo_offer": "a marketing offer such as a pre-approved credit card, loan, cashback or reward from a company",
    "unknown_sender": "the input explicitly says the sender is an unknown number or unsaved contact. Do NOT mark this just because the input does not name a sender",
    "authority_claim": "claims to be police, CBI, customs, a court, RBI, a bank officer or another authority",
}

EXTRACT_SYSTEM = (
    "You read a short phone call description or message (English, Hindi, Tamil, or Tamil or Hindi written in "
    "Roman letters, possibly mixed with English). Decide which red-flag features are PRESENT. "
    "Answer only about what the text actually says or asks. A genuine bank alert that only warns "
    "'do not share your OTP' does NOT count as otp_request. Return a JSON object whose keys are exactly "
    "these feature names, each true or false:\n"
    + "\n".join(f"- {k}: {v}" for k, v in FEATURE_HELP.items())
)

ANALYZE_SYSTEM = (
    "You help people in India decide whether a call or message is a scam. The input is either the message "
    "itself or the person describing what happened, in any language, possibly in Roman letters. "
    "Return a JSON object with \"verdict\", \"reply_language\" and the features below. "
    "reply_language is the language the person is using, in any script: \"hi\" for Hindi or Hinglish, \"ta\" for Tamil or Tanglish, otherwise \"en\". "
    "verdict: \"scam\" if it looks like fraud; \"unsure\" if it asks for something risky (clicking a link, paying, "
    "sharing details, installing something) and cannot be verified, or an unknown sender claims to be a bank or "
    "authority; \"legit\" if it is a routine notice or chat that asks for nothing risky, such as a bank alert or OTP code that "
    "warns not to share it, a reminder, a delivery update or a request to visit a branch. If it is genuinely unclear choose \"unsure\", "
    "because a missed scam can cost someone their savings. A company's marketing offer with a link is \"unsure\", "
    "not \"scam\", unless it also asks for a fee, OTP, card details or an app install. Features are true or false, based only on what the input says. A genuine alert that "
    "only warns 'do not share your OTP' is not otp_request.\n"
    + "\n".join(f"- {k}: {v}" for k, v in FEATURE_HELP.items())
)

RAW_SYSTEM = (
    "You are helping a person in India decide whether a call or message is a scam. The text may be in "
    "English, Hindi, Tamil, or those written in Roman letters. Reply with a JSON object: {\"verdict\": \"scam\" | \"legit\" | \"unsure\"}."
)


def _client():
    from groq import Groq

    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not set")
    return Groq(api_key=key, max_retries=int(os.getenv("GROQ_RETRIES", "2")))


def transcribe(audio_bytes, filename="clip.wav", language=None):
    """Speech to text. Returns (text, detected_language)."""
    kwargs = dict(
        file=(filename, audio_bytes),
        model=STT_MODEL,
        response_format="verbose_json",
        temperature=0.0,
        prompt=("Aadhaar card, PAN card, KYC update, OTP, UPI, CBI, RBI, TRAI, customs, parcel, digital arrest, "
                "money laundering, anti-national, bank account, AnyDesk, unknown number."),
    )
    if language:
        kwargs["language"] = language
    resp = _client().audio.transcriptions.create(**kwargs)
    text = (resp.text or "").strip()
    return ("" if _is_silence(resp, text) else text), getattr(resp, "language", None)


# Speech models invent these when given silence or background noise.
_SILENCE_PHRASES = {"thank you", "thanks", "thank you very much", "thanks for watching", "you", "bye",
                    "okay", "ok", "subtitles by", "நன்றி", "धन्यवाद", "शुक्रिया"}


def _is_silence(resp, text):
    cleaned = re.sub(r"[^\w\s]", "", text).strip().lower()
    if not cleaned or cleaned in _SILENCE_PHRASES:
        return True
    segments = getattr(resp, "segments", None) or []
    probs = [s.get("no_speech_prob") if isinstance(s, dict) else getattr(s, "no_speech_prob", None) for s in segments]
    probs = [p for p in probs if p is not None]
    return bool(probs) and sum(probs) / len(probs) > 0.6


def llm_features(text):
    """Ask the model for the red-flag checklist. Returns {feature: bool}."""
    resp = _client().chat.completions.create(
        model=LLM_MODEL,
        messages=[{"role": "system", "content": EXTRACT_SYSTEM}, {"role": "user", "content": text}],
        response_format={"type": "json_object"},
        temperature=0,
    )
    data = json.loads(resp.choices[0].message.content)
    return {f: bool(data.get(f)) for f in ALL_FEATURES}


def llm_analyze(text):
    """One model call returning (features, verdict, reply_language)."""
    from groq import RateLimitError

    models = [LLM_MODEL] + [m for m in FALLBACK_MODELS if m != LLM_MODEL]
    for i, model in enumerate(models):
        try:
            resp = _client().chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": ANALYZE_SYSTEM}, {"role": "user", "content": text}],
                response_format={"type": "json_object"},
                temperature=0,
            )
            break
        except RateLimitError:
            if i == len(models) - 1:
                raise
    data = json.loads(resp.choices[0].message.content)
    verdict = str(data.get("verdict", "unsure")).lower()
    reply = str(data.get("reply_language", "en")).lower()
    return ({f: bool(data.get(f)) for f in ALL_FEATURES},
            verdict if verdict in ("scam", "legit", "unsure") else "unsure",
            reply if reply in ("en", "hi", "ta") else "en")


def raw_verdict(text):
    """Baseline: ask the same model directly, with no rules. Returns scam/legit/unsure."""
    resp = _client().chat.completions.create(
        model=LLM_MODEL,
        messages=[{"role": "system", "content": RAW_SYSTEM}, {"role": "user", "content": text}],
        response_format={"type": "json_object"},
        temperature=0,
    )
    v = str(json.loads(resp.choices[0].message.content).get("verdict", "unsure")).lower()
    return v if v in ("scam", "legit", "unsure") else "unsure"


def analyze_text(text, use_llm=True, lang_hint=None):
    """Full analysis of text. Falls back to phrase lists alone if the model call fails."""
    lang = detect_language(text)  # the script or common words decide when clear
    if lang == "en" and lang_hint:
        lang = lang_hint
    lex, evidence = lexicon_features(text)
    llm, model_verdict, error = None, None, None
    if is_plain_otp_alert(text):
        # A code and a do-not-share warning, asking for nothing: no model call needed.
        lex, evidence = {}, {}
        merged = merge_features()
        model_failed = False
    else:
        if use_llm:
            try:
                llm, model_verdict, reply = llm_analyze(text)
                if lang == "en":  # nothing clear so far, so trust the model
                    lang = reply
            except Exception as e:  # keep the app working, but never reassure without the model
                error = f"{type(e).__name__}: {str(e)[:160]}"
        llm = clean_model_features(text, llm) if llm else llm
        merged = merge_features(lex, llm or {})
        model_failed = use_llm and llm is None
    kw = dict(model_verdict=model_verdict, model_failed=model_failed,
              otp_alert=is_plain_otp_alert(text) or mentions_otp_warning(text))
    result = evaluate(merged, lang=lang, **kw)
    # Same verdict in English too, so the page can switch without another model call.
    result["translations"] = {
        code: {k: v for k, v in evaluate(merged, lang=code, **kw).items()
               if k in ("verdict_text", "reasons", "next_steps")}
        for code in {lang, "en"}
    }
    result.update({
        "text": text,
        "lexicon_features": [f for f, v in lex.items() if v],
        "llm_features": [f for f, v in (llm or {}).items() if v],
        "llm_used": llm is not None,
        "model_verdict": model_verdict,
        "merged_features": merged,
        "llm_error": error,
        "evidence": evidence,
    })
    return result


def analyze_audio(audio_bytes, filename="clip.wav", use_llm=True):
    text, spoken_lang = transcribe(audio_bytes, filename)
    # Nothing to judge: stop here, so no model call is spent and no verdict is invented.
    if not text:
        return {"transcript": "", "reason": "silence"}
    if len(text.split()) < 3 and not any(lexicon_features(text)[0].values()):
        return {"transcript": "", "reason": "too_short"}
    # Speech recognition may write spoken Hindi or Tamil in Roman letters, or in English.
    spoken = (spoken_lang or "").lower()
    hint = "hi" if spoken in ("hindi", "hi") else "ta" if spoken in ("tamil", "ta") else None
    result = analyze_text(text, use_llm=use_llm, lang_hint=hint)
    result["transcript"] = text
    result["spoken_language"] = spoken_lang
    return result
