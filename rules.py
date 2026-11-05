"""Rule engine for the voice-first scam checker.

Two layers:
1. `lexicon_features(text)` finds red-flag features in a transcript or message using
   hand-written phrase lists for English, Tamil, Tanglish, Hindi and Hinglish.
2. `evaluate(features)` turns the features into a verdict, with reasons and next steps.

Features can come from the phrase lists, from an LLM, or both (see `merge_features`).

SOURCE TIERS (be honest about how well each rule is backed):
  official   - read on an official government page
  reported   - stated in a public advisory as reported by news outlets; original not checked
  heuristic  - a common scam pattern; no source checked
  model      - the AI model's own judgement, with no rule behind it
The phrase lists are hand-written and need review by a native Tamil speaker.
"""
import re

SOURCES = {
    "PIB-2110809": {
        "tier": "official",
        "label": "MHA release, PIB, 12 Mar 2025",
        "url": "https://pib.gov.in/PressReleasePage.aspx?PRID=2110809",
        "note": "Names helpline 1930 and cybercrime.gov.in; describes digital arrest scams.",
    },
    "I4C-ADVISORY": {
        "tier": "reported",
        "label": "I4C advisory on digital arrest (as reported)",
        "url": "https://udayavani.com/english-news/amid-rise-in-digital-arrest-cases-indian-cyber-crime-coordination-centre-issues-advisory-for-citizens",
        "note": "Police, CBI, customs, ED and judges do not arrest people on a video call.",
    },
    "RBI-KYC": {
        "tier": "reported",
        "label": "RBI caution on KYC-update fraud (as reported)",
        "url": "https://www.onmanorama.com/news/kerala/2024/09/23/cyber-fraud-in-the-guise-of-bank-kyc-updation-kerala-police-warn-public.html",
        "note": "Do not share credentials, card details, PINs or OTPs; fake KYC SMS carry links.",
    },
    "POLICE-OTP": {
        "tier": "reported",
        "label": "Hyderabad police OTP advisory (as reported)",
        "url": "https://newsmeter.in/crime/otp-scams-alert-hyderabad-police-issue-public-advisory-761366",
        "note": "No bank, government body or delivery service asks for an OTP.",
    },
    "COMMON-PATTERN": {
        "tier": "heuristic",
        "label": "Common scam pattern",
        "url": "",
        "note": "Widely seen warning sign; not tied to a specific advisory.",
    },
}

SOURCES["AI-MODEL"] = {
    "tier": "model",
    "label": "AI model judgement",
    "url": "",
    "note": "The model thought this looked like a scam, but no known rule matched.",
}

MODEL_REASON = {
    "en": "The AI check found this suspicious, though it did not match a known rule.",
    "ta": "AI சோதனை இதை சந்தேகத்திற்குரியதாக கண்டது, ஆனால் அறியப்பட்ட விதி எதுவும் பொருந்தவில்லை.",
}

HARD = ["otp_request", "arrest_threat", "crime_accusation", "remote_access_app", "safe_account_transfer"]
SOFT = ["money_request", "install_app", "link", "urgency", "kyc_update",
        "prize_job", "secrecy", "authority_claim", "unknown_sender", "promo_offer"]
ALL_FEATURES = HARD + SOFT

# Per-feature text shown to the user. "source" points into SOURCES.
REASONS = {
    "otp_request": {
        "source": "POLICE-OTP",
        "en": "It asks for an OTP, PIN, CVV or password. No bank or government office asks for these.",
        "ta": "OTP, PIN, CVV அல்லது கடவுச்சொல் கேட்கப்படுகிறது. எந்த வங்கியும் அரசு அலுவலகமும் இதை கேட்காது.",
    },
    "arrest_threat": {
        "source": "I4C-ADVISORY",
        "en": "It threatens arrest or legal action. Police, CBI, customs and courts do not arrest people over a call or video call.",
        "ta": "கைது அல்லது சட்ட நடவடிக்கை என மிரட்டுகிறது. காவல்துறை, CBI, சுங்கத்துறை அல்லது நீதிமன்றம் அழைப்பு அல்லது வீடியோ அழைப்பு மூலம் யாரையும் கைது செய்வதில்லை.",
    },
    "remote_access_app": {
        "source": "COMMON-PATTERN",
        "en": "It asks you to install a screen-sharing or remote-control app. That lets a stranger see and use your phone.",
        "ta": "திரையை பகிரும் அல்லது தொலைவிலிருந்து கட்டுப்படுத்தும் செயலியை நிறுவச் சொல்கிறது. இதன் மூலம் அந்நியர் உங்கள் போனை பயன்படுத்த முடியும்.",
    },
    "safe_account_transfer": {
        "source": "COMMON-PATTERN",
        "en": "It asks you to move money to a 'safe' or 'verification' account. Real banks never do this.",
        "ta": "'பாதுகாப்பான' அல்லது 'சரிபார்ப்பு' கணக்கிற்கு பணம் மாற்றச் சொல்கிறது. உண்மையான வங்கிகள் இப்படி கேட்காது.",
    },
    "money_request": {
        "source": "COMMON-PATTERN",
        "en": "It asks you to send money.",
        "ta": "பணம் அனுப்பச் சொல்கிறது.",
    },
    "install_app": {
        "source": "COMMON-PATTERN",
        "en": "It asks you to install or download an app or file.",
        "ta": "ஒரு செயலி அல்லது கோப்பை நிறுவ அல்லது பதிவிறக்கச் சொல்கிறது.",
    },
    "link": {
        "source": "COMMON-PATTERN",
        "en": "It includes a link. Links in unexpected messages can lead to fake pages that steal your details.",
        "ta": "இதில் ஒரு இணைப்பு உள்ளது. எதிர்பாராத செய்திகளில் உள்ள இணைப்புகள் உங்கள் விவரங்களை திருடும் போலி பக்கங்களுக்கு கொண்டு செல்லலாம்.",
    },
    "urgency": {
        "source": "COMMON-PATTERN",
        "en": "It pushes you to act immediately or threatens to block, cut or close something.",
        "ta": "உடனே செயல்பட வற்புறுத்துகிறது அல்லது முடக்கம், துண்டிப்பு என மிரட்டுகிறது.",
    },
    "kyc_update": {
        "source": "RBI-KYC",
        "en": "It mentions a KYC, PAN or Aadhaar update. Fake KYC updates are a known fraud.",
        "ta": "KYC, PAN அல்லது ஆதார் புதுப்பிப்பு பற்றி கூறுகிறது. போலி KYC புதுப்பிப்பு அறியப்பட்ட மோசடி.",
    },
    "prize_job": {
        "source": "COMMON-PATTERN",
        "en": "It offers a prize, lottery, easy job or guaranteed returns.",
        "ta": "பரிசு, லாட்டரி, எளிய வேலை அல்லது உறுதியான வருமானம் என ஆசை காட்டுகிறது.",
    },
    "secrecy": {
        "source": "COMMON-PATTERN",
        "en": "It tells you to keep this secret or stay on the line.",
        "ta": "இதை ரகசியமாக வைக்கச் சொல்கிறது அல்லது அழைப்பை துண்டிக்க வேண்டாம் என்கிறது.",
    },
    "authority_claim": {
        "source": "COMMON-PATTERN",
        "en": "It claims to come from police, a bank, a court or another authority.",
        "ta": "காவல்துறை, வங்கி, நீதிமன்றம் போன்ற அதிகார அமைப்பிலிருந்து வருவதாக கூறுகிறது.",
    },
}

VERDICTS = {
    "likely_scam": {
        "en": "Likely a scam",
        "ta": "இது மோசடியாக இருக்க வாய்ப்பு அதிகம்",
    },
    "not_sure": {
        "en": "Not sure. Be careful.",
        "ta": "உறுதியாக சொல்ல முடியாது. கவனமாக இருங்கள்.",
    },
    "likely_fine": {
        "en": "This looks genuine",
        "ta": "இது உண்மையானது போல் தெரிகிறது",
    },
}

NEXT_STEPS = {
    "likely_scam": {
        "source": "PIB-2110809",
        "en": [
            "Stop the call or stop replying. Do not send money, OTPs or install anything.",
            "Call the national cyber crime helpline 1930, or report at cybercrime.gov.in.",
            "If money was sent, report within the hour. Call your bank on the number printed on your card.",
        ],
        "ta": [
            "அழைப்பை நிறுத்துங்கள் அல்லது பதில் அனுப்பாதீர்கள். பணம், OTP கொடுக்காதீர்கள். எதையும் நிறுவாதீர்கள்.",
            "தேசிய சைபர் குற்ற உதவி எண் 1930 ஐ அழைக்கவும் அல்லது cybercrime.gov.in இல் புகார் செய்யவும்.",
            "பணம் அனுப்பியிருந்தால் உடனே, ஒரு மணி நேரத்திற்குள் புகார் செய்யுங்கள். உங்கள் அட்டையில் உள்ள எண்ணில் வங்கியை அழைக்கவும்.",
        ],
    },
    "not_sure": {
        "source": "PIB-2110809",
        "en": [
            "Do not click links, share OTPs or send money yet.",
            "Check it yourself: open the official app or website directly, or call the number on your card. Do not use the link or number in the message.",
            "If it feels wrong, report at cybercrime.gov.in or call 1930.",
        ],
        "ta": [
            "இப்போதைக்கு இணைப்புகளை கிளிக் செய்யாதீர்கள். OTP, பணம் கொடுக்காதீர்கள்.",
            "நீங்களே சரிபார்க்கவும்: அதிகாரப்பூர்வ செயலி அல்லது இணையதளத்தை நேரடியாக திறக்கவும், அல்லது உங்கள் அட்டையில் உள்ள எண்ணை அழைக்கவும். செய்தியில் உள்ள இணைப்பையோ எண்ணையோ பயன்படுத்த வேண்டாம்.",
            "சந்தேகம் இருந்தால் cybercrime.gov.in இல் புகார் செய்யவும் அல்லது 1930 ஐ அழைக்கவும்.",
        ],
    },
    "likely_fine": {
        "source": "COMMON-PATTERN",
        "en": [
            "You do not need to do anything.",
            "Never share an OTP or PIN with anyone, even if someone calls about this.",
        ],
        "ta": [
            "நீங்கள் எதுவும் செய்ய வேண்டியதில்லை.",
            "இது பற்றி யாராவது அழைத்தாலும், OTP அல்லது PIN ஐ யாரிடமும் பகிராதீர்கள்.",
        ],
    },
}


REASONS["promo_offer"] = {
    "source": "COMMON-PATTERN",
    "en": "It is a promotional offer, like a pre-approved card or loan. Real companies send these, and scammers copy them, so a message alone cannot prove which it is.",
    "ta": "இது முன்னரே அங்கீகரிக்கப்பட்ட கார்டு அல்லது கடன் போன்ற விளம்பர சலுகை. உண்மையான நிறுவனங்கள் இவற்றை அனுப்புகின்றன, மோசடிக்காரர்களும் இதை நகலெடுக்கிறார்கள். செய்தியை மட்டும் வைத்து எது என்று உறுதி செய்ய முடியாது.",
}

REASONS["crime_accusation"] = {
    "source": "I4C-ADVISORY",
    "en": "It says your Aadhaar, SIM, account or parcel is linked to a crime. Scammers use this accusation to frighten people, often leading to a fake \"digital arrest\".",
    "ta": "உங்கள் ஆதார், சிம், கணக்கு அல்லது பார்சல் ஒரு குற்றத்துடன் தொடர்புடையது என்று கூறுகிறது. மக்களை பயமுறுத்த மோசடிக்காரர்கள் இப்படி குற்றம் சாட்டுவார்கள். இது பெரும்பாலும் போலி \"டிஜிட்டல் கைது\" மோசடியாக மாறும்.",
}

REASONS["unknown_sender"] = {
    "source": "COMMON-PATTERN",
    "en": "It comes from an unknown number or sender. Banks and government offices use official channels.",
    "ta": "தெரியாத எண் அல்லது அனுப்புநரிடமிருந்து வந்துள்ளது. வங்கிகளும் அரசு அலுவலகங்களும் அதிகாரப்பூர்வ வழிகளைப் பயன்படுத்துகின்றன.",
}

# Hindi text, kept apart from the English and Tamil above.
_HI_REASONS = {'otp_request': 'OTP, PIN, CVV या पासवर्ड मांगा जा रहा है। कोई भी बैंक या सरकारी दफ्तर ये नहीं मांगता।', 'arrest_threat': 'गिरफ्तारी या कानूनी कार्रवाई की धमकी दी जा रही है। पुलिस, CBI, कस्टम या अदालत फोन या वीडियो कॉल पर किसी को गिरफ्तार नहीं करते।', 'remote_access_app': 'स्क्रीन शेयर या रिमोट कंट्रोल ऐप इंस्टॉल करने को कहा जा रहा है। इससे कोई अजनबी आपका फोन देख और चला सकता है।', 'safe_account_transfer': "पैसे किसी 'सुरक्षित' या 'वेरिफिकेशन' खाते में भेजने को कहा जा रहा है। असली बैंक ऐसा कभी नहीं कहते।", 'money_request': 'पैसे भेजने को कहा जा रहा है।', 'install_app': 'कोई ऐप या फाइल इंस्टॉल या डाउनलोड करने को कहा जा रहा है।', 'link': 'इसमें एक लिंक है। अनचाहे मैसेज के लिंक आपकी जानकारी चुराने वाले नकली पेज पर ले जा सकते हैं।', 'urgency': 'तुरंत कुछ करने का दबाव है, या कुछ बंद या ब्लॉक करने की धमकी है।', 'kyc_update': 'KYC, PAN या आधार अपडेट की बात है। फर्जी KYC अपडेट एक जानी-मानी धोखाधड़ी है।', 'prize_job': 'इनाम, लॉटरी, आसान नौकरी या पक्की कमाई का लालच दिया जा रहा है।', 'secrecy': 'इसे गुप्त रखने या कॉल पर बने रहने को कहा जा रहा है।', 'authority_claim': 'पुलिस, बैंक, अदालत या किसी और अधिकारी की ओर से होने का दावा है।'}
_HI_REASONS["promo_offer"] = "यह प्री-अप्रूव्ड कार्ड या लोन जैसा प्रचार ऑफर है। असली कंपनियां ऐसे मैसेज भेजती हैं और ठग उनकी नकल करते हैं, इसलिए सिर्फ मैसेज से पक्का नहीं कहा जा सकता।"
_HI_REASONS["crime_accusation"] = "इसमें कहा गया है कि आपका आधार, सिम, खाता या पार्सल किसी अपराध से जुड़ा है। ठग लोगों को डराने के लिए ऐसा आरोप लगाते हैं, और अक्सर यह नकली \"डिजिटल अरेस्ट\" तक पहुंचता है।"
_HI_REASONS["unknown_sender"] = "यह किसी अनजान नंबर या भेजने वाले से आया है। बैंक और सरकारी दफ्तर आधिकारिक माध्यम का इस्तेमाल करते हैं।"
for _f, _t in _HI_REASONS.items():
    REASONS[_f]["hi"] = _t
MODEL_REASON["hi"] = "AI जांच को यह संदिग्ध लगा, हालांकि यह किसी ज्ञात नियम से मेल नहीं खाता।"
VERDICTS["likely_scam"]["hi"] = "यह धोखाधड़ी होने की संभावना ज़्यादा है"
VERDICTS["not_sure"]["hi"] = "पक्का नहीं कह सकते। सावधान रहें।"
VERDICTS["likely_fine"]["hi"] = "यह असली लगता है"
NEXT_STEPS["likely_scam"]["hi"] = [
    "कॉल काट दें या जवाब देना बंद करें। पैसे या OTP न दें, और कुछ भी इंस्टॉल न करें।",
    "राष्ट्रीय साइबर अपराध हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर शिकायत करें।",
    "अगर पैसे भेज दिए हैं तो एक घंटे के अंदर शिकायत करें। अपने कार्ड पर छपे नंबर पर बैंक को कॉल करें।",
]
NEXT_STEPS["not_sure"]["hi"] = [
    "अभी लिंक पर क्लिक न करें, OTP न बताएं और पैसे न भेजें।",
    "खुद जांचें: आधिकारिक ऐप या वेबसाइट सीधे खोलें, या अपने कार्ड पर छपे नंबर पर कॉल करें। मैसेज में दिए लिंक या नंबर का इस्तेमाल न करें।",
    "अगर कुछ गलत लगे तो cybercrime.gov.in पर शिकायत करें या 1930 पर कॉल करें।",
]
NEXT_STEPS["likely_fine"]["hi"] = [
    "आपको कुछ करने की ज़रूरत नहीं है।",
    "इस बारे में कोई कॉल करे तब भी OTP या PIN किसी को न बताएं।",
]


OTP_REASON = {
    "en": "Real OTP alerts send a code and warn you not to share it. This one asks you for nothing.",
    "ta": "உண்மையான OTP செய்திகள் ஒரு குறியீட்டை அனுப்பி, அதை பகிர வேண்டாம் என்று எச்சரிக்கும். இது உங்களிடம் எதையும் கேட்கவில்லை.",
    "hi": "असली OTP अलर्ट एक कोड भेजते हैं और उसे शेयर न करने की चेतावनी देते हैं। यह आपसे कुछ नहीं मांगता।",
}
OTP_STEPS = {
    "en": ["If you made this transaction, you do not need to do anything.",
           "If you did not, someone may be trying to use your card. Do not share the OTP, and call your bank right away on the number on your card."],
    "ta": ["இந்த பரிவர்த்தனையை நீங்கள் செய்திருந்தால், எதுவும் செய்ய வேண்டியதில்லை.",
           "நீங்கள் செய்யவில்லை என்றால், யாரோ உங்கள் கார்டை பயன்படுத்த முயற்சிக்கலாம். OTP ஐ பகிராதீர்கள், உங்கள் கார்டில் உள்ள எண்ணில் உடனே வங்கியை அழைக்கவும்."],
    "hi": ["अगर यह लेनदेन आपने किया है, तो आपको कुछ करने की ज़रूरत नहीं है।",
           "अगर नहीं किया, तो हो सकता है कोई आपका कार्ड इस्तेमाल करने की कोशिश कर रहा हो। OTP शेयर न करें और अपने कार्ड पर छपे नंबर पर तुरंत बैंक को कॉल करें।"],
}
OFFER_STEPS = {
    "en": ["Do not use the link in the message.",
           "Open the company's official app yourself, or type its website address. A real offer should show up there.",
           "Never pay a fee or share an OTP or card details to claim an offer."],
    "ta": ["செய்தியில் உள்ள இணைப்பை பயன்படுத்த வேண்டாம்.",
           "நிறுவனத்தின் அதிகாரப்பூர்வ செயலியை நீங்களே திறக்கவும், அல்லது அதன் இணையதள முகவரியை தட்டச்சு செய்யவும். உண்மையான சலுகை அங்கே தெரிய வேண்டும்.",
           "சலுகையைப் பெற கட்டணம் செலுத்தவோ, OTP அல்லது கார்டு விவரங்களை பகிரவோ வேண்டாம்."],
    "hi": ["मैसेज में दिए लिंक का इस्तेमाल न करें।",
           "कंपनी का आधिकारिक ऐप खुद खोलें, या उसकी वेबसाइट का पता टाइप करें। असली ऑफर वहां दिखना चाहिए।",
           "ऑफर पाने के लिए कभी फीस न दें, और OTP या कार्ड की जानकारी न बताएं।"],
}

# ---------------------------------------------------------------------------
# Phrase lists. Each feature maps to regex patterns (case-insensitive).
# Tamil patterns match inside Tamil script; Tanglish patterns match Roman Tamil.
# ---------------------------------------------------------------------------
_SECRET = r"(otp|ஓடிபி|ஓ\.டி\.பி|pin|பின்|cvv|சிவிவி|password|passcode|கடவுச்சொல்)"

LEXICON = {
    "otp_request": [
        # English: verb near otp/pin/cvv/password
        r"\b(share|send|tell|give|read( out)?|provide|forward|confirm|say|enter)\b.{0,30}\b(otp|one[- ]time password|pin|cvv|password|passcode)\b",
        r"\b(otp|one[- ]time password|pin|cvv|password|passcode)\b.{0,20}\b(share|send|tell|give|read out|forward)\b",
        # Tamil script
        _SECRET + r".{0,25}(சொல்லுங்க|சொல்லுங்கள்|சொல்லுங|அனுப்புங்க|அனுப்புங்கள்|கொடுங்க|கொடுங்கள்|பகிருங்கள்|சொல்லு)",
        r"(சொல்லுங்க|சொல்லுங்கள்|அனுப்புங்க|அனுப்புங்கள்|கொடுங்க|கொடுங்கள்|பகிருங்கள்).{0,25}" + _SECRET,
        # Tanglish
        r"\b(otp|pin|cvv|password)\b.{0,20}\b(sollunga|solunga|sollu|anuppunga|anupunga|anuppu|kudunga|kodunga|share pannunga|share pannu|thaanga|thanga)\b",
        r"\b(sollunga|solunga|anuppunga|anupunga|kudunga|kodunga|share pannunga|thaanga)\b.{0,20}\b(otp|pin|cvv|password)\b",
    ],
    "arrest_threat": [
        r"\b(digital arrest|arrest warrant|be arrested|arrest you|under arrest|you will be arrested)\b",
        r"கைது",
        r"\b(arrest pannuvom|arrest pannuvaanga|arrest aaga|arrest aagiduveenga|arrest warrant|case file pannuvom|case podrom|jail)\b",
    ],
    "crime_accusation": [
        r"\b(money laundering|anti[- ]national|terror(ist|ism)? (activity|activities|funding)|illegal (activity|activities|items?)|narcotics case|drugs?\b.{0,25}\b(parcel|package|courier)|(parcel|package|courier)\b.{0,25}\bdrugs?)\b",
        r"பணமோசடி|பண மோசடி|போதைப்பொருள்|தேச விரோத|சட்டவிரோத",
        r"मनी लॉन्ड्रिंग|ड्रग्स|देश विरोधी|देशद्रोही|अवैध गतिविधि|गैरकानूनी",
    ],
    "remote_access_app": [
        r"\b(anydesk|any desk|teamviewer|team viewer|quicksupport|rustdesk|screen ?shar(e|ing))\b",
        r"எனிடெஸ்க்|டீம்வியூவர்|ஸ்கிரீன் ஷேர்",
    ],
    "safe_account_transfer": [
        r"\b(safe account|verification account|rbi account|secure account|will be (refunded|returned) after verification)\b",
        r"பாதுகாப்பான கணக்கு|சரிபார்ப்பு கணக்கு",
        r"\b(safe account|verification account)\b",
    ],
    "money_request": [
        r"\b(send|transfer|pay|deposit)\b.{0,30}\b(money|amount|rs\.?|rupees|upi|fee|charges|₹)",
        r"\b(money|amount|fee|charges)\b.{0,20}\b(send|transfer|pay|deposit)\b",
        r"பணம்.{0,15}(அனுப்பு|செலுத்து|மாற்று)|(அனுப்புங்க|அனுப்புங்கள்|செலுத்துங்கள்).{0,15}பணம்",
        r"\b(paisa|panam|money|amount)\b.{0,15}\b(anuppunga|anupunga|pay pannunga|transfer pannunga|kattunga)\b",
    ],
    "install_app": [
        r"\b(install|download)\b.{0,15}\b(this |the |our )?(app|apk|application|software|file)\b",
        r"\.apk\b",
        r"(செயலி|ஆப்).{0,15}(நிறுவ|பதிவிறக்க|இன்ஸ்டால்)",
        r"\b(app|apk)\b.{0,15}\b(install pannunga|download pannunga|install pannu)\b",
    ],
    "link": [
        r"https?://|www\.|bit\.ly|tinyurl|\.xyz\b|\.top\b",
        r"\b(click|tap|open)\b.{0,15}\b(link|url)\b",
        r"இணைப்பு.{0,15}(கிளிக்|தட்டு|திற)|(கிளிக்).{0,15}இணைப்பு",
        r"\blink\b.{0,15}\b(click pannunga|click pannu|open pannunga)\b",
    ],
    "urgency": [
        r"\b(immediately|urgent(ly)?|right now|within \d+ (hours?|minutes?|mins?)|tonight|today itself|last warning|final notice|will be (blocked|suspended|disconnected|cut|closed|frozen))\b",
        r"உடனடியாக|உடனே|இன்று இரவு|துண்டிக்கப்படும்|முடக்கப்படும்|தடை செய்யப்படும்|நிறுத்தப்படும்",
        r"\b(udane|udanae|ippove|ippavae|inniku night|inniku raathiri|block aagum|block aaidum|cut aagum|disconnect aagum|close aagum|suspend aagum)\b",
    ],
    "kyc_update": [
        r"\b(kyc|pan (card )?(update|expired|link)|aadhaar (update|link|expired)|aadhar (update|link|expired))\b",
        r"கேஒய்சி|கே\.ஒய்\.சி|ஆதார்.{0,10}(புதுப்பி|இணை)|பான்.{0,10}(புதுப்பி|இணை)",
    ],
    "prize_job": [
        r"\b(lottery|lucky draw|you (have )?won|prize money|work from home|part[- ]time job|guaranteed returns?|double your money|earn .{0,15}daily)\b",
        r"லாட்டரி|பரிசு.{0,10}(விழுந்த|வென்ற)|வீட்டிலிருந்து வேலை",
        r"\b(lottery adichiruku|prize vandhirukku|prize vanthirukku|work from home|part time job)\b",
    ],
    "secrecy": [
        r"\b(don'?t tell|do not tell|do not inform|keep (this )?(confidential|secret)|no one (should )?know|stay on (the )?(line|call)|do not (cut|disconnect) the call)\b",
        r"யாரிடமும் சொல்லாதீர்கள்|ரகசியம்|அழைப்பை துண்டிக்காதீர்கள்|போனை வைக்காதீர்கள்",
        r"\b(yaaridamum solla vendaam|yaarukitayum solla vendaam|yarukum solladheenga|yarukum solla vendam|call cut pannadheenga|confidential)\b",
    ],
    "authority_claim": [
        r"\b(cbi|police|customs|narcotics|ncb|enforcement directorate|income tax|trai|cyber ?crime|court|judge|bank manager|rbi)\b",
        r"காவல்|போலீஸ்|சிபிஐ|சுங்கத்துறை|நீதிமன்ற|ரிசர்வ் வங்கி|வங்கி அதிகாரி|சைபர் கிரைம்",
    ],
}


# Hindi: Devanagari and Hinglish (Hindi in Roman letters).
_HI_SECRET = r"(otp|ओटीपी|pin|पिन|cvv|सीवीवी|password|पासवर्ड)"
_HI_LEXICON = {
    "otp_request": [
        _HI_SECRET + r".{0,25}(बताइए|बताइये|बताएं|बताओ|बता दीजिए|भेजिए|भेजें|भेजो|दीजिए|दे दीजिए|शेयर कीजिए|शेयर करें)",
        r"\b(otp|pin|cvv|password)\b.{0,20}\b(batao|bataiye|batayen|bata do|bata dijiye|bhejo|bhejiye|dijiye|de do|share karo|share kijiye|share karein)\b",
    ],
    "arrest_threat": [
        r"गिरफ्तार|गिरफ़्तार|डिजिटल अरेस्ट|अरेस्ट वारंट",
        r"\b(giraftar|arrest kar|arrest ho jaoge|arrest ho jayenge|arrest warrant|jail bhej)\b",
    ],
    "remote_access_app": [r"एनीडेस्क|टीमव्यूअर|स्क्रीन शेयर"],
    "safe_account_transfer": [r"सुरक्षित खात|वेरिफिकेशन खात|\b(surakshit khata)\b"],
    "money_request": [
        r"(पैसे|रुपये|रुपए|राशि|शुल्क|फीस).{0,20}(भेज|ट्रांसफर|जमा कर|जमा करें|भुगतान कर)",
        r"(भेजिए|भेजें|भेजो|जमा करें|भुगतान करें).{0,20}(पैसे|रुपये|रुपए|राशि|शुल्क|फीस)",
        r"\b(paise|rupaye|rupees|amount|fee)\b.{0,20}\b(bhejiye|bhejo|bhej do|transfer karo|transfer kijiye|jama karein|jama karo|pay karo|pay kijiye)\b",
    ],
    "install_app": [
        r"(ऐप|एप|एपीके|फाइल).{0,15}(इंस्टॉल|डाउनलोड)",
        r"\b(app|apk|file)\b.{0,15}\b(install kar|download kar)",
    ],
    "link": [r"लिंक.{0,15}(क्लिक|खोल)|(क्लिक).{0,15}लिंक", r"\blink\b.{0,15}\b(click kar|khol)"],
    "urgency": [
        r"तुरंत|फौरन|अभी|आज रात|बंद हो जाएगा|बंद कर दिया जाएगा|ब्लॉक हो|काट दी जाएगी|कट जाएगी",
        r"\b(turant|abhi ke abhi|aaj raat|band ho jayega|block ho jayega|kaat di jayegi|kat jayegi)\b",
    ],
    "kyc_update": [r"केवाईसी|आधार.{0,10}(अपडेट|लिंक)|पैन.{0,10}(अपडेट|लिंक)"],
    "prize_job": [
        r"लॉटरी|इनाम|पुरस्कार|घर बैठे|वर्क फ्रॉम होम|पार्ट टाइम",
        r"\b(lottery lagi|inaam|ghar baithe|roz .{0,10}kamaiye)\b",
    ],
    "secrecy": [
        r"किसी को (न|ना|मत) बता|गुप्त रख|कॉल पर बने रह|फोन (न|ना|मत) काट",
        r"\b(kisi ko (na|mat) batana|kisi ko mat batao|call mat kaatna|phone mat kaatna)\b",
    ],
    "authority_claim": [r"पुलिस|सीबीआई|कस्टम|अदालत|कोर्ट|आरबीआई|बैंक अधिकारी|बैंक मैनेजर|साइबर क्राइम"],
}
for _f, _p in _HI_LEXICON.items():
    LEXICON[_f] = LEXICON[_f] + _p

LEXICON["unknown_sender"] = [
    r"\b(unknown|unsaved|random|strange|unfamiliar) (number|sender|caller|phone)\b|\bnumber i (don'?t|do not) (know|recogni[sz]e)\b",
    r"தெரியாத (எண்|நம்பர்)|அறியாத (எண்|நம்பர்)|அறிமுகமில்லாத (எண்|நபர்)",
    r"\b(theriyadha|theriyatha|theriyaadha) (number|nambar|aal)\b",
    r"अनजान (नंबर|व्यक्ति)|अज्ञात (नंबर|व्यक्ति)",
    r"\b(anjaan|anjan|agyat) (number|aadmi)\b",
]
LEXICON["promo_offer"] = [
    r"\b(pre[- ]?approved|credit card offer|loan offer|personal loan offer|cash ?back offer|exclusive offer|special offer|limited[- ]time offer|lifetime free card)\b",
    r"முன்னரே அங்கீகரிக்கப்பட்ட|கிரெடிட் கார்டு சலுகை|கடன் சலுகை|சிறப்பு சலுகை",
    r"प्री[- ]?अप्रूव्ड|क्रेडिट कार्ड ऑफर|लोन ऑफर|विशेष ऑफर|कैशबैक ऑफर",
]
LEXICON["link"] = LEXICON["link"] + [
    r"\b(gave|give|given|sent|send|shared|got|has|had|with|contains?)\b.{0,15}\b(a|an|the|this|some)\b.{0,8}\blink\b",
    r"\blink\b.{0,12}\b(kuduthaanga|kuduthanga|anuppi|vandhuchu|irukku|bheja|aaya|diya|hai)\b",
    r"(இணைப்பு|லிங்க்|link) *(அனுப்பி|கொடுத்|வந்த|இருக்கு)|(लिंक|link) *(भेजा|दिया|आया|है)",
]
LEXICON["kyc_update"] = LEXICON["kyc_update"] + [
    r"\bupdate (my|your|the)?.{0,12}(bank )?(details|account details)\b",
]

# Words that cancel a request-style match when they appear just before it
# (a genuine bank alert says "do not share your OTP").
_NEGATION = re.compile(
    r"(do not|don'?t|dont|never|not to|no one|without|should not|sollaadheenga|sollathinga|"
    r"sollaadhinga|vendaam|வேண்டாம்|சொல்லாதீர்|பகிராதீர்|கொடுக்காதீர்|"
    r"मत|न बताएं|ना बताएं|न करें|नहीं मांग|nahi|mat batao|mat batana|mat dena)",
    re.IGNORECASE,
)
_NEG_GUARDED = {"otp_request"}


def _matches(feature, pattern, text):
    for m in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
        if feature in _NEG_GUARDED:
            window = text[max(0, m.start() - 25): m.end() + 25]
            if _NEGATION.search(window):
                continue
        return m.group(0)
    return None


def _split_scripts(text):
    """Speech-to-text glues Tamil or Hindi endings onto English words ("launderingல"), which hides them."""
    text = re.sub(r"([a-z0-9])([\u0900-\u097F\u0B80-\u0BFF])", r"\1 \2", text)
    return re.sub(r"([\u0900-\u097F\u0B80-\u0BFF])([a-z0-9])", r"\1 \2", text)


_REAL_LINK = re.compile(r"https?://|www\.|\b[\w-]+\.(com|in|org|net|xyz|top|test|ly)\b|\b(click|tap|open)\b|கிளிக்|क्लिक", re.I)
_LINKED_SENSE = re.compile(r"\blinked\b|\blink\s*(ஆ|aa|aay|aag|ho\b|hua|hui|hai ki|with\b|to\b)|लिंक (हो|है कि|किया)|லிங்க்\s*ஆ", re.I)


_ARREST_WORDS = re.compile(
    r"arrest|warrant|\bjail\b|legal action|\bcase\b|\bfir\b|court notice|police (will|are coming)|"
    r"கைது|வழக்கு|சிறை|गिरफ़?्त|अरेस्ट|वारंट|जेल|मुकदमा|कानूनी कार्रवाई|giraftar|kanooni", re.I)


def clean_model_features(text, features):
    """The model can over-read. Drop claims the words themselves contradict, so reasons stay true."""
    cleaned = dict(features)
    spaced = _split_scripts((text or "").lower())
    # An accusation of a crime is not a threat of arrest unless the words say so.
    if cleaned.get("arrest_threat") and not _ARREST_WORDS.search(spaced):
        cleaned["arrest_threat"] = False
        cleaned["crime_accusation"] = True
    # "Your Aadhaar is linked to..." means connected, not a link to click.
    if cleaned.get("link") and _LINKED_SENSE.search(spaced) and not _REAL_LINK.search(spaced):
        cleaned["link"] = False
    return cleaned


def lexicon_features(text):
    """Return ({feature: bool}, {feature: matched snippet}) for a piece of text."""
    text = (text or "").lower()
    # Speech-to-text often spells these out, e.g. "K.Y.C." or "o t p".
    text = re.sub(r"\bk[.\s]+y[.\s]+c\b\.?", "kyc", text)
    text = re.sub(r"\bo[.\s]+t[.\s]+p\b\.?", "otp", text)
    text = re.sub(r"\bc[.\s]+v[.\s]+v\b\.?", "cvv", text)
    text = _split_scripts(text)
    found, evidence = {}, {}
    for feature in ALL_FEATURES:
        hit = None
        for pattern in LEXICON.get(feature, []):
            hit = _matches(feature, pattern, text)
            if hit:
                break
        found[feature] = bool(hit)
        if hit:
            evidence[feature] = hit.strip()[:80]
    return found, evidence


def merge_features(*feature_dicts):
    """OR several feature dicts together (phrase lists, LLM output)."""
    merged = {f: False for f in ALL_FEATURES}
    for d in feature_dicts:
        for f in ALL_FEATURES:
            if d and d.get(f):
                merged[f] = True
    return merged


_TANGLISH = re.compile(r"\b(naan|enakku|ennaku|unga|ungala|ungaluku|sollunga|solli|sonnaanga|sonnanga|vandhuchu|vanthuchu|vandhudhu|irukku|iruku|irundhu|pannunga|pannu|pannanum|panna|pesuren|pesuraanga|illa|illana|enna|yaar|yaaru|aagum|aaidum|anuppunga|kekkuraanga|kettaanga|da|machan|nalaiku|naalaiku|inniku)\b", re.I)
_HINGLISH = re.compile(r"\b(mujhe|mera|meri|mere|aap|aapka|aapke|aapko|aapki|kya|hai|hain|tha|thi|raha|rahi|nahi|nahin|kar|karo|karna|kijiye|bataiye|batao|bhejo|bhejiye|paise|aaya|aayi|bol|bola|kaha|kisi|abhi|turant|kal|beta|yeh|ye|hua|hoga|gaya)\b", re.I)


def detect_language(text):
    """Reply language. Tanglish gets Tamil and Hinglish gets Hindi; people can switch to English."""
    text = text or ""
    if re.search(r"[\u0B80-\u0BFF]", text):
        return "ta"
    if re.search(r"[\u0900-\u097F]", text):
        return "hi"
    ta, hi = len(_TANGLISH.findall(text)), len(_HINGLISH.findall(text))
    if ta >= 2 and ta > hi:
        return "ta"
    if hi >= 2 and hi > ta:
        return "hi"
    return "en"


_OTP_CODE = re.compile(r"(otp|ओटीपी|ஓடிபி|one[- ]time password|verification code).{0,40}\d{4,8}|\d{4,8}.{0,40}(otp|ओटीपी|ஓடிபி|one[- ]time password|verification code)", re.I | re.S)
_DO_NOT_SHARE = re.compile(
    r"(do not|don'?t|never|not to) (share|disclose|tell|give)|share (na|mat) |किसी (को|के साथ).{0,20}(न|ना|मत) |साझा न|शेयर न|बताएं नहीं|"
    r"யாரிடமும்.{0,20}(பகிர|சொல்ல)|பகிராத|பகிர வேண்டாம்|yaar ?(kitta|kittayum|idamum).{0,15}(sollaadh|solla vendaam|share panna)|kisi ko (na|mat|nahi)",
    re.I | re.S)
_ALERT_ASKS = re.compile(
    r"https?://|www\.|bit\.ly|\.(com|in|xyz|top|test)\b|\b(except|only to|asked|asking|wants?|tell it|maang\w*|kett\w*|click|tap|call|called|contact|reply|send|pay|install|download|forward|anuppu|sollunga|bhejo|bhejiye|batao|bataiye)\b|"
    r"कॉल कर|संपर्क|क्लिक|भेजें|बताएं\b|அழைக்க|அனுப்பு|கிளிக்|சொல்லுங்",
    re.I)


def mentions_otp_warning(text):
    """Someone describing an OTP alert that carries a do-not-share warning."""
    text = text or ""
    return bool(re.search(r"\botp\b|ओटीपी|ஓடிபி", text, re.I) and _DO_NOT_SHARE.search(text)
                and not _ALERT_ASKS.search(text))


def is_plain_otp_alert(text):
    """A code plus a do-not-share warning, asking for nothing. Harmless by construction."""
    text = text or ""
    return bool(_OTP_CODE.search(text) and _DO_NOT_SHARE.search(text) and not _ALERT_ASKS.search(text))


def evaluate(features, lang="en", model_verdict=None, model_failed=False, otp_alert=False):
    """Turn features, and optionally the model's own verdict, into a final verdict.

    Missing a scam is worse than an extra warning, so "no warning signs" needs real
    agreement: no concrete sign at all, and a working model that does not object.
    A bare authority mention does not count as a sign on its own.
    """
    lang = lang if lang in ("en", "ta", "hi") else "en"
    hard_hits = [f for f in HARD if features.get(f)]
    soft_hits = [f for f in SOFT if features.get(f)]
    signs = [f for f in soft_hits if f != "authority_claim"]
    # Real companies send offers with links too. On its own, that is "check it", not "scam".
    just_an_offer = features.get("promo_offer") and not hard_hits and not any(
        features.get(f) for f in ("money_request", "install_app", "urgency", "kyc_update",
                                  "prize_job", "secrecy", "unknown_sender"))
    impersonation = features.get("unknown_sender") and any(
        features.get(f) for f in ("kyc_update", "authority_claim", "link", "money_request"))
    if just_an_offer:
        verdict = "not_sure"
    elif hard_hits or len(soft_hits) >= 3 or impersonation or (model_verdict == "scam" and signs):
        verdict = "likely_scam"
    elif signs or len(soft_hits) >= 2 or model_verdict in ("scam", "unsure") or model_failed:
        verdict = "not_sure"
    else:
        verdict = "likely_fine"
    triggered = hard_hits + ["promo_offer"] * bool(features.get("promo_offer")) + [f for f in soft_hits if f != "promo_offer"]
    reasons = []
    for f in triggered:
        r = REASONS[f]
        # Only cite the KYC advisory when the message is actually about KYC.
        src = SOURCES["RBI-KYC" if f == "link" and features.get("kyc_update") else r["source"]]
        reasons.append({
            "feature": f,
            "text": r[lang],
            "source_label": src["label"],
            "source_tier": src["tier"],
            "source_url": src["url"],
        })
    if model_verdict == "scam" and not hard_hits and not signs:
        src = SOURCES["AI-MODEL"]
        reasons.append({
            "feature": "model_verdict",
            "text": MODEL_REASON[lang],
            "source_label": src["label"],
            "source_tier": src["tier"],
            "source_url": src["url"],
        })
    steps = NEXT_STEPS[verdict]
    offer_only = bool(just_an_offer)
    otp_fine = otp_alert and verdict == "likely_fine"
    if otp_fine:
        src = SOURCES["POLICE-OTP"]
        reasons.append({"feature": "otp_alert", "text": OTP_REASON[lang], "source_label": src["label"],
                        "source_tier": src["tier"], "source_url": src["url"]})
    return {
        "verdict": verdict,
        "verdict_text": VERDICTS[verdict][lang],
        "reasons": reasons,
        "next_steps": OTP_STEPS[lang] if otp_fine else OFFER_STEPS[lang] if offer_only else steps[lang],
        # Nothing has gone wrong yet, so reporting to 1930 would be overkill here.
        "can_report": verdict != "likely_fine" and not offer_only,
        "next_steps_source": SOURCES[steps["source"]]["label"],
        "lang": lang,
        "hard_hits": hard_hits,
        "soft_hits": soft_hits,
    }


if __name__ == "__main__":
    demo = "This is CBI. A case is filed. You will be arrested. Share your OTP now and install AnyDesk."
    feats, ev = lexicon_features(demo)
    print(evaluate(feats)["verdict_text"], [f for f, v in feats.items() if v])
    safe = "Your OTP is 482913. Do not share this OTP with anyone. - HDFC Bank"
    feats, ev = lexicon_features(safe)
    print(evaluate(feats)["verdict_text"], [f for f, v in feats.items() if v])
