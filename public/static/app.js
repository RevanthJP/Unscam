const $ = (id) => document.getElementById(id);
const hero = document.querySelector(".hero");
const capture = $("capture"), result = $("result"), statusEl = $("status"), timerEl = $("timer"), errorEl = $("error"), mic = $("micBtn");

const TEXT = {
  en: { why: "Why", unclear: "We could not find a clear sign either way, so please check it yourself before acting.", none: "Nothing here asks for money, an OTP or your details, and there are no threats.", steps: "What to do now", heard: "What we heard", call: "Call 1930", report: "Report online", family: "Send to family", risk: ["Risk: low", "Risk: unclear", "Risk: high"], fix: "Not what you said? Fix it and check again" },
  ta: { why: "ஏன்", unclear: "எந்த பக்கமும் தெளிவான அறிகுறி கிடைக்கவில்லை. செயல்படும் முன் நீங்களே சரிபார்க்கவும்.", none: "இதில் பணம், OTP அல்லது உங்கள் விவரங்கள் கேட்கப்படவில்லை, மிரட்டலும் இல்லை.", steps: "இப்போது என்ன செய்ய வேண்டும்", heard: "நாங்கள் கேட்டது", call: "1930 ஐ அழைக்கவும்", report: "ஆன்லைனில் புகார்", family: "குடும்பத்திற்கு அனுப்பு", risk: ["ஆபத்து: குறைவு", "ஆபத்து: தெளிவில்லை", "ஆபத்து: அதிகம்"], fix: "நீங்கள் சொன்னது இது இல்லையா? திருத்தி மீண்டும் சரிபார்க்கவும்" },
  hi: { why: "क्यों", unclear: "किसी भी तरफ कोई साफ संकेत नहीं मिला। कुछ करने से पहले खुद जांच लें।", none: "इसमें पैसे, OTP या आपकी जानकारी नहीं मांगी गई है, और कोई धमकी नहीं है।", steps: "अब क्या करें", heard: "हमने क्या सुना", call: "1930 पर कॉल करें", report: "ऑनलाइन शिकायत", family: "परिवार को भेजें", risk: ["जोखिम: कम", "जोखिम: साफ नहीं", "जोखिम: ज़्यादा"], fix: "आपने यह नहीं कहा? ठीक करके फिर जांचें" },
};
const SOURCE_NOTE = { official: "official source", reported: "advisory as reported in the news", heuristic: "no specific source checked" };
const BADGE = { likely_scam: "!", not_sure: "?", likely_fine: "✓" };
const MAX_SECONDS = 90;

// Headline cycles through scripts, which shows the point without listing anything.
const HEADLINES = ["Is this safe?", "क्या यह सुरक्षित है?", "இது பாதுகாப்பானதா?"];
let hi = 0;
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const headline = $("headline");

// Keep the headline on one line and shrink it to fit, so no script is ever cut off.
function fitHeadline() {
  headline.style.fontSize = "";
  const range = document.createRange();
  range.selectNodeContents(headline);
  const room = (headline.clientWidth - 8) * 0.97;
  const need = range.getBoundingClientRect().width;
  if (need > room) {
    const base = parseFloat(getComputedStyle(headline).fontSize);
    headline.style.fontSize = Math.floor(base * (room / need)) + "px";
  }
}
addEventListener("resize", fitHeadline);
// Script fonts load only on first use and are wider than the fallback, so load them up front and re-fit on arrival.
if (document.fonts) {
  document.fonts.addEventListener && document.fonts.addEventListener("loadingdone", fitHeadline);
  Promise.all([
    document.fonts.load('600 48px "Noto Sans Tamil"', "இது"),
    document.fonts.load('600 48px "Noto Sans Devanagari"', "क्या"),
    document.fonts.load('600 48px "Inter"', "Is"),
  ]).then(fitHeadline).catch(() => {});
}
fitHeadline();

if (!reduced) setInterval(() => {
  headline.classList.add("swap");
  setTimeout(() => {
    hi = (hi + 1) % HEADLINES.length;
    headline.textContent = HEADLINES[hi];
    fitHeadline();
    headline.classList.remove("swap");
  }, 350);
}, 3600);

function setState(s) {
  capture.classList.remove("recording", "checking");
  if (s) capture.classList.add(s);
  mic.disabled = s === "checking";
  mic.setAttribute("aria-label", s === "recording" ? "Stop and check" : "Start speaking");
  $("alts").hidden = !!s;
  $("alts").style.display = s ? "none" : "";
  timerEl.hidden = s !== "recording";
}
function showError(msg) { errorEl.textContent = msg; errorEl.hidden = false; }
function clearError() { errorEl.hidden = true; }

/* ---------- sound wave ---------- */
function buildWave() {
  const wave = $("wave");
  const count = innerWidth < 600 ? 34 : innerWidth < 1100 ? 64 : 96;
  const bars = [];
  for (let i = 0; i < count; i++) {
    const x = i / (count - 1);                 // 0 to 1 across the screen
    const edge = Math.sin(Math.PI * x) ** 0.6; // calm at the screen edges
    const ripple = 0.35 + 0.65 * Math.abs(Math.sin(x * 23) * Math.cos(x * 7.5));
    const hue = x < 0.5 ? "#0071E3" : "#D9681E";
    const bar = document.createElement("i");
    bar.style.cssText = `--h:${(0.1 + 0.5 * edge * ripple).toFixed(3)};--c:${hue};--v:${(0.5 + 1.1 * ripple).toFixed(2)}`;
    bars.push(bar);
  }
  wave.replaceChildren(...bars);
}
buildWave();
let waveWidth = innerWidth;
addEventListener("resize", () => { if (Math.abs(innerWidth - waveWidth) > 120) { waveWidth = innerWidth; buildWave(); } });

/* ---------- recording ---------- */
let voiced = 0, metered = false;
let rec = null, stream = null, chunks = [], tick = null, raf = null, audioCtx = null, startedAt = 0;

function pickMime() {
  for (const m of ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg;codecs=opus"]) {
    if (window.MediaRecorder && MediaRecorder.isTypeSupported(m)) return m;
  }
  return "";
}
function extFor(type) { return type.includes("mp4") ? "m4a" : type.includes("ogg") ? "ogg" : "webm"; }

async function startRecording() {
  clearError();
  if (!navigator.mediaDevices || !window.MediaRecorder) {
    showError("This browser cannot record here. Please type it or upload a voice note.");
    return;
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    showError("We need microphone permission to listen. You can allow it in your browser, or type it instead.");
    return;
  }
  const mime = pickMime();
  chunks = [];
  rec = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
  rec.ondataavailable = (e) => { if (e.data.size) chunks.push(e.data); };
  rec.onstop = () => {
    const type = rec.mimeType || mime || "audio/webm";
    cleanupStream();
    const blob = new Blob(chunks, { type });
    if ((Date.now() - startedAt) < 700 || !blob.size) {
      setState(null); statusEl.textContent = "Tap and start talking";
      showError("That was too short. Tap, say what happened, then tap again.");
      return;
    }
    // Silence never reaches the server, so it costs no API call and invents no words.
    if (metered && voiced < 8) {
      setState(null); statusEl.textContent = "Tap and start talking";
      showError("We could not hear you. Check your microphone and try again, or type it instead.");
      return;
    }
    sendAudio(blob, "recording." + extFor(type));
  };
  voiced = 0;
  metered = false;
  rec.start();
  startedAt = Date.now();
  setState("recording");
  statusEl.textContent = "Listening... tap when you finish";
  timerEl.textContent = "0:00";
  tick = setInterval(() => {
    const s = Math.floor((Date.now() - startedAt) / 1000);
    timerEl.textContent = Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    if (s >= MAX_SECONDS) stopRecording();
  }, 250);
  meter(stream);
}
function stopRecording() { if (rec && rec.state === "recording") rec.stop(); }
function cleanupStream() {
  clearInterval(tick); cancelAnimationFrame(raf);
  if (stream) stream.getTracks().forEach((t) => t.stop());
  if (audioCtx) audioCtx.close().catch(() => {});
  stream = null; audioCtx = null; mic.style.setProperty("--level", 0); $("wave").style.setProperty("--level", 0);
}
function meter(s) {
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const an = audioCtx.createAnalyser();
    an.fftSize = 512;
    audioCtx.createMediaStreamSource(s).connect(an);
    const buf = new Uint8Array(an.fftSize);
    const loop = () => {
      an.getByteTimeDomainData(buf);
      let sum = 0;
      for (const v of buf) sum += ((v - 128) / 128) ** 2;
      const level = Math.min(1, Math.sqrt(sum / buf.length) * 4).toFixed(3);
      metered = true;
      if (level > 0.09) voiced++;
      mic.style.setProperty("--level", level);
      $("wave").style.setProperty("--level", level);
      raf = requestAnimationFrame(loop);
    };
    loop();
  } catch (e) { /* the rings are decoration; recording still works */ }
}

mic.addEventListener("click", () => {
  if (capture.classList.contains("recording")) stopRecording();
  else if (!capture.classList.contains("checking")) startRecording();
});

/* ---------- sending ---------- */
async function post(url, options) {
  setState("checking");
  statusEl.textContent = "Checking...";
  clearError();
  try {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Something went wrong. Please try again.");
    render(data);
  } catch (e) {
    const offline = e instanceof TypeError;
    showError(offline ? "We could not reach the server. Check your connection and try again." : e.message);
  } finally {
    setState(null);
    statusEl.textContent = "Tap and start talking";
  }
}
function sendAudio(blob, name) {
  const fd = new FormData();
  fd.append("file", blob, name);
  post("/api/check-audio", { method: "POST", body: fd });
}
function sendText(text) {
  post("/api/check-text", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
}

$("exToggle").addEventListener("click", () => {
  const ex = $("examples");
  ex.hidden = !ex.hidden;
  $("exToggle").setAttribute("aria-expanded", String(!ex.hidden));
});
$("typeToggle").addEventListener("click", () => {
  const f = $("typedForm");
  f.hidden = !f.hidden;
  if (!f.hidden) $("typed").focus();
});
$("typedForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const t = $("typed").value.trim();
  if (!t) { showError("Please type or paste something first."); return; }
  sendText(t);
});
$("fileInput").addEventListener("change", (e) => {
  const f = e.target.files[0];
  if (f && f.size > 4 * 1024 * 1024) showError("That recording is too large. Please keep it under 4 MB, or type it instead.");
  else if (f) sendAudio(f, f.name);
  e.target.value = "";
});
document.querySelectorAll("[data-ex]").forEach((b) => b.addEventListener("click", () => sendText(b.dataset.ex)));

/* ---------- result ---------- */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function linkBtn(cls, href, label, blank) {
  const a = el("a", cls, label);
  a.href = href;
  if (blank) { a.target = "_blank"; a.rel = "noopener"; }
  return a;
}
const LANG_NAME = { en: "English", ta: "தமிழ்", hi: "हिन्दी" };
let current = null;

function paint(lang) {
  const d = current;
  const c = d.translations[lang];
  const t = TEXT[lang] || TEXT.en;
  document.documentElement.lang = lang;
  $("verdictText").textContent = c.verdict_text;
  const level = { likely_fine: 0, not_sure: 1, likely_scam: 2 }[d.verdict];
  $("meter").dataset.level = level;
  $("meterLabel").textContent = t.risk[level];
  $("meter").setAttribute("aria-label", t.risk[level]);

  $("heardLabel").textContent = t.heard;
  $("fixHeard").textContent = t.fix;
  $("whyLabel").textContent = t.why;
  const list = $("reasons");
  list.replaceChildren();
  if (!c.reasons.length) list.append(el("li", "", d.verdict === "likely_fine" ? t.none : t.unclear));
  for (const r of c.reasons) {
    const li = el("li", "", r.text);
    const note = SOURCE_NOTE[r.source_tier];
    const label = r.source_label.replace(" (as reported)", "") + (note ? " · " + note : "");
    const src = el("span", "src");
    if (r.source_url) { const a = linkBtn("", r.source_url, label, true); src.append(a); } else src.textContent = label;
    li.append(src);
    list.append(li);
  }

  $("stepsLabel").textContent = t.steps;
  $("steps").replaceChildren(...c.next_steps.map((s) => el("li", "", s)));

  const actions = $("actions");
  actions.replaceChildren();
  if (d.can_report) {
    actions.append(linkBtn("a-primary", "tel:1930", t.call), linkBtn("a-second", "https://cybercrime.gov.in", t.report, true));
  }
  const share = c.verdict_text + "\n" + c.next_steps.join("\n");
  if (d.verdict !== "likely_fine") actions.append(linkBtn("a-ghost", "https://wa.me/?text=" + encodeURIComponent(share), t.family, true));
  $("langs").querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === lang)));
}

function render(d) {
  current = d;
  result.className = "result v-" + d.verdict;
  $("badgeMark").textContent = BADGE[d.verdict];

  $("heardBox").hidden = !d.transcript;
  $("heard").textContent = d.transcript || "";

  // Switching language reuses the text already received, so it costs no API call.
  const langs = $("langs");
  const codes = Object.keys(d.translations);
  langs.replaceChildren();
  langs.hidden = codes.length < 2;
  if (codes.length > 1) {
    for (const code of [d.lang, "en"]) {
      const b = el("button", "", LANG_NAME[code]);
      b.type = "button";
      b.dataset.lang = code;
      b.addEventListener("click", () => {
        result.classList.add("swapping");
        setTimeout(() => { paint(code); result.classList.remove("swapping"); }, 160);
      });
      langs.append(b);
    }
  }
  paint(d.lang);

  $("degraded").hidden = !d.ai_unavailable;
  capture.hidden = true;
  capture.style.display = "none";
  result.hidden = false;
  hero.classList.add("has-result");
  document.body.classList.add("showing-result");
  document.querySelector(".hero-copy").style.display = "none";
  window.scrollTo({ top: 0 });
  result.focus({ preventScroll: true });
}
$("fixHeard").addEventListener("click", () => {
  const said = current && current.transcript;
  $("again").click();
  $("typedForm").hidden = false;
  $("typed").value = said || "";
  $("typed").focus();
});
$("again").addEventListener("click", () => {
  result.hidden = true;
  capture.hidden = false;
  capture.style.display = "";
  hero.classList.remove("has-result");
  document.body.classList.remove("showing-result");
  document.querySelector(".hero-copy").style.display = "";
  document.documentElement.lang = "en";
  $("typed").value = "";
  $("typedForm").hidden = true;
  clearError();
  window.scrollTo({ top: 0 });
});

/* ---------- motion ---------- */
// Sections fade up once as they enter view. Cards in a row arrive slightly staggered.
const revealed = document.querySelectorAll(".band h2, .watch>p, .watch>div>p, .how-grid li, .flags, .fact-text, .fact-art");
document.querySelectorAll(".how-grid li").forEach((li, i) => li.style.setProperty("--d", i * 0.12 + "s"));
revealed.forEach((n) => n.classList.add("reveal"));
function countUp(node) {
  const target = +node.dataset.count;
  const start = performance.now(), length = 1300;
  (function step(now) {
    const p = Math.min(1, (now - start) / length);
    node.textContent = Math.round(target * (1 - (1 - p) ** 3)).toLocaleString("en-IN");
    if (p < 1) requestAnimationFrame(step);
  })(start);
}
if ("IntersectionObserver" in window && !reduced) {
  // Plays every time a section enters view, scrolling down or back up.
  const io = new IntersectionObserver((entries) => entries.forEach((e) => {
    const n = e.target;
    if (e.isIntersecting) {
      n.classList.remove("above");
      n.classList.add("in");
      // The statistic plays once only, in either direction.
      if (n.closest(".fact")) {
        const c = n.querySelector("[data-count]");
        if (c) countUp(c);
        io.unobserve(n);
      }
    } else {
      n.classList.remove("in");
      // Left through the top, so it should come back moving downward.
      n.classList.toggle("above", e.boundingClientRect.top < 0);
    }
  }), { threshold: 0.15 });
  revealed.forEach((n) => io.observe(n));
} else {
  revealed.forEach((n) => n.classList.add("in"));
}
