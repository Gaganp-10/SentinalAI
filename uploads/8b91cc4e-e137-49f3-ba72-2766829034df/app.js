(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const nowMs = () => Date.now();

  const els = {
    authScreen: $("authScreen"),
    appShell: $("appShell"),
    authForm: $("authForm"),
    tabLogin: $("tabLogin"),
    tabRegister: $("tabRegister"),
    authName: $("authName"),
    authPhone: $("authPhone"),
    authPassword: $("authPassword"),
    authSubmit: $("authSubmit"),
    authMessage: $("authMessage"),

    greetingTitle: $("greetingTitle"),
    greetingSubtitle: $("greetingSubtitle"),
    brandSubtitle: $("brandSubtitle"),
    mic: $("btnMic"),
    micLabel: $("micLabel"),
    micHint: $("micHint"),
    statusLine: $("statusLine"),
    btnMedicine: $("btnMedicine"),
    btnEmergency: $("btnEmergency"),
    btnGrocery: $("btnGrocery"),
    btnActivity: $("btnActivity"),
    btnLanguage: $("btnLanguage"),
    btnSound: $("btnSound"),
    btnLogout: $("btnLogout"),
    chatList: $("chatList"),

    medicineBtnSub: $("medicineBtnSub"),
    emergencyBtnSub: $("emergencyBtnSub"),

    homeNextValue: $("homeNextValue"),
    homeLastValue: $("homeLastValue"),

    medicineModal: $("medicineModal"),
    emergencyModal: $("emergencyModal"),
    languageModal: $("languageModal"),
    groceryModal: $("groceryModal"),
    activityModal: $("activityModal"),

    medTime: $("medTime"),
    btnSaveMedTime: $("btnSaveMedTime"),
    btnTookMed: $("btnTookMed"),
    nextMedValue: $("nextMedValue"),
    lastMedValue: $("lastMedValue"),

    btnCallHelp: $("btnCallHelp"),
    emergencyConfirm: $("emergencyConfirm"),

    langEn: $("langEn"),
    langHi: $("langHi"),
    langKn: $("langKn"),

    groceryQueryValue: $("groceryQueryValue"),
    blinkitLink: $("blinkitLink"),
    zeptoLink: $("zeptoLink"),
    activityList: $("activityList"),
    activityProgressValue: $("activityProgressValue"),
    activityInput: $("activityInput"),
    activityTimeSelect: $("activityTimeSelect"),
    btnAddActivity: $("btnAddActivity"),
    btnResetActivities: $("btnResetActivities"),
    oneTapGrid: $("oneTapGrid"),
    aiRecs: $("aiRecs"),
    nearbyFast: $("nearbyFast"),
    recentOrders: $("recentOrders"),
    smartOrderModal: $("smartOrderModal"),
    smartDetected: $("smartDetected"),
    smartUrgency: $("smartUrgency"),
    smartCategory: $("smartCategory"),
    smartProducts: $("smartProducts"),
    smartPlatforms: $("smartPlatforms"),
    btnOneTapCheckout: $("btnOneTapCheckout"),
    btnAddCart: $("btnAddCart"),
  };

  const STORAGE = {
    name: "sahay.userName",
    users: "sahay.users",
    sessionPhone: "sahay.session.phone",
    lang: "sahay.lang",
    sound: "sahay.soundOn",
    medTime: "sahay.medTime",
    medLastTaken: "sahay.medLastTaken",
    doubtState: "sahay.doubtState",
    groceryLastItem: "sahay.groceryLastItem",
    dailyActivities: "sahay.daily.activities",
    dailyActivityPlans: "sahay.daily.activity.plans",
    recentOrders: "sahay.orders.recent",
    habitStats: "sahay.orders.habits",
  };

  const DEFAULTS = {
    userName: "Friend",
    lang: "en",
    soundOn: true,
    medTime: "09:00",
  };

  const LANGS = {
    en: { label: "English", speech: "en-IN" },
    hi: { label: "हिंदी", speech: "hi-IN" },
    kn: { label: "ಕನ್ನಡ", speech: "kn-IN" },
  };

  function safeJsonParse(value, fallback) {
    try {
      if (!value) return fallback;
      return JSON.parse(value);
    } catch {
      return fallback;
    }
  }

  function getSetting(key, fallback) {
    const v = localStorage.getItem(key);
    if (v === null || v === undefined) return fallback;
    return v;
  }

  function setSetting(key, value) {
    localStorage.setItem(key, value);
  }

  function getBool(key, fallback) {
    const v = getSetting(key, fallback ? "1" : "0");
    return v === "1" || v === "true";
  }

  function setBool(key, value) {
    setSetting(key, value ? "1" : "0");
  }

  function formatTimeForUser(date, lang) {
    try {
      return new Intl.DateTimeFormat(lang === "en" ? "en-IN" : lang === "hi" ? "hi-IN" : "kn-IN", {
        hour: "numeric",
        minute: "2-digit",
      }).format(date);
    } catch {
      const h = String(date.getHours()).padStart(2, "0");
      const m = String(date.getMinutes()).padStart(2, "0");
      return `${h}:${m}`;
    }
  }

  function formatDateTimeForUser(date, lang) {
    try {
      return new Intl.DateTimeFormat(lang === "en" ? "en-IN" : lang === "hi" ? "hi-IN" : "kn-IN", {
        weekday: "short",
        hour: "numeric",
        minute: "2-digit",
      }).format(date);
    } catch {
      return date.toLocaleString();
    }
  }

  function clamp(n, a, b) {
    return Math.max(a, Math.min(b, n));
  }

  const copy = {
    en: {
      brandSubtitle: "A calm companion",
      greetingTitle: (name) => `Hello ${name} 👋`,
      greetingSubtitle: "How are you today?",
      micLabelIdle: "Click to Speak",
      micLabelListening: "Listening…",
      micHint: "You can say: “Did I take my medicine?” or “Help”.",
      statusReady: "Ready.",
      statusNoSpeech: "I didn’t hear that. Please try again.",
      statusNotSupported: "Voice is not supported in this browser.",
      statusPermission: "Please allow microphone access.",
      medicineSub: "Check next time",
      emergencySub: "Call for help",
      said: "You said",
      helpConfirm: "Alert sent to family. Stay calm. I’m here with you.",
      helpConfirmShort: "Alert sent.",
      helpPrompt: "I can call for help now.",
      medicineSet: "Okay. I will remind you every day at",
      medicineTaken: "Okay. I saved it. You took your medicine at",
      medicineNoneTaken: "I don’t see a saved time yet. If you just took it, press “I took my medicine”.",
      medicineLastTaken: (t) => `Yes. You took your medicine at ${t}.`,
      medicineNotToday: (t) => `I last saved it at ${t}. If you took it again today, press “I took my medicine”.`,
      reassurance: "You already checked this. Everything is okay.",
      askGrocery: "Tell me what you need. For example: “I need milk.”",
      grocerySaved: (item) => `Okay. I can help you open a grocery search for ${item}.`,
      unknown: "I’m here. You can ask about your medicine, or say “Help”.",
      voiceOn: "Voice: On",
      voiceOff: "Voice: Off",
      activitySub: "A calm routine for today",
      activitySummary: (done, total) => `Today’s activities: ${done} of ${total} completed.`,
      activityPrompt: "I opened your daily activities. Small steps. No pressure.",
    },
    hi: {
      brandSubtitle: "शांत साथी",
      greetingTitle: (name) => `नमस्ते ${name} 👋`,
      greetingSubtitle: "आज आप कैसे हैं?",
      micLabelIdle: "बोलने के लिए दबाएँ",
      micLabelListening: "सुन रही हूँ…",
      micHint: "आप कह सकते हैं: “क्या मैंने दवा ली?” या “मदद”.",
      statusReady: "तैयार हूँ।",
      statusNoSpeech: "मैंने नहीं सुना। कृपया फिर से बोलें।",
      statusNotSupported: "इस ब्राउज़र में आवाज़ समर्थित नहीं है।",
      statusPermission: "कृपया माइक्रोफोन की अनुमति दें।",
      medicineSub: "अगला समय देखें",
      emergencySub: "मदद बुलाएँ",
      said: "आपने कहा",
      helpConfirm: "परिवार को संदेश भेज दिया है। शांत रहें। मैं आपके साथ हूँ।",
      helpConfirmShort: "संदेश भेज दिया।",
      helpPrompt: "मैं अभी मदद बुला सकती हूँ।",
      medicineSet: "ठीक है। मैं हर दिन याद दिलाऊँगी",
      medicineTaken: "ठीक है। मैंने सेव कर लिया। आपने दवा ली",
      medicineNoneTaken: "मेरे पास अभी कोई समय सेव नहीं है। अगर आपने अभी दवा ली है, “मैंने दवा ली” दबाएँ।",
      medicineLastTaken: (t) => `हाँ। आपने दवा ${t} बजे ली थी।`,
      medicineNotToday: (t) => `मैंने आख़िरी बार ${t} पर सेव किया था। अगर आपने आज फिर ली है, “मैंने दवा ली” दबाएँ।`,
      reassurance: "आपने अभी यही देखा था। सब ठीक है।",
      askGrocery: "बताइए आपको क्या चाहिए। जैसे: “मुझे दूध चाहिए।”",
      grocerySaved: (item) => `ठीक है। मैं ${item} के लिए ग्रोसरी खोज खोल सकती हूँ।`,
      unknown: "मैं यहीं हूँ। आप दवा के बारे में पूछ सकते हैं, या “मदद” कह सकते हैं।",
      voiceOn: "आवाज़: चालू",
      voiceOff: "आवाज़: बंद",
      activitySub: "आज के लिए शांत दिनचर्या",
      activitySummary: (done, total) => `आज की गतिविधियाँ: ${total} में से ${done} पूरी हुईं।`,
      activityPrompt: "मैंने आपकी आज की गतिविधियाँ खोल दी हैं। धीरे-धीरे, बिना दबाव।",
    },
    kn: {
      brandSubtitle: "ಶಾಂತ ಸಂಗಾತಿ",
      greetingTitle: (name) => `ನಮಸ್ಕಾರ ${name} 👋`,
      greetingSubtitle: "ಇಂದು ನೀವು ಹೇಗಿದ್ದೀರಾ?",
      micLabelIdle: "ಮಾತನಾಡಲು ಒತ್ತಿರಿ",
      micLabelListening: "ಕೇಳುತ್ತಿದ್ದೇನೆ…",
      micHint: "ನೀವು ಹೇಳಬಹುದು: “ನಾನು ಔಷಧಿ ತೆಗೆದೆನಾ?” ಅಥವಾ “ಸಹಾಯ”.",
      statusReady: "ಸಿದ್ಧವಾಗಿದೆ.",
      statusNoSpeech: "ನಾನು ಕೇಳಲಿಲ್ಲ. ದಯವಿಟ್ಟು ಮತ್ತೆ ಹೇಳಿ.",
      statusNotSupported: "ಈ ಬ್ರೌಸರ್‌ನಲ್ಲಿ ಧ್ವನಿ ಬೆಂಬಲ ಇಲ್ಲ.",
      statusPermission: "ದಯವಿಟ್ಟು ಮೈಕ್ರೋಫೋನ್ ಅನುಮತಿ ನೀಡಿ.",
      medicineSub: "ಮುಂದಿನ ಸಮಯ ನೋಡಿ",
      emergencySub: "ಸಹಾಯ ಕರೆ",
      said: "ನೀವು ಹೇಳಿದರು",
      helpConfirm: "ಕುಟುಂಬಕ್ಕೆ ಸಂದೇಶ ಕಳಿಸಲಾಗಿದೆ. ಶಾಂತವಾಗಿರಿ. ನಾನು ನಿಮ್ಮ ಜೊತೆ ಇದ್ದೇನೆ.",
      helpConfirmShort: "ಸಂದೇಶ ಕಳಿಸಲಾಗಿದೆ.",
      helpPrompt: "ನಾನು ಈಗ ಸಹಾಯ ಕರೆಯಬಹುದು.",
      medicineSet: "ಸರಿ. ನಾನು ಪ್ರತಿ ದಿನ ನೆನಪಿಸುತೇನೆ",
      medicineTaken: "ಸರಿ. ನಾನು ಉಳಿಸಿದ್ದೇನೆ. ನೀವು ಔಷಧಿ ತೆಗೆದುಕೊಂಡ ಸಮಯ",
      medicineNoneTaken: "ನಾನು ಇನ್ನೂ ಸಮಯ ಉಳಿಸಿಲ್ಲ. ಈಗ ತೆಗೆದುಕೊಂಡಿದ್ದರೆ “ನಾನು ಔಷಧಿ ತೆಗೆದುಕೊಂಡೆ” ಒತ್ತಿರಿ.",
      medicineLastTaken: (t) => `ಹೌದು. ನೀವು ${t}ಕ್ಕೆ ಔಷಧಿ ತೆಗೆದುಕೊಂಡಿದ್ದೀರಿ.`,
      medicineNotToday: (t) => `ನಾನು ಕೊನೆಯದಾಗಿ ${t}ಕ್ಕೆ ಉಳಿಸಿದ್ದೇನೆ. ಇಂದು ಮತ್ತೆ ತೆಗೆದುಕೊಂಡಿದ್ದರೆ “ನಾನು ಔಷಧಿ ತೆಗೆದುಕೊಂಡೆ” ಒತ್ತಿರಿ.`,
      reassurance: "ನೀವು ಈಗಾಗಲೇ ಇದನ್ನು ಪರಿಶೀಲಿಸಿದ್ದೀರಿ. ಎಲ್ಲವೂ ಚೆನ್ನಾಗಿದೆ.",
      askGrocery: "ನಿಮಗೆ ಏನು ಬೇಕು ಹೇಳಿ. ಉದಾಹರಣೆ: “ನನಗೆ ಹಾಲು ಬೇಕು.”",
      grocerySaved: (item) => `ಸರಿ. ${item}ಗಾಗಿ ಗ್ರಾಸರಿ ಹುಡುಕಾಟವನ್ನು ತೆರೆಯಬಹುದು.`,
      unknown: "ನಾನು ಇಲ್ಲೇ ಇದ್ದೇನೆ. ಔಷಧಿ ಬಗ್ಗೆ ಕೇಳಿ ಅಥವಾ “ಸಹಾಯ” ಹೇಳಿ.",
      voiceOn: "ಧ್ವನಿ: ಆನ್",
      voiceOff: "ಧ್ವನಿ: ಆಫ್",
      activitySub: "ಇಂದಿನ ಶಾಂತ ದಿನಚರಿ",
      activitySummary: (done, total) => `ಇಂದಿನ ಚಟುವಟಿಕೆಗಳು: ${total}ರಲ್ಲಿ ${done} ಪೂರ್ಣಗೊಂಡಿವೆ.`,
      activityPrompt: "ನಾನು ನಿಮ್ಮ ಇಂದಿನ ಚಟುವಟಿಕೆಗಳನ್ನು ತೆರೆದಿದ್ದೇನೆ. ನಿಧಾನವಾಗಿ, ಒತ್ತಡ ಬೇಡ.",
    },
  };

  const state = {
    userName: getSetting(STORAGE.name, DEFAULTS.userName),
    authMode: "login",
    lang: getSetting(STORAGE.lang, DEFAULTS.lang),
    soundOn: getBool(STORAGE.sound, DEFAULTS.soundOn),
    listening: false,
    recognition: null,
    lastIntent: { key: null, at: 0, repeats: 0 },
    currentSmartOrder: null,
  };

  const ONE_TAP_PRESETS = [
    { label: "Order Milk", query: "I need milk" },
    { label: "Buy Medicines", query: "Order medicine" },
    { label: "Get Groceries", query: "Get groceries" },
    { label: "Order Fruits", query: "Buy apples and bananas" },
    { label: "Food Delivery", query: "Need food" },
    { label: "Emergency Medicine", query: "Need emergency medicine" },
    { label: "Daily Essentials", query: "Get daily essentials" },
    { label: "Snacks & Drinks", query: "Order snacks and drinks" },
    { label: "Baby Care", query: "Need baby products" },
    { label: "Personal Care", query: "Need personal care items" },
  ];

  const PLATFORM_MAP = [
    { name: "Blinkit", etaMin: 16, type: "grocery", base: "https://blinkit.com/s/?q=" },
    { name: "Zepto", etaMin: 18, type: "grocery", base: "https://www.zepto.com/search?query=" },
    { name: "Swiggy Instamart", etaMin: 22, type: "grocery", base: "https://www.swiggy.com/instamart/search?query=" },
    { name: "BigBasket", etaMin: 55, type: "grocery", base: "https://www.bigbasket.com/ps/?q=" },
    { name: "Apollo Pharmacy", etaMin: 32, type: "medicine", base: "https://www.apollopharmacy.in/search-medicines/" },
    { name: "MedPlus", etaMin: 36, type: "medicine", base: "https://www.medplusmart.com/search?text=" },
    { name: "Amazon", etaMin: 130, type: "general", base: "https://www.amazon.in/s?k=" },
    { name: "Flipkart", etaMin: 150, type: "general", base: "https://www.flipkart.com/search?q=" },
  ];

  function currentUserKey() {
    return getSetting(STORAGE.sessionPhone, "guest");
  }

  function getUserScopedObject(storageKey) {
    return safeJsonParse(getSetting(storageKey, "{}"), {});
  }

  function getUserScopedValue(storageKey, fallback) {
    const all = getUserScopedObject(storageKey);
    const user = currentUserKey();
    return all[user] !== undefined ? all[user] : fallback;
  }

  function setUserScopedValue(storageKey, value) {
    const all = getUserScopedObject(storageKey);
    all[currentUserKey()] = value;
    setSetting(storageKey, JSON.stringify(all));
  }

  function t() {
    return copy[state.lang] || copy.en;
  }

  function setStatus(text) {
    els.statusLine.textContent = text || "";
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function addBubble(role, text, meta) {
    const wrap = document.createElement("div");
    wrap.className = `bubble ${role === "user" ? "bubble--user" : "bubble--ai"}`;
    wrap.innerHTML = `<div class="bubble__text">${escapeHtml(text)}</div>`;
    if (meta) {
      const m = document.createElement("div");
      m.className = "bubble__meta";
      m.textContent = meta;
      wrap.appendChild(m);
    }
    els.chatList.appendChild(wrap);
    els.chatList.scrollTop = els.chatList.scrollHeight;
  }

  function speak(text) {
    if (!state.soundOn) return;
    if (!("speechSynthesis" in window)) return;

    try {
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = (LANGS[state.lang] || LANGS.en).speech;
      u.rate = 0.85;
      u.pitch = 1.0;
      u.volume = 1.0;
      window.speechSynthesis.speak(u);
    } catch {
      // ignore
    }
  }

  function openModal(dialogEl) {
    if (!dialogEl) return;
    if (typeof dialogEl.showModal === "function") {
      dialogEl.showModal();
    } else {
      dialogEl.setAttribute("open", "open");
    }
  }

  function closeModal(dialogEl) {
    if (!dialogEl) return;
    if (typeof dialogEl.close === "function") {
      dialogEl.close();
    } else {
      dialogEl.removeAttribute("open");
    }
  }

  function isSameLocalDay(a, b) {
    return (
      a.getFullYear() === b.getFullYear() &&
      a.getMonth() === b.getMonth() &&
      a.getDate() === b.getDate()
    );
  }

  function getDailyTime() {
    const v = getSetting(STORAGE.medTime, DEFAULTS.medTime);
    if (typeof v !== "string" || !/^\d{2}:\d{2}$/.test(v)) return DEFAULTS.medTime;
    return v;
  }

  function setDailyTime(v) {
    if (typeof v !== "string" || !/^\d{2}:\d{2}$/.test(v)) return;
    setSetting(STORAGE.medTime, v);
  }

  function computeNextMedicineDate() {
    const time = getDailyTime();
    const [hh, mm] = time.split(":").map((x) => parseInt(x, 10));
    const d = new Date();
    const next = new Date(d);
    next.setHours(clamp(hh, 0, 23), clamp(mm, 0, 59), 0, 0);
    if (next.getTime() <= d.getTime()) {
      next.setDate(next.getDate() + 1);
    }
    return next;
  }

  function getLastTaken() {
    const raw = getSetting(STORAGE.medLastTaken, "");
    const ms = parseInt(raw, 10);
    if (!Number.isFinite(ms) || ms <= 0) return null;
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return null;
    return d;
  }

  function setLastTaken(date) {
    setSetting(STORAGE.medLastTaken, String(date.getTime()));
  }

  function updateMedicineUi() {
    const next = computeNextMedicineDate();
    const last = getLastTaken();
    els.nextMedValue.textContent = formatDateTimeForUser(next, state.lang);
    els.lastMedValue.textContent = last ? formatDateTimeForUser(last, state.lang) : "—";
    if (els.homeNextValue) els.homeNextValue.textContent = formatDateTimeForUser(next, state.lang);
    if (els.homeLastValue) els.homeLastValue.textContent = last ? formatDateTimeForUser(last, state.lang) : "—";
    els.medicineBtnSub.textContent = t().medicineSub;
    els.emergencyBtnSub.textContent = t().emergencySub;
    if (els.btnActivity) {
      const sub = els.btnActivity.querySelector("#activityBtnSub");
      if (sub) sub.textContent = t().activitySub;
    }
    els.medTime.value = getDailyTime();
  }

  function setLanguage(lang) {
    if (!LANGS[lang]) return;
    state.lang = lang;
    setSetting(STORAGE.lang, lang);
    renderStaticCopy();
    updateMedicineUi();
    updateSelectedLanguageUi();
  }

  function updateSelectedLanguageUi() {
    const selected = state.lang;
    [els.langEn, els.langHi, els.langKn].forEach((btn) => {
      if (!btn) return;
      const lang = btn.dataset.lang;
      btn.dataset.selected = lang === selected ? "true" : "false";
      btn.setAttribute("aria-pressed", lang === selected ? "true" : "false");
    });
  }

  function renderStaticCopy() {
    const C = t();
    els.brandSubtitle.textContent = C.brandSubtitle;
    els.greetingTitle.textContent = C.greetingTitle(state.userName);
    els.greetingSubtitle.textContent = C.greetingSubtitle;
    els.micLabel.textContent = state.listening ? C.micLabelListening : C.micLabelIdle;
    els.micHint.textContent = C.micHint;
    els.btnSound.textContent = state.soundOn ? C.voiceOn : C.voiceOff;
    els.btnSound.setAttribute("aria-pressed", state.soundOn ? "true" : "false");
    els.btnLanguage.textContent = state.lang ? `Language: ${LANGS[state.lang]?.label || "—"}` : "Language";
    setStatus(C.statusReady);
  }

  function setListening(on) {
    state.listening = on;
    els.mic.dataset.listening = on ? "true" : "false";
    els.mic.setAttribute("aria-pressed", on ? "true" : "false");
    els.micLabel.textContent = on ? t().micLabelListening : t().micLabelIdle;
  }

  function normalize(s) {
    return String(s || "")
      .trim()
      .replace(/\s+/g, " ")
      .toLowerCase();
  }

  function detectIntent(text) {
    const s = normalize(text);

    // Emergency voice triggers (English/Hindi/Kannada)
    const helpWords = [
      "help",
      "emergency",
      "call for help",
      "save me",
      "मदद",
      "बचाओ",
      "इमरजेंसी",
      "ಸಹಾಯ",
      "ಸಹಾಯ ಮಾಡಿ",
      "ತುರ್ತು",
    ];
    if (helpWords.some((w) => s.includes(normalize(w)))) {
      return { key: "emergency.help", slots: {} };
    }

    // Medicine status query
    const medStatusPhrases = [
      "did i take my medicine",
      "did i take medicine",
      "have i taken my medicine",
      "medicine taken",
      "medicine status",
      "did i take my tablet",
      "दवा ली",
      "क्या मैंने दवा ली",
      "क्या मैंने दवा ली है",
      "मैंने दवा ली",
      "ಔಷಧಿ ತೆಗೆದೆನಾ",
      "ನಾನು ಔಷಧಿ ತೆಗೆದುಕೊಂಡೆನಾ",
      "ನಾನು ಔಷಧಿ ತೆಗೆದೆ",
    ];
    if (medStatusPhrases.some((p) => s.includes(normalize(p)))) {
      return { key: "medicine.status", slots: {} };
    }

    // Medicine set time (simple "set medicine time to 9" isn't required; keep minimal)
    const medOpenPhrases = ["medicine", "दवा", "औषध", "ಔಷಧಿ"];
    if (medOpenPhrases.some((p) => s === normalize(p) || s.includes(`${normalize(p)} `))) {
      return { key: "ui.openMedicine", slots: {} };
    }

    const activityPhrases = [
      "today activity",
      "today activities",
      "daily activity",
      "daily routine",
      "today routine",
      "आज की गतिविधि",
      "आज की दिनचर्या",
      "ಇಂದಿನ ಚಟುವಟಿಕೆ",
      "ಇಂದಿನ ದಿನಚರಿ",
    ];
    if (activityPhrases.some((p) => s.includes(normalize(p)))) {
      return { key: "activity.open", slots: {} };
    }

    if (/\b(order|buy|get|add to cart|purchase|need)\b/.test(s) && /(milk|medicine|grocer|fruit|food|snack|baby|personal|essential)/.test(s)) {
      return { key: "shopping.smart", slots: { query: text } };
    }

    // Grocery intent (optional legacy path)
    const needMatch =
      s.match(/\b(i need|need|i want)\s+(.+)$/) ||
      s.match(/\b(mujhe|मुझे)\s+(.+)\s+(chahiye|चाहिए)\b/) ||
      s.match(/\b(nanage|ನನಗೆ)\s+(.+)\s+(beku|ಬೇಕು)\b/);
    if (needMatch) {
      const item = (needMatch[2] || "").trim();
      if (item && item.length <= 50) return { key: "shopping.smart", slots: { query: item } };
    }

    return { key: "unknown", slots: {} };
  }

  function doubtReassureIfNeeded(intentKey) {
    const windowMs = 10 * 60 * 1000; // 10 minutes
    const now = nowMs();
    if (state.lastIntent.key === intentKey && now - state.lastIntent.at <= windowMs) {
      state.lastIntent.repeats += 1;
    } else {
      state.lastIntent = { key: intentKey, at: now, repeats: 1 };
    }

    if (intentKey === "medicine.status" && state.lastIntent.repeats >= 3) {
      return t().reassurance;
    }
    return null;
  }

  function answerMedicineStatus() {
    const last = getLastTaken();
    if (!last) return t().medicineNoneTaken;

    const now = new Date();
    const time = formatTimeForUser(last, state.lang);

    if (isSameLocalDay(last, now)) {
      return t().medicineLastTaken(time);
    }
    return t().medicineNotToday(formatDateTimeForUser(last, state.lang));
  }

  function setGroceryItem(item) {
    const cleaned = item.replace(/[.?!]+$/g, "").trim();
    setSetting(STORAGE.groceryLastItem, cleaned);
    updateGroceryUi();
  }

  function updateGroceryUi() {
    const item = getSetting(STORAGE.groceryLastItem, "");
    els.groceryQueryValue.textContent = item ? item : "—";

    const q = encodeURIComponent(item || "");
    const blinkit = item
      ? `https://blinkit.com/s/?q=${q}`
      : "https://blinkit.com/";
    const zepto = item
      ? `https://www.zepto.com/search?query=${q}`
      : "https://www.zepto.com/";
    els.blinkitLink.href = blinkit;
    els.zeptoLink.href = zepto;
  }

  function getTodayKey() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }

  function defaultDailyPlan() {
    return [
      { id: "morning_water", title: "Drink a glass of water", sub: "Start gently", time: "Morning" },
      { id: "medicine_check", title: "Check medicine", sub: "Take if scheduled", time: "Morning" },
      { id: "walk", title: "Short walk or stretching", sub: "5–10 minutes", time: "Afternoon" },
      { id: "call_family", title: "Talk to family", sub: "Stay connected", time: "Evening" },
      { id: "night_relax", title: "Relax before sleep", sub: "Breathe slowly", time: "Night" },
    ];
  }

  function getAllPlans() {
    return safeJsonParse(getSetting(STORAGE.dailyActivityPlans, "{}"), {});
  }

  function setAllPlans(plans) {
    setSetting(STORAGE.dailyActivityPlans, JSON.stringify(plans));
  }

  function getDailyPlan() {
    const user = currentUserKey();
    const plans = getAllPlans();
    if (!Array.isArray(plans[user]) || plans[user].length === 0) {
      plans[user] = defaultDailyPlan();
      setAllPlans(plans);
    }
    return plans[user];
  }

  function setDailyPlan(plan) {
    const user = currentUserKey();
    const plans = getAllPlans();
    plans[user] = plan;
    setAllPlans(plans);
  }

  function getActivityStore() {
    return safeJsonParse(getSetting(STORAGE.dailyActivities, "{}"), {});
  }

  function setActivityStore(store) {
    setSetting(STORAGE.dailyActivities, JSON.stringify(store));
  }

  function getTodayDoneMap() {
    const store = getActivityStore();
    const key = getTodayKey();
    const user = currentUserKey();
    if (!store[user]) store[user] = {};
    if (!store[user][key]) store[user][key] = {};
    setActivityStore(store);
    return store[user][key];
  }

  function activityProgress() {
    const plan = getDailyPlan();
    const doneMap = getTodayDoneMap();
    const done = plan.filter((x) => doneMap[x.id]).length;
    return { done, total: plan.length };
  }

  function renderActivityList() {
    if (!els.activityList) return;
    const plan = getDailyPlan();
    const doneMap = getTodayDoneMap();
    els.activityList.innerHTML = "";
    plan.forEach((item) => {
      const done = Boolean(doneMap[item.id]);
      const row = document.createElement("div");
      row.className = "activity-item";
      row.innerHTML = `
        <button class="activity-check" data-id="${item.id}" data-done="${done ? "true" : "false"}" aria-pressed="${done ? "true" : "false"}" type="button">${done ? "✓" : "○"}</button>
        <div class="activity-text">
          <div class="activity-title">${item.title}</div>
          <div class="activity-sub">${item.sub}</div>
          <div class="activity-meta">
            <div class="activity-time">${item.time}</div>
            <button class="activity-remove" data-remove-id="${item.id}" type="button" aria-label="Remove activity">✕</button>
          </div>
        </div>
      `;
      els.activityList.appendChild(row);
    });
    const p = activityProgress();
    if (els.activityProgressValue) els.activityProgressValue.textContent = `${p.done}/${p.total}`;
  }

  function toggleActivityDone(id) {
    const store = getActivityStore();
    const key = getTodayKey();
    const user = currentUserKey();
    if (!store[user]) store[user] = {};
    if (!store[user][key]) store[user][key] = {};
    store[user][key][id] = !store[user][key][id];
    setActivityStore(store);
    renderActivityList();
  }

  function removeActivity(id) {
    const plan = getDailyPlan().filter((x) => x.id !== id);
    if (plan.length === 0) return;
    setDailyPlan(plan);
    renderActivityList();
  }

  function addActivity() {
    const title = String(els.activityInput?.value || "").trim();
    const time = String(els.activityTimeSelect?.value || "Morning");
    if (!title) return;
    const id = `custom_${Date.now()}`;
    const plan = getDailyPlan();
    plan.push({ id, title, sub: "Custom", time });
    setDailyPlan(plan);
    if (els.activityInput) els.activityInput.value = "";
    renderActivityList();
  }

  function resetActivitiesToDefault() {
    setDailyPlan(defaultDailyPlan());
    renderActivityList();
  }

  function openActivitiesWithVoice() {
    renderActivityList();
    openModal(els.activityModal);
    const p = activityProgress();
    const msg = `${t().activityPrompt} ${t().activitySummary(p.done, p.total)}`;
    addBubble("ai", msg);
    speak(msg);
  }

  function detectShoppingIntent(text) {
    const s = normalize(text);
    const urgentWords = ["urgent", "emergency", "fast", "urgently", "ತುರ್ತು", "जल्दी", "तुरंत"];
    const urgency = urgentWords.some((w) => s.includes(w)) ? "high" : "normal";

    let category = "general";
    if (/(medicine|tablet|fever|pharmacy|दवा|औषध|ಔಷಧಿ)/.test(s)) category = "medicine";
    else if (/(milk|grocery|rice|dal|snacks|drink|grocer| किराना|ग्रॉसरी)/.test(s)) category = "grocery";
    else if (/(fruit|apple|banana|fruits)/.test(s)) category = "fruits";
    else if (/(food|lunch|dinner|meal)/.test(s)) category = "food";
    else if (/(baby)/.test(s)) category = "baby";
    else if (/(personal care|soap|shampoo)/.test(s)) category = "personal";

    const item = s
      .replace(/\b(i need|need|buy|order|get|add)\b/g, "")
      .trim() || text.trim();

    return { raw: text, item, category, urgency };
  }

  function estimatePrice(item, category) {
    const seed = Math.max(1, item.length);
    const base = category === "medicine" ? 180 : category === "food" ? 250 : 120;
    return base + seed * 7;
  }

  function getSmartProducts(intent) {
    const primary = intent.item || "daily essentials";
    const products = [
      { name: primary, score: 4.6, price: estimatePrice(primary, intent.category) },
    ];
    const bundles = {
      bread: ["milk", "butter", "jam"],
      milk: ["bread", "eggs"],
      medicine: ["ORS", "thermometer"],
    };
    const key = Object.keys(bundles).find((k) => primary.includes(k));
    if (key) bundles[key].forEach((x) => products.push({ name: x, score: 4.4, price: estimatePrice(x, intent.category) - 30 }));
    return products.slice(0, 4);
  }

  function rankPlatforms(intent) {
    const relevant = PLATFORM_MAP.filter((p) => p.type === intent.category || p.type === "general" || (intent.category === "fruits" && p.type === "grocery"));
    return relevant
      .map((p, i) => ({
        ...p,
        eta: intent.urgency === "high" ? Math.max(10, p.etaMin - 4) : p.etaMin,
        priceIndex: 100 + i * 2,
      }))
      .sort((a, b) => a.eta - b.eta)
      .slice(0, 4);
  }

  function renderSmartOrder(intent) {
    state.currentSmartOrder = intent;
    const products = getSmartProducts(intent);
    const platforms = rankPlatforms(intent);
    els.smartDetected.textContent = intent.raw;
    els.smartUrgency.textContent = intent.urgency === "high" ? "High" : "Normal";
    els.smartCategory.textContent = intent.category;
    els.smartProducts.innerHTML = products
      .map((p) => `<div class="list-item"><span>${p.name}</span><span class="pill">Rs ${Math.round(p.price)} | ⭐ ${p.score}</span></div>`)
      .join("");
    els.smartPlatforms.innerHTML = platforms
      .map((p) => `<div class="list-item"><span>${p.name}</span><span class="pill">${p.eta} min</span></div>`)
      .join("");
  }

  function openSmartOrder(query) {
    const intent = detectShoppingIntent(query);
    renderSmartOrder(intent);
    openModal(els.smartOrderModal);
    const response = intent.urgency === "high"
      ? "I found urgent options. I am showing the fastest delivery first."
      : "I found good options. You can checkout in one tap.";
    addBubble("ai", response);
    speak(response);
  }

  function buildPlatformUrl(platform, item) {
    return `${platform.base}${encodeURIComponent(item)}`;
  }

  function getRecentOrders() {
    return getUserScopedValue(STORAGE.recentOrders, []);
  }

  function setRecentOrders(v) {
    setUserScopedValue(STORAGE.recentOrders, v);
  }

  function addRecentOrder(order) {
    const list = getRecentOrders();
    list.unshift({ ...order, at: Date.now() });
    setRecentOrders(list.slice(0, 8));
  }

  function getHabitStats() {
    return getUserScopedValue(STORAGE.habitStats, {});
  }

  function updateHabit(item) {
    const stats = getHabitStats();
    stats[item] = (stats[item] || 0) + 1;
    setUserScopedValue(STORAGE.habitStats, stats);
  }

  function renderRecentOrders() {
    const list = getRecentOrders();
    els.recentOrders.innerHTML = list.length
      ? list.slice(0, 5).map((o) => `<div class="list-item"><span>${o.item}</span><span class="pill">${o.platform}</span></div>`).join("")
      : `<div class="list-item"><span>No recent orders yet</span><span class="pill">Start with One Tap</span></div>`;
  }

  function renderNearbyFast() {
    els.nearbyFast.innerHTML = PLATFORM_MAP
      .slice(0, 4)
      .sort((a, b) => a.etaMin - b.etaMin)
      .map((p) => `<div class="list-item"><span>${p.name}</span><span class="pill">${p.etaMin} min</span></div>`)
      .join("");
  }

  function renderAiRecs() {
    const stats = getHabitStats();
    const top = Object.entries(stats).sort((a, b) => b[1] - a[1]).slice(0, 3);
    if (!top.length) {
      els.aiRecs.innerHTML = `<div class="list-item"><span>Try ordering milk or medicines.</span><span class="pill">AI learns habits</span></div>`;
      return;
    }
    els.aiRecs.innerHTML = top
      .map(([name]) => `<div class="list-item"><span>${name} + bundle suggestion</span><span class="pill">Save money</span></div>`)
      .join("");
  }

  function respond(userText, intent) {
    addBubble("user", userText, t().said);

    const reassurance = doubtReassureIfNeeded(intent.key);
    if (reassurance) {
      addBubble("ai", reassurance);
      speak(reassurance);
      return;
    }

    if (intent.key === "emergency.help") {
      openModal(els.emergencyModal);
      triggerEmergency();
      return;
    }

    if (intent.key === "medicine.status") {
      const a = answerMedicineStatus();
      addBubble("ai", a);
      speak(a);
      return;
    }

    if (intent.key === "ui.openMedicine") {
      openModal(els.medicineModal);
      const a = answerMedicineStatus();
      addBubble("ai", a);
      speak(a);
      return;
    }

    if (intent.key === "grocery.need") {
      const item = intent.slots.item;
      setGroceryItem(item);
      openModal(els.groceryModal);
      const a = t().grocerySaved(item);
      addBubble("ai", a);
      speak(a);
      return;
    }

    if (intent.key === "activity.open") {
      openActivitiesWithVoice();
      return;
    }

    if (intent.key === "shopping.smart") {
      openSmartOrder(intent.slots.query || userText);
      return;
    }

    const a = t().unknown;
    addBubble("ai", a);
    speak(a);
  }

  function createRecognition() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return null;
    const r = new SR();
    r.continuous = false;
    r.interimResults = false;
    r.maxAlternatives = 1;
    r.lang = (LANGS[state.lang] || LANGS.en).speech;
    return r;
  }

  function startListening() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) {
      setStatus(t().statusNotSupported);
      addBubble("ai", t().statusNotSupported);
      return;
    }

    if (state.recognition) {
      try {
        state.recognition.abort();
      } catch {
        // ignore
      }
      state.recognition = null;
    }

    const r = createRecognition();
    if (!r) {
      setStatus(t().statusNotSupported);
      return;
    }
    state.recognition = r;

    setListening(true);
    setStatus(t().micLabelListening);

    r.onresult = (event) => {
      const transcript = event?.results?.[0]?.[0]?.transcript || "";
      const cleaned = transcript.trim();
      if (!cleaned) return;
      const intent = detectIntent(cleaned);
      respond(cleaned, intent);
    };

    r.onerror = (event) => {
      const err = event?.error || "";
      if (err === "not-allowed" || err === "service-not-allowed") {
        setStatus(t().statusPermission);
        addBubble("ai", t().statusPermission);
      } else if (err === "no-speech") {
        setStatus(t().statusNoSpeech);
      } else {
        setStatus(`${t().statusNoSpeech}`);
      }
    };

    r.onend = () => {
      setListening(false);
      setStatus(t().statusReady);
    };

    try {
      r.start();
    } catch {
      setListening(false);
      setStatus(t().statusPermission);
      addBubble("ai", t().statusPermission);
    }
  }

  function stopListening() {
    if (!state.recognition) return;
    try {
      state.recognition.stop();
    } catch {
      // ignore
    }
  }

  function triggerEmergency() {
    const msg = t().helpConfirm;
    els.emergencyConfirm.textContent = msg;
    addBubble("ai", msg);
    speak(msg);
  }

  function onMedicineTaken() {
    const d = new Date();
    setLastTaken(d);
    updateMedicineUi();
    const time = formatTimeForUser(d, state.lang);
    const msg = `${t().medicineTaken} ${time}.`;
    addBubble("ai", msg);
    speak(msg);
  }

  function onSaveMedTime() {
    const v = els.medTime.value;
    if (!v) return;
    setDailyTime(v);
    updateMedicineUi();
    const msg = `${t().medicineSet} ${v}.`;
    addBubble("ai", msg);
    speak(msg);
  }

  function toggleSound() {
    state.soundOn = !state.soundOn;
    setBool(STORAGE.sound, state.soundOn);
    els.btnSound.textContent = state.soundOn ? t().voiceOn : t().voiceOff;
    els.btnSound.setAttribute("aria-pressed", state.soundOn ? "true" : "false");
    if (!state.soundOn) {
      try {
        window.speechSynthesis?.cancel?.();
      } catch {
        // ignore
      }
    }
  }

  function wireUi() {
    if (els.oneTapGrid) {
      els.oneTapGrid.innerHTML = ONE_TAP_PRESETS.map(
        (p) =>
          `<button class="one-tap-btn" data-query="${p.query}" type="button"><div class="one-tap-title">${p.label}</div><div class="one-tap-sub">One tap smart action</div></button>`
      ).join("");
      els.oneTapGrid.addEventListener("click", (e) => {
        const target = e.target;
        if (!(target instanceof HTMLElement)) return;
        const btn = target.closest(".one-tap-btn");
        if (!btn) return;
        const q = btn.getAttribute("data-query");
        if (!q) return;
        openSmartOrder(q);
      });
    }

    document.querySelectorAll(".smart-order-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const q = btn.getAttribute("data-query") || "Get essentials";
        openSmartOrder(q);
      });
    });

    els.mic.addEventListener("click", () => {
      if (state.listening) stopListening();
      else startListening();
    });

    els.btnMedicine.addEventListener("click", () => {
      updateMedicineUi();
      openModal(els.medicineModal);
    });

    els.btnEmergency.addEventListener("click", () => {
      els.emergencyConfirm.textContent = "";
      openModal(els.emergencyModal);
    });

    els.btnCallHelp.addEventListener("click", () => {
      triggerEmergency();
    });

    els.btnLanguage.addEventListener("click", () => {
      openModal(els.languageModal);
    });

    els.btnSound.addEventListener("click", () => {
      toggleSound();
    });
    els.btnLogout.addEventListener("click", () => {
      localStorage.removeItem(STORAGE.sessionPhone);
      window.location.href = "./login.html";
    });

    els.langEn.addEventListener("click", () => {
      setLanguage("en");
      closeModal(els.languageModal);
      addBubble("ai", "Okay. I will speak in English.");
      speak("Okay. I will speak in English.");
    });
    els.langHi.addEventListener("click", () => {
      setLanguage("hi");
      closeModal(els.languageModal);
      addBubble("ai", "ठीक है। मैं हिंदी में बोलूँगी।");
      speak("ठीक है। मैं हिंदी में बोलूँगी।");
    });
    els.langKn.addEventListener("click", () => {
      setLanguage("kn");
      closeModal(els.languageModal);
      addBubble("ai", "ಸರಿ. ನಾನು ಕನ್ನಡದಲ್ಲಿ ಮಾತನಾಡುತ್ತೇನೆ.");
      speak("ಸರಿ. ನಾನು ಕನ್ನಡದಲ್ಲಿ ಮಾತನಾಡುತ್ತೇನೆ.");
    });

    els.btnSaveMedTime.addEventListener("click", () => onSaveMedTime());
    els.btnTookMed.addEventListener("click", () => onMedicineTaken());

    els.btnGrocery.addEventListener("click", () => {
      updateGroceryUi();
      openModal(els.groceryModal);
      const msg = t().askGrocery;
      addBubble("ai", msg);
      speak(msg);
    });

    if (els.btnActivity) {
      els.btnActivity.addEventListener("click", () => {
        renderActivityList();
        openModal(els.activityModal);
      });
    }

    if (els.activityList) {
      els.activityList.addEventListener("click", (e) => {
        const target = e.target;
        if (!(target instanceof HTMLElement)) return;
        const removeBtn = target.closest(".activity-remove");
        if (removeBtn) {
          const removeId = removeBtn.getAttribute("data-remove-id");
          if (removeId) removeActivity(removeId);
          return;
        }
        const btn = target.closest(".activity-check");
        if (!btn) return;
        const id = btn.getAttribute("data-id");
        if (!id) return;
        toggleActivityDone(id);
      });
    }

    if (els.btnAddActivity) {
      els.btnAddActivity.addEventListener("click", () => addActivity());
    }
    if (els.btnResetActivities) {
      els.btnResetActivities.addEventListener("click", () => resetActivitiesToDefault());
    }

    if (els.btnAddCart) {
      els.btnAddCart.addEventListener("click", () => {
        if (!state.currentSmartOrder) return;
        addRecentOrder({ item: state.currentSmartOrder.item, platform: "Smart Cart" });
        updateHabit(state.currentSmartOrder.item);
        renderRecentOrders();
        renderAiRecs();
        addBubble("ai", "Smart cart saved. You can checkout anytime.");
      });
    }

    if (els.btnOneTapCheckout) {
      els.btnOneTapCheckout.addEventListener("click", () => {
        if (!state.currentSmartOrder) return;
        const ranked = rankPlatforms(state.currentSmartOrder);
        if (!ranked.length) {
          addBubble("ai", "I could not find a platform right now. Please try again.");
          return;
        }
        const best = ranked[0];
        const url = buildPlatformUrl(best, state.currentSmartOrder.item);
        addRecentOrder({ item: state.currentSmartOrder.item, platform: best.name });
        updateHabit(state.currentSmartOrder.item);
        renderRecentOrders();
        renderAiRecs();
        window.open(url, "_blank", "noopener,noreferrer");
        addBubble("ai", `Opening ${best.name} for quick checkout.`);
      });
    }

    // Keyboard safety: ESC should stop listening
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && state.listening) stopListening();
    });
  }

  function seedWelcome() {
    const C = t();
    const intro =
      state.lang === "en"
        ? "I’m Sahay. Tap the microphone and speak. I will keep things simple and calm."
        : state.lang === "hi"
          ? "मैं सहाय हूँ। माइक्रोफोन दबाएँ और बोलें। मैं सब सरल और शांत रखूँगी।"
          : "ನಾನು ಸಹಾಯ. ಮೈಕ್ರೋಫೋನ್ ಒತ್ತಿ ಮಾತನಾಡಿ. ನಾನು ಎಲ್ಲವೂ ಸರಳವಾಗಿ, ಶಾಂತವಾಗಿ ಇಡುತ್ತೇನೆ.";
    addBubble("ai", intro);
    speak(intro);
  }

  function init() {
    const users = safeJsonParse(localStorage.getItem(STORAGE.users) || "[]", []);
    const sessionPhone = localStorage.getItem(STORAGE.sessionPhone) || "";
    const sessionUser = users.find((u) => u.phone === sessionPhone);
    if (!sessionUser) {
      window.location.href = "./login.html";
      return;
    }
    state.userName = sessionUser.name || DEFAULTS.userName;
    setSetting(STORAGE.name, state.userName);

    // Ensure defaults exist
    if (!getSetting(STORAGE.lang, null)) setSetting(STORAGE.lang, DEFAULTS.lang);
    if (!getSetting(STORAGE.medTime, null)) setSetting(STORAGE.medTime, DEFAULTS.medTime);
    if (!localStorage.getItem(STORAGE.sound)) setBool(STORAGE.sound, DEFAULTS.soundOn);

    state.lang = getSetting(STORAGE.lang, DEFAULTS.lang);
    state.soundOn = getBool(STORAGE.sound, DEFAULTS.soundOn);

    wireUi();
    renderStaticCopy();
    updateMedicineUi();
    updateGroceryUi();
    renderActivityList();
    renderNearbyFast();
    renderRecentOrders();
    renderAiRecs();
    updateSelectedLanguageUi();
    seedWelcome();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
