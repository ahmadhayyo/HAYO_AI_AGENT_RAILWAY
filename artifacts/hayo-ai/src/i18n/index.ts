import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import ar from "./locales/ar.json";
import en from "./locales/en.json";
import tr from "./locales/tr.json";
import pt from "./locales/pt.json";
import fr from "./locales/fr.json";
import de from "./locales/de.json";
import es from "./locales/es.json";
import hi from "./locales/hi.json";
import ru from "./locales/ru.json";
import zh from "./locales/zh.json";

export const LANGUAGES = [
  { code: "ar", label: "العربية", flag: "🇸🇦", dir: "rtl" },
  { code: "en", label: "English", flag: "🇺🇸", dir: "ltr" },
  { code: "es", label: "Español", flag: "🇪🇸", dir: "ltr" },
  { code: "fr", label: "Français", flag: "🇫🇷", dir: "ltr" },
  { code: "de", label: "Deutsch", flag: "🇩🇪", dir: "ltr" },
  { code: "pt", label: "Português", flag: "🇧🇷", dir: "ltr" },
  { code: "ru", label: "Русский", flag: "🇷🇺", dir: "ltr" },
  { code: "tr", label: "Türkçe", flag: "🇹🇷", dir: "ltr" },
  { code: "zh", label: "中文", flag: "🇨🇳", dir: "ltr" },
  { code: "hi", label: "हिन्दी", flag: "🇮🇳", dir: "ltr" },
] as const;

// English-first: the platform's base language is English (the universal business
// language for investors). On first visit everyone lands in English; if a user
// explicitly picks another language it's remembered and honored afterwards.
// Fallback is also English so a missing key never bleeds another language.
const savedLang = localStorage.getItem("hayo-lang") || "en";

i18n.use(initReactI18next).init({
  resources: {
    ar: { translation: ar }, en: { translation: en }, tr: { translation: tr },
    pt: { translation: pt }, fr: { translation: fr }, de: { translation: de },
    es: { translation: es }, hi: { translation: hi }, ru: { translation: ru },
    zh: { translation: zh },
  },
  lng: savedLang,
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

i18n.on("languageChanged", (lang) => {
  localStorage.setItem("hayo-lang", lang);
  const langConfig = LANGUAGES.find((l) => l.code === lang);
  document.documentElement.dir = langConfig?.dir || "ltr";
  document.documentElement.lang = lang;
});

const initialLang = LANGUAGES.find((l) => l.code === savedLang);
document.documentElement.dir = initialLang?.dir || "ltr";
document.documentElement.lang = savedLang;

export default i18n;
