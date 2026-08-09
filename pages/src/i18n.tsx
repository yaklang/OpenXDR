import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Locale = "en" | "zh-CN";

const pageMetadata = {
  en: {
    title: "OpenXDR - Signal over noise",
    description:
      "OpenXDR is an open-source XDR platform combining endpoint, network, and log telemetry with AI-assisted correlation.",
  },
  "zh-CN": {
    title: "OpenXDR - 从噪声中提取信号",
    description:
      "OpenXDR 是一个开源 XDR 平台，通过 AI 辅助关联端点、网络与日志遥测数据。",
  },
} satisfies Record<Locale, { title: string; description: string }>;

function detectLocale(): Locale {
  const languages = navigator.languages.length
    ? navigator.languages
    : [navigator.language];
  return languages.some((language) => language.toLowerCase().startsWith("zh"))
    ? "zh-CN"
    : "en";
}

const LocaleContext = createContext<Locale>("en");

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>(detectLocale);

  useEffect(() => {
    const syncLocale = () => setLocale(detectLocale());
    window.addEventListener("languagechange", syncLocale);
    return () => window.removeEventListener("languagechange", syncLocale);
  }, []);

  useEffect(() => {
    const metadata = pageMetadata[locale];
    document.documentElement.lang = locale;
    document.title = metadata.title;
    document
      .querySelector<HTMLMetaElement>('meta[name="description"]')
      ?.setAttribute("content", metadata.description);
  }, [locale]);

  const value = useMemo(() => locale, [locale]);
  return (
    <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
  );
}

export function useLocale() {
  return useContext(LocaleContext);
}
