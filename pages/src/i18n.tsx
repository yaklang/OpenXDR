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
    title: "OpenXDR - Open-source autonomous XDR",
    description:
      "Open-source autonomous XDR. Install the agent, pick a group, and it notices, judges and acts on its own — every step with its reasons, every action reversible.",
  },
  "zh-CN": {
    title: "OpenXDR - 开源的自治 XDR",
    description:
      "开源的自治 XDR。装上 agent，分好组，它自己察觉、研判、处置——每一步都留下理由，每一次处置都能撤回。",
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

/** 按当前语言取一份文案，中英文成对写在调用处。 */
export function useCopy<T>(copy: Record<Locale, T>): T {
  return copy[useLocale()];
}
