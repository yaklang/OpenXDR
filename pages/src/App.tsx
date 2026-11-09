import Footer12 from "@/components/blocks/footer-12";
import { Hero24 } from "@/components/blocks/hero-24";
import Navigation15 from "@/components/blocks/navigation-15";
import { Architecture } from "@/components/story/architecture";
import { Assistant } from "@/components/story/assistant";
import { Closing } from "@/components/story/closing";
import { Features } from "@/components/story/features";
import { Funnel } from "@/components/story/funnel";
import { Intent } from "@/components/story/intent";
import { Onboard } from "@/components/story/onboard";
import { Respond } from "@/components/story/respond";
import { Surface } from "@/components/story/surface";
import { Watch } from "@/components/story/watch";
import { useLocale } from "@/i18n";

export default function App() {
  const locale = useLocale();

  return (
    <div className="min-h-screen overflow-x-clip bg-neutral-950 text-white">
      <a
        href="#platform"
        className="fixed left-4 top-4 z-[60] -translate-y-24 rounded-full bg-white px-4 py-2 text-sm font-medium text-neutral-950 transition-transform focus:translate-y-0"
      >
        {locale === "zh-CN" ? "跳到主要内容" : "Skip to content"}
      </a>
      <Navigation15 />
      <main>
        <Hero24 />
        <Architecture />
        <Onboard />
        <Funnel />
        <Surface />
        <Intent />
        <Respond />
        <Assistant />
        <Features />
        <Closing />
      </main>
      <Footer12 />
      <Watch />
    </div>
  );
}
