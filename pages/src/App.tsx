import { Features10 } from "@/components/blocks/features-10";
import Footer12 from "@/components/blocks/footer-12";
import { Hero24 } from "@/components/blocks/hero-24";
import { HowItWorks8 } from "@/components/blocks/how-it-works-8";
import Navigation15 from "@/components/blocks/navigation-15";
import Stats14 from "@/components/blocks/stats-14";

export default function App() {
  return (
    <div className="min-h-screen overflow-x-hidden bg-neutral-950 text-white">
      <a
        href="#platform"
        className="fixed left-4 top-4 z-[60] -translate-y-24 rounded-full bg-white px-4 py-2 text-sm font-medium text-neutral-950 transition-transform focus:translate-y-0"
      >
        Skip to content
      </a>
      <Navigation15 />
      <main>
        <Hero24 />
        <Features10 />
        <HowItWorks8 />
        <Stats14 />
      </main>
      <Footer12 />
    </div>
  );
}
