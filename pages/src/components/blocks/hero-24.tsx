"use client";

import { ArrowRight } from "lucide-react";
import { motion, useReducedMotion, type Variants } from "motion/react";
import { useEffect, useRef, useState } from "react";
import BlackHole from "@/components/react-bits/black-hole";
import { useLocale } from "@/i18n";

const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.09, delayChildren: 0.08 } },
};

const item: Variants = {
  hidden: { opacity: 0, y: 20 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] },
  },
};

const headline: Variants = {
  hidden: { opacity: 0, y: 26, filter: "blur(10px)" },
  show: {
    opacity: 1,
    y: 0,
    filter: "blur(0px)",
    transition: { duration: 0.85, ease: [0.22, 1, 0.36, 1] },
  },
};

export function Hero24() {
  const locale = useLocale();
  const reduceMotion = useReducedMotion();
  const sectionRef = useRef<HTMLElement>(null);
  const [isVisible, setIsVisible] = useState(true);
  const copy =
    locale === "zh-CN"
      ? {
          badge: "开源 · EDR + NDR + SIEM",
          headline: "一万条告警进来。",
          headlineAccent: "三个真实事件出来。",
          description:
            "OpenXDR 将端点、全流量、身份与日志证据汇聚成一条可解释的攻击链，再由 AI 调查通过关联筛选的事件。",
          github: "在 GitHub 查看",
          pipeline: "追踪信号路径",
          evidence: "统一证据平面覆盖",
          partners: ["端点", "网络", "身份", "云", "日志"],
        }
      : {
          badge: "Open source · EDR + NDR + SIEM",
          headline: "Ten thousand alerts in.",
          headlineAccent: "Three incidents out.",
          description:
            "OpenXDR joins endpoint, full-traffic, identity, and log evidence into one explainable attack story, then lets AI investigate the incidents that survive correlation.",
          github: "View on GitHub",
          pipeline: "Follow the signal",
          evidence: "One evidence plane across",
          partners: ["ENDPOINT", "NETWORK", "IDENTITY", "CLOUD", "LOGS"],
        };

  useEffect(() => {
    const section = sectionRef.current;
    if (!section) return;
    const observer = new IntersectionObserver(
      ([entry]) => setIsVisible(entry.isIntersecting),
      { threshold: 0.01 },
    );
    observer.observe(section);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      id="platform"
      className="relative flex min-h-[900px] w-full items-start overflow-hidden bg-neutral-950 px-4 pb-20 pt-32 sm:px-6 sm:pb-24 sm:pt-36 lg:min-h-screen lg:items-center lg:px-8"
    >
      {isVisible && (
        <div className="pointer-events-none absolute inset-0">
          <BlackHole
            width="100%"
            height="100%"
            speed={reduceMotion ? 0 : 0.72}
            zoom={1.48}
            particleCount={16}
            orbSize={0.76}
            glow={0.075}
            contrast={2.7}
            distanceFade={0.32}
            mirrorSplits={2}
            warpEnabled
            backgroundColor="#0a0a0a"
            opacity={0.96}
            cursorInteraction={false}
          />
        </div>
      )}

      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(90deg,rgba(10,10,10,0.94)_0%,rgba(10,10,10,0.86)_36%,rgba(10,10,10,0.66)_58%,rgba(10,10,10,0.24)_82%,rgba(10,10,10,0.08)_100%)] lg:bg-[linear-gradient(90deg,rgba(10,10,10,0.92)_0%,rgba(10,10,10,0.82)_30%,rgba(10,10,10,0.52)_50%,rgba(10,10,10,0.16)_70%,rgba(10,10,10,0)_88%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_bottom,rgba(10,10,10,0)_52%,rgba(10,10,10,0.92)_92%,#0a0a0a)]"
      />

      <div className="relative z-10 mx-auto w-full max-w-[1400px]">
        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          className="flex max-w-2xl flex-col items-start text-left lg:max-w-[640px]"
        >
          <motion.div
            variants={item}
            className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3.5 py-1.5 text-xs font-medium text-neutral-200 shadow-sm backdrop-blur-md"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-300 opacity-70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
            {copy.badge}
          </motion.div>

          <motion.h1
            variants={headline}
            className="mt-7 text-4xl font-medium leading-[1.02] tracking-[-0.04em] text-white sm:text-6xl md:text-7xl"
          >
            {copy.headline}
            <br />
            <span className="text-neutral-400">
              {copy.headlineAccent}
            </span>
          </motion.h1>

          <motion.p
            variants={item}
            className="mt-6 max-w-lg text-base leading-relaxed text-neutral-300 sm:text-lg"
          >
            {copy.description}
          </motion.p>

          <motion.div
            variants={item}
            className="mt-10 flex w-full flex-col gap-3 sm:w-auto sm:flex-row"
          >
            <a
              href="https://github.com/yaklang/OpenXDR"
              target="_blank"
              rel="noreferrer"
              className="inline-flex w-full cursor-pointer items-center justify-center rounded-full bg-white px-6 py-3 text-sm font-medium text-neutral-950 transition-colors duration-200 hover:bg-neutral-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              {copy.github}
              <ArrowRight className="ml-2 h-4 w-4" />
            </a>
            <a
              href="#pipeline"
              className="inline-flex w-full cursor-pointer items-center justify-center rounded-full border border-white/20 bg-white/5 px-6 py-3 text-sm font-medium text-white backdrop-blur transition-colors duration-200 hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              {copy.pipeline}
            </a>
          </motion.div>

          <motion.div variants={item} className="mt-14 w-full">
            <p className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-500">
              {copy.evidence}
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-x-7 gap-y-3">
              {copy.partners.map((name) => (
                <span
                  key={name}
                  className="text-sm font-semibold tracking-tight text-neutral-600 transition-colors duration-200 hover:text-neutral-300"
                >
                  {name}
                </span>
              ))}
            </div>
          </motion.div>
        </motion.div>
      </div>
    </section>
  );
}
