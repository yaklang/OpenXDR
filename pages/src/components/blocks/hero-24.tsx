"use client";

import { ArrowRight } from "lucide-react";
import { motion, useReducedMotion, type Variants } from "motion/react";
import { useEffect, useRef, useState } from "react";
import BlackHole from "@/components/react-bits/black-hole";

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

const partners = ["ENDPOINT", "NETWORK", "IDENTITY", "CLOUD", "LOGS"];

export function Hero24() {
  const reduceMotion = useReducedMotion();
  const sectionRef = useRef<HTMLElement>(null);
  const [isVisible, setIsVisible] = useState(true);

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
        <div className="pointer-events-none absolute right-[-48%] top-16 h-[680px] w-[136%] sm:right-[-30%] sm:top-20 sm:h-[760px] sm:w-[112%] lg:-right-[8%] lg:inset-y-0 lg:h-auto lg:w-[70%]">
          <BlackHole
            width="100%"
            height="100%"
            speed={reduceMotion ? 0 : 0.72}
            zoom={1.65}
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
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(90deg,#0a0a0a_0%,#0a0a0a_32%,rgba(10,10,10,0.94)_48%,rgba(10,10,10,0.58)_68%,rgba(10,10,10,0.08)_100%)] lg:bg-[linear-gradient(90deg,#0a0a0a_0%,#0a0a0a_36%,rgba(10,10,10,0.9)_49%,rgba(10,10,10,0.28)_66%,rgba(10,10,10,0)_84%)]"
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
            Open source · EDR + NDR + SIEM
          </motion.div>

          <motion.h1
            variants={headline}
            className="mt-7 text-4xl font-medium leading-[1.02] tracking-[-0.04em] text-white sm:text-6xl md:text-7xl"
          >
            Ten thousand alerts in.
            <br />
            <span className="text-neutral-400">
              Three incidents out.
            </span>
          </motion.h1>

          <motion.p
            variants={item}
            className="mt-6 max-w-lg text-base leading-relaxed text-neutral-300 sm:text-lg"
          >
            OpenXDR joins endpoint, full-traffic, identity, and log evidence
            into one explainable attack story — then lets AI investigate the
            incidents that survive correlation.
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
              View on GitHub
              <ArrowRight className="ml-2 h-4 w-4" />
            </a>
            <a
              href="#pipeline"
              className="inline-flex w-full cursor-pointer items-center justify-center rounded-full border border-white/20 bg-white/5 px-6 py-3 text-sm font-medium text-white backdrop-blur transition-colors duration-200 hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              Follow the signal
            </a>
          </motion.div>

          <motion.div variants={item} className="mt-14 w-full">
            <p className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-500">
              One evidence plane across
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-x-7 gap-y-3">
              {partners.map((name) => (
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
