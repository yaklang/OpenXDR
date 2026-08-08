"use client";

import { ArrowRight } from "lucide-react";
import { motion, useReducedMotion, type Variants } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { NeuroNoise } from "@paper-design/shaders-react";

function useIsDark() {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const read = () => {
      const classes = document.documentElement.classList;
      if (classes.contains("dark")) return true;
      if (classes.contains("light")) return false;
      return query.matches;
    };
    const update = () => setIsDark(read());
    update();
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    query.addEventListener("change", update);
    return () => {
      observer.disconnect();
      query.removeEventListener("change", update);
    };
  }, []);

  return isDark;
}

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
  const isDark = useIsDark();
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

  const neuro = isDark
    ? {
        colorBack: "#0a0a0a",
        colorMid: "#17663f",
        colorFront: "#8df0bd",
        brightness: 0.2,
        contrast: 0.48,
      }
    : {
        colorBack: "#ffffff",
        colorMid: "#aebcff",
        colorFront: "#6b57ff",
        brightness: 0.62,
        contrast: 0.42,
      };

  return (
    <section
      ref={sectionRef}
      id="platform"
      className="relative flex min-h-[900px] w-full items-start overflow-hidden bg-white px-4 pb-20 pt-32 dark:bg-neutral-950 sm:px-6 sm:pb-24 sm:pt-36 lg:min-h-screen lg:items-center lg:px-8"
    >
      {isVisible && (
        <NeuroNoise
          key={isDark ? "dark" : "light"}
          className="absolute inset-0 h-full w-full"
          style={{ width: "100%", height: "100%" }}
          colorBack={neuro.colorBack}
          colorMid={neuro.colorMid}
          colorFront={neuro.colorFront}
          brightness={neuro.brightness}
          contrast={neuro.contrast}
          scale={1.15}
          offsetX={0.42}
          speed={reduceMotion ? 0 : 0.55}
        />
      )}

      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.96)_18%,rgba(255,255,255,0.72)_46%,rgba(255,255,255,0)_82%)] dark:hidden"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 hidden bg-[linear-gradient(to_right,rgba(10,10,10,0.94)_18%,rgba(10,10,10,0.62)_46%,rgba(10,10,10,0)_82%)] dark:block"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_bottom,rgba(255,255,255,0)_60%,rgba(255,255,255,0.9))] dark:bg-[linear-gradient(to_bottom,rgba(10,10,10,0)_60%,rgba(10,10,10,0.9))]"
      />

      <div className="relative z-10 mx-auto w-full max-w-[1400px]">
        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          className="flex max-w-2xl flex-col items-start text-left"
        >
          <motion.div
            variants={item}
            className="inline-flex items-center gap-2 rounded-full border border-neutral-200/80 bg-white/70 px-3.5 py-1.5 text-xs font-medium text-neutral-700 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-white/5 dark:text-neutral-200"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-300 opacity-70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
            Open source · EDR + NDR + SIEM
          </motion.div>

          <motion.h1
            variants={headline}
            className="mt-7 text-4xl font-medium leading-[1.02] tracking-[-0.04em] text-neutral-950 dark:text-white sm:text-6xl md:text-7xl"
          >
            Ten thousand alerts in.
            <br />
            <span className="text-neutral-500 dark:text-neutral-400">
              Three incidents out.
            </span>
          </motion.h1>

          <motion.p
            variants={item}
            className="mt-6 max-w-lg text-base leading-relaxed text-neutral-600 dark:text-neutral-300 sm:text-lg"
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
              className="inline-flex w-full cursor-pointer items-center justify-center rounded-full bg-neutral-950 px-6 py-3 text-sm font-medium text-white transition-colors duration-200 hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:bg-white dark:text-neutral-950 dark:hover:bg-neutral-200 dark:focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              View on GitHub
              <ArrowRight className="ml-2 h-4 w-4" />
            </a>
            <a
              href="#pipeline"
              className="inline-flex w-full cursor-pointer items-center justify-center rounded-full border border-neutral-300 bg-white/60 px-6 py-3 text-sm font-medium text-neutral-900 backdrop-blur transition-colors duration-200 hover:bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:border-white/20 dark:bg-white/5 dark:text-white dark:hover:bg-white/10 dark:focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              Follow the signal
            </a>
          </motion.div>

          <motion.div variants={item} className="mt-14 w-full">
            <p className="text-xs font-medium uppercase tracking-[0.18em] text-neutral-400 dark:text-neutral-500">
              One evidence plane across
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-x-7 gap-y-3">
              {partners.map((name) => (
                <span
                  key={name}
                  className="text-sm font-semibold tracking-tight text-neutral-400 transition-colors duration-200 hover:text-neutral-700 dark:text-neutral-600 dark:hover:text-neutral-300"
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
