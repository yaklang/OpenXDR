"use client";

import { motion, useReducedMotion } from "motion/react";
import type { Variants } from "motion/react";
import {
  Boxes,
  Cloud,
  FileText,
  GitBranch,
  Network,
  ShieldCheck,
  Terminal,
  Users,
} from "lucide-react";
import { useLocale } from "@/i18n";

const nodes = [
  { en: "Endpoint agent", zh: "端点 Agent", icon: Terminal, x: 50, y: 10 },
  { en: "Network sensor", zh: "网络 Sensor", icon: Network, x: 84.6, y: 30 },
  { en: "Cloud workloads", zh: "云工作负载", icon: Cloud, x: 84.6, y: 70 },
  { en: "Identity & auth", zh: "身份与认证", icon: Users, x: 50, y: 90 },
  { en: "Syslog & SaaS", zh: "Syslog 与 SaaS", icon: FileText, x: 15.4, y: 70 },
  { en: "Threat intel", zh: "威胁情报", icon: ShieldCheck, x: 15.4, y: 30 },
];

const scatter = [
  { cx: 27, cy: 15, r: 0.6 },
  { cx: 71, cy: 9, r: 0.4 },
  { cx: 93, cy: 50, r: 0.5 },
  { cx: 87, cy: 87, r: 0.4 },
  { cx: 13, cy: 88, r: 0.5 },
  { cx: 7, cy: 49, r: 0.4 },
  { cx: 35, cy: 95, r: 0.4 },
  { cx: 64, cy: 5, r: 0.5 },
];

const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08, delayChildren: 0.1 } },
};

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 16 },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: [0.22, 1, 0.36, 1] },
  },
};

const fadeIn: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] } },
};

const draw: Variants = {
  hidden: { pathLength: 0, opacity: 0 },
  show: {
    pathLength: 1,
    opacity: 1,
    transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] },
  },
};

const pop: Variants = {
  hidden: { opacity: 0, scale: 0.85 },
  show: {
    opacity: 1,
    scale: 1,
    transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] },
  },
};

const orchestra: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.05 } },
};

export function Features10() {
  const locale = useLocale();
  const reduce = useReducedMotion();
  const copy =
    locale === "zh-CN"
      ? {
          eyebrow: "信号织网",
          heading: "所有信号，汇成一幅全局图",
          description:
            "端点活动、网络会话、认证、云事件与日志通过专用采集器进入，最终汇聚到同一组实体、时间线与证据图中。",
          cta: "查看处理链路",
          schema: "3 个接入平面 · 1 套模式",
          mapLabel:
            "信号图：端点、网络、云、身份、日志和威胁情报连接到 OpenXDR",
        }
      : {
          eyebrow: "Signal fabric",
          heading: "Every signal, one operating picture",
          description:
            "Endpoint activity, network sessions, authentication, cloud events, and logs arrive through purpose-built collectors, then converge on the same entities, timeline, and evidence graph.",
          cta: "Trace the pipeline",
          schema: "3 ingest planes · one schema",
          mapLabel:
            "Signal map showing endpoint, network, cloud, identity, logs, and threat intelligence connected to OpenXDR",
        };

  return (
    <section
      id="signals"
      className="w-full overflow-hidden bg-white px-4 py-16 dark:bg-neutral-950 sm:px-6 sm:py-20 lg:px-8 lg:py-28"
    >
      <div className="mx-auto grid w-full max-w-[1400px] grid-cols-1 items-center gap-14 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          className="flex flex-col items-start"
        >
          <motion.span
            variants={fadeUp}
            className="inline-flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-neutral-500 dark:text-neutral-400"
          >
            <GitBranch className="h-3.5 w-3.5" />
            {copy.eyebrow}
          </motion.span>

          <motion.h2
            variants={fadeUp}
            className="mt-5 max-w-xl text-3xl font-semibold leading-[1.1] tracking-tight text-neutral-900 dark:text-white sm:text-4xl md:text-5xl"
          >
            {copy.heading}
          </motion.h2>

          <motion.p
            variants={fadeUp}
            className="mt-5 max-w-md text-base leading-relaxed text-neutral-600 dark:text-neutral-400 sm:text-lg"
          >
            {copy.description}
          </motion.p>

          <motion.div
            variants={fadeUp}
            className="mt-8 flex w-full flex-col items-stretch gap-3 sm:w-auto sm:flex-row sm:items-center"
          >
            <a
              href="#pipeline"
              className="w-full cursor-pointer rounded-full bg-black px-6 py-3 text-center text-sm font-medium text-white transition-colors duration-200 hover:bg-neutral-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 focus-visible:ring-offset-2 dark:bg-white dark:text-black dark:hover:bg-neutral-200 dark:focus-visible:ring-white dark:focus-visible:ring-offset-neutral-950 sm:w-auto sm:px-8 sm:py-3.5 sm:text-base"
            >
              {copy.cta}
            </a>
            <div className="inline-flex items-center justify-center gap-2.5 rounded-full border border-neutral-200 bg-white px-5 py-3 text-sm text-neutral-600 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-400 sm:py-3.5">
              <span className="relative flex h-2 w-2">
                {!reduce && (
                  <motion.span
                    animate={{ scale: [1, 2.1], opacity: [0.55, 0] }}
                    transition={{
                      duration: 2.4,
                      repeat: Infinity,
                      ease: "easeOut",
                    }}
                    className="absolute inline-flex h-full w-full rounded-full bg-emerald-500 dark:bg-emerald-400"
                  />
                )}
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500 dark:bg-emerald-400" />
              </span>
              {copy.schema}
            </div>
          </motion.div>
        </motion.div>

        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          role="img"
          aria-label={copy.mapLabel}
          className="relative mx-auto mb-8 aspect-square w-full max-w-[520px]"
        >
          <div
            aria-hidden="true"
            className="absolute inset-0 rounded-full bg-[radial-gradient(circle_at_center,rgba(23,23,23,0.05),transparent_62%)] dark:bg-[radial-gradient(circle_at_center,rgba(255,255,255,0.06),transparent_62%)]"
          />

          <motion.svg
            variants={orchestra}
            viewBox="0 0 100 100"
            className="absolute inset-0 h-full w-full"
            aria-hidden="true"
          >
            {scatter.map((dot, index) => (
              <motion.circle
                key={index}
                variants={fadeIn}
                cx={dot.cx}
                cy={dot.cy}
                r={dot.r}
                className="fill-neutral-300 dark:fill-neutral-700"
              />
            ))}
            <motion.circle
              variants={fadeIn}
              cx="50"
              cy="50"
              r="40"
              fill="none"
              vectorEffect="non-scaling-stroke"
              strokeWidth={1}
              className="stroke-neutral-200 dark:stroke-neutral-800"
            />
            <motion.circle
              variants={fadeIn}
              cx="50"
              cy="50"
              r="26"
              fill="none"
              vectorEffect="non-scaling-stroke"
              strokeWidth={1}
              strokeDasharray="0.3 2.4"
              strokeLinecap="round"
              className="stroke-neutral-300/80 dark:stroke-neutral-700/80"
            />
            {nodes.map((node) => (
              <motion.line
                key={node.en}
                variants={draw}
                x1="50"
                y1="50"
                x2={node.x}
                y2={node.y}
                vectorEffect="non-scaling-stroke"
                strokeWidth={1.25}
                strokeLinecap="round"
                className="stroke-neutral-200 dark:stroke-neutral-800"
              />
            ))}
          </motion.svg>

          <motion.div
            variants={pop}
            className="absolute left-1/2 top-1/2 z-10 -translate-x-1/2 -translate-y-1/2"
          >
            <div className="relative flex h-24 w-24 items-center justify-center rounded-3xl border border-neutral-200 bg-white shadow-xl shadow-neutral-300/40 dark:border-neutral-700 dark:bg-neutral-900 dark:shadow-black/40 sm:h-28 sm:w-28">
              {!reduce && (
                <motion.span
                  aria-hidden="true"
                  animate={{ scale: [1, 1.3, 1], opacity: [0.45, 0, 0.45] }}
                  transition={{
                    duration: 3.2,
                    repeat: Infinity,
                    ease: "easeInOut",
                  }}
                  className="absolute inset-0 rounded-3xl border border-neutral-300 dark:border-neutral-600"
                />
              )}
              <Boxes
                className="h-10 w-10 text-neutral-900 dark:text-white sm:h-11 sm:w-11"
                strokeWidth={1.5}
              />
              <span className="absolute left-1/2 top-full mt-3 -translate-x-1/2 whitespace-nowrap rounded-full bg-white px-2 text-[11px] font-medium uppercase tracking-[0.18em] text-neutral-400 dark:bg-neutral-950 dark:text-neutral-500">
                OpenXDR
              </span>
            </div>
          </motion.div>

          {nodes.map((node, index) => {
            const Icon = node.icon;
            return (
              <motion.div
                key={node.en}
                variants={pop}
                style={{ left: `${node.x}%`, top: `${node.y}%` }}
                className="absolute z-20 -translate-x-1/2 -translate-y-1/2"
              >
                <motion.div
                  animate={reduce ? undefined : { y: [0, -5, 0] }}
                  transition={
                    reduce
                      ? undefined
                      : {
                          duration: 4.2 + index * 0.35,
                          repeat: Infinity,
                          ease: "easeInOut",
                        }
                  }
                  className="relative"
                >
                  <motion.div
                    whileHover={{ y: -3, scale: 1.02 }}
                    transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                    className="flex h-14 w-14 items-center justify-center rounded-2xl border border-neutral-200 bg-white shadow-lg shadow-neutral-200/60 transition-colors duration-200 hover:border-neutral-300 dark:border-neutral-800 dark:bg-neutral-900 dark:shadow-black/40 dark:hover:border-neutral-600 sm:h-16 sm:w-16"
                  >
                    <Icon
                      className="h-6 w-6 text-neutral-700 dark:text-neutral-300 sm:h-7 sm:w-7"
                      strokeWidth={1.5}
                    />
                  </motion.div>
                  <span className="absolute left-1/2 top-full mt-2 -translate-x-1/2 whitespace-nowrap rounded-full bg-white px-1.5 text-[11px] font-medium text-neutral-500 dark:bg-neutral-950 dark:text-neutral-400">
                    {locale === "zh-CN" ? node.zh : node.en}
                  </span>
                </motion.div>
              </motion.div>
            );
          })}
        </motion.div>
      </div>
    </section>
  );
}
