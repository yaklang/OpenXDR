"use client";

import { motion, useReducedMotion, type Variants } from "motion/react";
import { ArrowRight, Github } from "lucide-react";
import { useLocale } from "@/i18n";

const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-white dark:focus-visible:ring-offset-neutral-950";

const container: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.12, delayChildren: 0.05 } },
};

const item: Variants = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] } },
};

export default function Footer12() {
  const locale = useLocale();
  const reduce = useReducedMotion();
  const copy =
    locale === "zh-CN"
      ? {
          project: "OpenXDR 项目",
          heading: "安全遥测应该成为证据，而不是另一条告警队列。",
          description:
            "检查代码、运行采集器、回放检测语料，共同打造一套推理过程始终可见的 XDR 技术栈。",
          repositoryCta: "浏览代码仓库",
          pipelineCta: "阅读处理链路",
          dispatches: ["EDR", "NDR", "SIEM", "AI 辅助研判"],
          vitals: [
            { label: "代码仓库", value: "GitHub 公开项目", live: true },
            { label: "采集器", value: "Rust · Linux / Windows" },
            { label: "核心", value: "Go · PostgreSQL" },
            { label: "界面", value: "React" },
          ],
          summary:
            "面向安全团队的开源 XDR：更少告警、更强证据，以及从信号到响应的透明路径。",
          copyright: "© 2026 OpenXDR 贡献者",
          navGroups: [
            {
              title: "平台",
              links: [
                { label: "信号", href: "#signals" },
                { label: "处理链路", href: "#pipeline" },
                { label: "设计原则", href: "#principles" },
              ],
            },
            {
              title: "项目",
              links: [
                { label: "代码仓库", href: "https://github.com/yaklang/OpenXDR" },
                { label: "路线图", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/roadmap.md" },
                { label: "Issues", href: "https://github.com/yaklang/OpenXDR/issues" },
              ],
            },
            {
              title: "参考",
              links: [
                { label: "README", href: "https://github.com/yaklang/OpenXDR#readme" },
                { label: "API", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/api.md" },
                { label: "架构", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/architecture.md" },
              ],
            },
            {
              title: "构建",
              links: [
                { label: "Actions", href: "https://github.com/yaklang/OpenXDR/actions" },
                { label: "检测规则", href: "https://github.com/yaklang/OpenXDR/tree/master/rules" },
                { label: "验证语料", href: "https://github.com/yaklang/OpenXDR/tree/master/validation" },
              ],
            },
          ],
        }
      : {
          project: "OpenXDR project",
          heading: "Security telemetry should become evidence, not another alert queue.",
          description:
            "Inspect the code, run the collectors, replay the detection corpus, and help shape an XDR stack whose reasoning stays visible.",
          repositoryCta: "Explore the repository",
          pipelineCta: "Read the pipeline",
          dispatches: ["EDR", "NDR", "SIEM", "AI-assisted triage"],
          vitals: [
            { label: "Repository", value: "Public on GitHub", live: true },
            { label: "Collectors", value: "Rust · Linux / Windows" },
            { label: "Core", value: "Go · PostgreSQL" },
            { label: "Interface", value: "React" },
          ],
          summary:
            "Open-source XDR for teams that want fewer alerts, stronger evidence, and an inspectable path from signal to response.",
          copyright: "© 2026 OpenXDR contributors",
          navGroups: [
            {
              title: "Platform",
              links: [
                { label: "Signals", href: "#signals" },
                { label: "Pipeline", href: "#pipeline" },
                { label: "Principles", href: "#principles" },
              ],
            },
            {
              title: "Project",
              links: [
                { label: "Repository", href: "https://github.com/yaklang/OpenXDR" },
                { label: "Roadmap", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/roadmap.md" },
                { label: "Issues", href: "https://github.com/yaklang/OpenXDR/issues" },
              ],
            },
            {
              title: "Reference",
              links: [
                { label: "README", href: "https://github.com/yaklang/OpenXDR#readme" },
                { label: "API", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/api.md" },
                { label: "Architecture", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/architecture.md" },
              ],
            },
            {
              title: "Build",
              links: [
                { label: "Actions", href: "https://github.com/yaklang/OpenXDR/actions" },
                { label: "Detection rules", href: "https://github.com/yaklang/OpenXDR/tree/master/rules" },
                { label: "Validation", href: "https://github.com/yaklang/OpenXDR/tree/master/validation" },
              ],
            },
          ],
        };

  return (
    <footer className="w-full bg-white px-4 py-16 dark:bg-neutral-950 sm:px-6 sm:py-20 lg:px-8 lg:py-24">
      <motion.div
        variants={container}
        initial={reduce ? false : "hidden"}
        whileInView="visible"
        viewport={{ once: true, margin: "-80px" }}
        className="mx-auto w-full max-w-[1400px]"
      >
        <motion.div
          variants={item}
          className="relative overflow-hidden rounded-3xl bg-neutral-900 p-7 ring-1 ring-neutral-950/10 dark:ring-white/10 sm:p-10 lg:p-14"
        >
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-white/[0.04] blur-3xl"
          />
          <div className="relative grid grid-cols-1 gap-10 lg:grid-cols-[1.2fr_1fr] lg:gap-16">
            <div>
              <div className="flex items-center gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-base font-semibold text-neutral-900">
                  OX
                </span>
                <span className="text-sm font-medium text-neutral-400">{copy.project}</span>
              </div>
              <h2 className="mt-8 max-w-xl text-3xl font-medium leading-[1.12] tracking-tight text-white sm:text-4xl">
                {copy.heading}
              </h2>
              <p className="mt-4 max-w-md text-sm leading-relaxed text-neutral-400 sm:text-base">
                {copy.description}
              </p>
              <div className="mt-8 flex w-full max-w-md flex-col gap-3 sm:flex-row">
                <a
                  href="https://github.com/yaklang/OpenXDR"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex cursor-pointer items-center justify-center gap-2 rounded-full bg-white px-6 py-3 text-sm font-medium text-neutral-900 transition-colors duration-200 hover:bg-neutral-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-neutral-900"
                >
                  {copy.repositoryCta}
                  <ArrowRight className="h-4 w-4" />
                </a>
                <a
                  href="#pipeline"
                  className="inline-flex cursor-pointer items-center justify-center rounded-full border border-white/15 bg-white/[0.04] px-6 py-3 text-sm font-medium text-white transition-colors duration-200 hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white"
                >
                  {copy.pipelineCta}
                </a>
              </div>
              <div className="mt-5 flex flex-wrap gap-2">
                {copy.dispatches.map((chip) => (
                  <span
                    key={chip}
                    className="rounded-full border border-white/10 px-3 py-1 text-xs font-medium text-neutral-400"
                  >
                    {chip}
                  </span>
                ))}
              </div>
            </div>

            <div className="flex flex-col justify-center border-t border-white/10 pt-10 lg:border-l lg:border-t-0 lg:pl-14 lg:pt-0">
              <dl className="divide-y divide-white/10">
                {copy.vitals.map((vital) => (
                  <div key={vital.label} className="flex items-center justify-between gap-6 py-4 first:pt-0 last:pb-0">
                    <dt className="text-xs font-medium uppercase tracking-[0.16em] text-neutral-500">{vital.label}</dt>
                    <dd className="flex items-center gap-2.5 text-right text-sm font-medium text-white">
                      {vital.live && (
                        <span className="relative flex h-2.5 w-2.5">
                          {!reduce && (
                            <motion.span
                              aria-hidden="true"
                              className="absolute inline-flex h-full w-full rounded-full bg-emerald-400"
                              animate={{ scale: [1, 2.1], opacity: [0.5, 0] }}
                              transition={{ duration: 1.8, repeat: Infinity, ease: "easeOut" }}
                            />
                          )}
                          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
                        </span>
                      )}
                      {vital.value}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          </div>
        </motion.div>

        <motion.div
          variants={item}
          className="mt-14 grid grid-cols-2 gap-x-8 gap-y-10 sm:grid-cols-4 lg:grid-cols-[1.35fr_1fr_1fr_1fr_1fr]"
        >
          <div className="col-span-2 sm:col-span-4 lg:col-span-1">
            <p className="text-lg font-semibold tracking-tight text-neutral-900 dark:text-white">OpenXDR</p>
            <p className="mt-3 max-w-[28ch] text-sm leading-relaxed text-neutral-500 dark:text-neutral-400">
              {copy.summary}
            </p>
          </div>
          {copy.navGroups.map((group) => (
            <nav key={group.title} aria-label={group.title} className="min-w-0">
              <h3 className="mb-5 text-xs font-medium uppercase tracking-[0.16em] text-neutral-500 dark:text-neutral-500">
                {group.title}
              </h3>
              <ul className="space-y-3">
                {group.links.map((link) => (
                  <li key={link.label}>
                    <a
                      href={link.href}
                      target={link.href.startsWith("http") ? "_blank" : undefined}
                      rel={link.href.startsWith("http") ? "noreferrer" : undefined}
                      className={`rounded-sm text-sm text-neutral-600 transition-colors duration-200 hover:text-neutral-950 dark:text-neutral-400 dark:hover:text-white ${focusRing}`}
                    >
                      {link.label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          ))}
        </motion.div>

        <motion.div
          variants={item}
          className="mt-14 flex flex-col gap-4 border-t border-neutral-200 pt-6 dark:border-neutral-800 sm:flex-row sm:items-center sm:justify-between"
        >
          <p className="text-sm text-neutral-500 dark:text-neutral-500">{copy.copyright}</p>
          <div className="flex items-center gap-1">
            <a
              href="https://github.com/yaklang/OpenXDR"
              target="_blank"
              rel="noreferrer"
              aria-label="GitHub"
              className="flex h-9 w-9 items-center justify-center rounded-full text-neutral-500 transition-colors duration-200 hover:bg-neutral-100 hover:text-neutral-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 dark:text-neutral-500 dark:hover:bg-neutral-900 dark:hover:text-white dark:focus-visible:ring-white"
            >
              <Github className="h-[18px] w-[18px]" />
            </a>
          </div>
        </motion.div>
      </motion.div>
    </footer>
  );
}
