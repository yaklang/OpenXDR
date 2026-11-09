"use client";

import { motion, useReducedMotion, type Variants } from "motion/react";
import { Logo } from "@/components/logo";
import { Github } from "lucide-react";
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
          summary:
            "开源的自治 XDR：它全天值守，你只需说清意图。",
          copyright: "© 2026 OpenXDR 贡献者",
          navGroups: [
            {
              title: "平台",
              links: [
                { label: "接入", href: "#onboard" },
                { label: "安全", href: "#secure" },
                { label: "资产", href: "#surface" },
                { label: "意图", href: "#intent" },
                { label: "自治", href: "#respond" },
                { label: "运维", href: "#operate" },
                { label: "开始", href: "#start" },
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
                { label: "部署文档", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/deployment.md" },
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
          summary:
            "Open-source autonomous XDR: it keeps the watch, you bring the intent.",
          copyright: "© 2026 OpenXDR contributors",
          navGroups: [
            {
              title: "Platform",
              links: [
                { label: "Onboard", href: "#onboard" },
                { label: "Secure", href: "#secure" },
                { label: "Assets", href: "#surface" },
                { label: "Intent", href: "#intent" },
                { label: "Autonomy", href: "#respond" },
                { label: "Operate", href: "#operate" },
                { label: "Start", href: "#start" },
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
                { label: "Deployment", href: "https://github.com/yaklang/OpenXDR/blob/master/docs/deployment.md" },
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
          className="grid grid-cols-2 gap-x-8 gap-y-10 sm:grid-cols-4 lg:grid-cols-[1.35fr_1fr_1fr_1fr_1fr]"
        >
          <div className="col-span-2 sm:col-span-4 lg:col-span-1">
            <p className="flex items-center gap-2.5 text-lg font-semibold tracking-tight text-neutral-900 dark:text-white">
              <Logo />
              OpenXDR
            </p>
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
