"use client";

import { useEffect, useState } from "react";
import {
  AnimatePresence,
  motion,
  useReducedMotion,
  type Variants,
} from "motion/react";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { useLocale } from "@/i18n";

const EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-900 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-white dark:focus-visible:ring-offset-neutral-950";

export default function Navigation15() {
  const locale = useLocale();
  const [hovered, setHovered] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const shouldReduceMotion = useReducedMotion();
  const copy =
    locale === "zh-CN"
      ? {
          links: [
            { label: "信号", href: "#signals" },
            { label: "处理链路", href: "#pipeline" },
            { label: "设计原则", href: "#principles" },
            { label: "代码仓库", href: "https://github.com/yaklang/OpenXDR" },
          ],
          primary: "主导航",
          build: "构建状态",
          source: "查看源码",
          open: "打开菜单",
          close: "关闭菜单",
          menu: "菜单",
          menuLinks: "菜单链接",
          openSource: "开源 XDR",
        }
      : {
          links: [
            { label: "Signals", href: "#signals" },
            { label: "Pipeline", href: "#pipeline" },
            { label: "Principles", href: "#principles" },
            { label: "Repository", href: "https://github.com/yaklang/OpenXDR" },
          ],
          primary: "Primary",
          build: "Build status",
          source: "View source",
          open: "Open menu",
          close: "Close menu",
          menu: "Menu",
          menuLinks: "Menu links",
          openSource: "Open source XDR",
        };
  const current = hovered ?? copy.links[0].label;

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    const query = window.matchMedia("(min-width: 768px)");
    const onChange = (event: MediaQueryListEvent) => {
      if (event.matches) setOpen(false);
    };
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  const drawerStagger: Variants = {
    hidden: {},
    visible: {
      transition: {
        staggerChildren: 0.06,
        delayChildren: shouldReduceMotion ? 0 : 0.2,
      },
    },
  };

  const drawerItem: Variants = {
    hidden: { opacity: 0, x: shouldReduceMotion ? 0 : 20 },
    visible: { opacity: 1, x: 0, transition: { duration: 0.45, ease: EASE } },
  };

  return (
    <header className="absolute inset-x-0 top-0 z-40 w-full">
      <div className="w-full">
        <motion.nav
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: EASE }}
          className="border-b border-white/10 bg-neutral-950/45 backdrop-blur-xl"
          aria-label={copy.primary}
        >
          <div className="mx-auto flex w-full max-w-[1400px] items-center justify-between gap-4 px-4 py-5 sm:px-6 lg:px-8">
          <a
            href="#"
            className={`flex items-center gap-2.5 rounded-sm text-lg font-semibold tracking-tight text-neutral-950 dark:text-white ${focusRing}`}
          >
            <span className="grid h-7 w-7 place-items-center rounded-lg border border-emerald-300/30 bg-emerald-300/10 text-[10px] font-bold text-emerald-200">
              OX
            </span>
            OpenXDR
          </a>

          <div
            className="hidden items-center gap-8 md:flex"
            onMouseLeave={() => setHovered(null)}
          >
            {copy.links.map((link) => (
              <a
                key={link.label}
                href={link.href}
                onMouseEnter={() => setHovered(link.label)}
                onFocus={() => setHovered(link.label)}
                onBlur={() => setHovered(null)}
                target={link.href.startsWith("http") ? "_blank" : undefined}
                rel={link.href.startsWith("http") ? "noreferrer" : undefined}
                className={`relative rounded-sm py-2 text-sm font-medium transition-colors duration-200 ${focusRing} ${
                  current === link.label
                    ? "text-neutral-950 dark:text-white"
                    : "text-neutral-500 dark:text-neutral-400"
                }`}
              >
                {link.label}
                {current === link.label && (
                  <motion.span
                    layoutId="nav15-line"
                    className="absolute inset-x-0 bottom-0 h-px bg-neutral-950 dark:bg-white"
                    transition={{ duration: 0.3, ease: EASE }}
                  />
                )}
              </a>
            ))}
          </div>

          <div className="hidden items-center gap-3 md:flex">
            <a
              href="https://github.com/yaklang/OpenXDR/actions"
              target="_blank"
              rel="noreferrer"
              className={`rounded-sm text-sm font-medium text-neutral-500 transition-colors duration-200 hover:text-neutral-950 dark:text-neutral-400 dark:hover:text-white ${focusRing}`}
            >
              {copy.build}
            </a>
            <a
              href="https://github.com/yaklang/OpenXDR"
              target="_blank"
              rel="noreferrer"
              className={`inline-flex items-center gap-1.5 rounded-full border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-950 transition-colors duration-200 hover:bg-neutral-950 hover:text-white dark:border-neutral-700 dark:text-white dark:hover:bg-white dark:hover:text-neutral-950 ${focusRing}`}
            >
              {copy.source}
              <ArrowUpRight className="h-4 w-4" />
            </a>
          </div>

          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-expanded={open}
            aria-controls="nav15-drawer"
            aria-label={copy.open}
            className={`flex h-11 w-11 cursor-pointer items-center justify-center rounded-full border border-neutral-200 text-neutral-950 transition-colors duration-200 hover:bg-neutral-50 dark:border-neutral-800 dark:text-white dark:hover:bg-neutral-900 md:hidden ${focusRing}`}
          >
            <Menu className="h-5 w-5" />
          </button>
          </div>
        </motion.nav>

        <AnimatePresence>
          {open && (
            <>
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25, ease: EASE }}
                className="fixed inset-0 z-40 bg-neutral-950/40 backdrop-blur-[2px] md:hidden"
                onClick={() => setOpen(false)}
                aria-hidden="true"
              />
              <motion.aside
                id="nav15-drawer"
                role="dialog"
                aria-modal="true"
                aria-label={copy.menu}
                initial={
                  shouldReduceMotion ? { opacity: 0 } : { x: "100%" }
                }
                animate={shouldReduceMotion ? { opacity: 1 } : { x: 0 }}
                exit={shouldReduceMotion ? { opacity: 0 } : { x: "100%" }}
                transition={{
                  duration: shouldReduceMotion ? 0.2 : 0.5,
                  ease: EASE,
                }}
                className="fixed inset-0 z-50 flex w-full flex-col overflow-y-auto bg-white px-6 pb-8 pt-5 dark:bg-neutral-950 md:hidden"
              >
                <div className="flex items-center justify-between border-b border-neutral-200 pb-5 dark:border-neutral-800">
                  <span className="flex items-center gap-2.5 text-lg font-semibold tracking-tight text-neutral-950 dark:text-white">
                    <span className="grid h-7 w-7 place-items-center rounded-lg border border-emerald-300/30 bg-emerald-300/10 text-[10px] font-bold text-emerald-200">
                      OX
                    </span>
                    OpenXDR
                  </span>
                  <button
                    type="button"
                    onClick={() => setOpen(false)}
                    aria-label={copy.close}
                    className={`flex h-11 w-11 cursor-pointer items-center justify-center rounded-full border border-neutral-200 text-neutral-950 transition-colors duration-200 hover:bg-neutral-50 dark:border-neutral-800 dark:text-white dark:hover:bg-neutral-900 ${focusRing}`}
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                <motion.nav
                  initial="hidden"
                  animate="visible"
                  variants={drawerStagger}
                  className="mt-8 flex flex-col"
                  aria-label={copy.menuLinks}
                >
                  <motion.p
                    variants={drawerItem}
                    className="text-xs font-medium uppercase tracking-[0.2em] text-neutral-500"
                  >
                    {copy.menu}
                  </motion.p>
                  {copy.links.map((link) => (
                    <motion.a
                      key={link.label}
                      href={link.href}
                      target={link.href.startsWith("http") ? "_blank" : undefined}
                      rel={link.href.startsWith("http") ? "noreferrer" : undefined}
                      variants={drawerItem}
                      onClick={() => setOpen(false)}
                      className={`group flex items-center justify-between border-b border-neutral-200 py-4 dark:border-neutral-800 ${focusRing}`}
                    >
                      <span className="text-2xl font-semibold tracking-tight text-neutral-950 transition-colors duration-200 group-hover:text-neutral-500 dark:text-white dark:group-hover:text-neutral-400">
                        {link.label}
                      </span>
                      <ArrowUpRight className="h-5 w-5 text-neutral-400 transition-colors duration-200 group-hover:text-neutral-950 dark:text-neutral-600 dark:group-hover:text-white" />
                    </motion.a>
                  ))}
                </motion.nav>

                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{
                    duration: 0.5,
                    delay: shouldReduceMotion ? 0.1 : 0.5,
                    ease: EASE,
                  }}
                  className="mt-auto pt-10"
                >
                  <p className="text-xs font-medium uppercase tracking-[0.2em] text-neutral-500">
                    {copy.openSource}
                  </p>
                  <a
                    href="https://github.com/yaklang/OpenXDR"
                    target="_blank"
                    rel="noreferrer"
                    className={`mt-2 inline-block rounded-sm text-base font-medium text-neutral-950 transition-colors duration-200 hover:text-neutral-500 dark:text-white dark:hover:text-neutral-400 ${focusRing}`}
                  >
                    github.com/yaklang/OpenXDR
                  </a>
                  <div className="mt-6 grid gap-2">
                    <a
                      href="https://github.com/yaklang/OpenXDR/actions"
                      target="_blank"
                      rel="noreferrer"
                      className={`rounded-full border border-neutral-300 px-5 py-3 text-center text-sm font-medium text-neutral-950 transition-colors duration-200 hover:bg-neutral-50 dark:border-neutral-700 dark:text-white dark:hover:bg-neutral-900 ${focusRing}`}
                    >
                      {copy.build}
                    </a>
                    <a
                      href="https://github.com/yaklang/OpenXDR"
                      target="_blank"
                      rel="noreferrer"
                      className={`inline-flex items-center justify-center gap-1.5 rounded-full bg-black px-5 py-3 text-sm font-medium text-white transition-colors duration-200 hover:bg-neutral-800 dark:bg-white dark:text-black dark:hover:bg-neutral-200 ${focusRing}`}
                    >
                      {copy.source}
                      <ArrowUpRight className="h-4 w-4" />
                    </a>
                  </div>
                </motion.div>
              </motion.aside>
            </>
          )}
        </AnimatePresence>
      </div>
    </header>
  );
}
