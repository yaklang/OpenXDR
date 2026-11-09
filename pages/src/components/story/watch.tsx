import { AnimatePresence, motion, useMotionValueEvent, useScroll } from "motion/react";
import { useEffect, useState } from "react";
import { useCopy } from "@/i18n";
import { EASE } from "./chapter";

// 页面上一直在值守的那一行：滚过首屏后出现在左下角，轮着说它正在做的事（与各章节演示同一个夜晚）
const COPY = {
  "zh-CN": {
    label: "值守中",
    lines: [
      "03:41 隔离容器 ctf-07 · 依据：你的记忆",
      "03:41 db-01 等三台主机封锁 10.0.3.17",
      "04:30 old-db 已下线，失联不推送",
      "06:05 web-02 内部更新，判良性并结案",
      "09:30 记住了：靶场只准打 10.0.3.0/24",
      "10:00 每日巡检报告已写好",
    ],
  },
  en: {
    label: "On watch",
    lines: [
      "03:41 isolated container ctf-07 · per your memory",
      "03:41 three hosts block 10.0.3.17",
      "04:30 old-db is retired — no page",
      "06:05 web-02 internal update, benign, closed",
      "09:30 remembered: the lab hits 10.0.3.0/24 only",
      "10:00 daily inspection report written",
    ],
  },
};

export function Watch() {
  const t = useCopy(COPY);
  const [shown, setShown] = useState(false);
  const [i, setI] = useState(0);
  const { scrollY } = useScroll();
  useMotionValueEvent(scrollY, "change", (y) => setShown(y > window.innerHeight * 0.8));

  useEffect(() => {
    if (!shown) return;
    const timer = setInterval(() => setI((n) => (n + 1) % t.lines.length), 3200);
    return () => clearInterval(timer);
  }, [shown, t.lines.length]);

  return (
    <AnimatePresence>
      {shown && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 16 }}
          transition={{ duration: 0.5, ease: EASE }}
          className="pointer-events-none fixed bottom-5 left-5 z-40 hidden items-center gap-2.5 rounded-full border border-white/10 bg-neutral-950/80 px-4 py-2 text-xs shadow-lg backdrop-blur-md lg:flex"
          aria-hidden
        >
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-300 opacity-70" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
          </span>
          <span className="shrink-0 text-emerald-300">{t.label}</span>
          <span className="relative h-4 w-[340px] overflow-hidden">
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={i}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.35, ease: EASE }}
                className="absolute inset-0 truncate font-mono text-neutral-300"
              >
                {t.lines[i]}
              </motion.span>
            </AnimatePresence>
          </span>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
