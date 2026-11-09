import { ArrowRight } from "lucide-react";
import { motion, useMotionValueEvent, useScroll, type MotionValue } from "motion/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useLocale } from "@/i18n";

export const EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

/** 一条数据：机器产生的写成字符串，人产生的写成 { you }，整页统一用绿色标出。 */
export type Datum = string | { you: string };
/** 一个章节读哪些数据、写回哪些数据。 */
export type Flow = { reads: Datum[]; writes: Datum[] };

function Chip({ d }: { d: Datum }) {
  const you = typeof d !== "string";
  return (
    <span
      className={`rounded-md border px-1.5 py-0.5 ${
        you ? "border-emerald-300/30 bg-emerald-400/[0.08] text-emerald-200" : "border-white/10 text-neutral-400"
      }`}
    >
      {you ? d.you : d}
    </span>
  );
}

/** 章节的数据流：读 → 写。 */
function FlowLine({ flow }: { flow: Flow }) {
  const zh = useLocale() === "zh-CN";
  return (
    <div className="mt-6 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
      <span className="mr-0.5 text-neutral-500">{zh ? "读" : "reads"}</span>
      {flow.reads.map((d) => (
        <Chip key={typeof d === "string" ? d : d.you} d={d} />
      ))}
      <ArrowRight className="mx-1 h-3 w-3 text-neutral-600" />
      <span className="mr-0.5 text-neutral-500">{zh ? "写" : "writes"}</span>
      {flow.writes.map((d) => (
        <Chip key={typeof d === "string" ? d : d.you} d={d} />
      ))}
    </div>
  );
}

/** 叙事章节的标题区：序号 + 主题词 + 标题 + 说明。 */
export function ChapterHead({
  index,
  kicker,
  title,
  body,
  flow,
  tone = "emerald",
}: {
  index: string;
  kicker: string;
  title: ReactNode;
  body: ReactNode;
  flow?: Flow;
  tone?: "emerald" | "rose" | "amber" | "sky";
}) {
  const color = {
    emerald: "text-emerald-300",
    rose: "text-rose-300",
    amber: "text-amber-300",
    sky: "text-sky-300",
  }[tone];
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.8, ease: EASE }}
      className="max-w-2xl"
    >
      <p className={`font-mono text-xs uppercase tracking-[0.22em] ${color}`}>
        {index} · {kicker}
      </p>
      <h2 className="mt-5 text-3xl font-medium leading-[1.08] tracking-[-0.03em] text-white sm:text-5xl">
        {title}
      </h2>
      <p className="mt-5 whitespace-pre-line text-base leading-relaxed text-neutral-400 sm:text-lg">
        {body}
      </p>
      {flow && <FlowLine flow={flow} />}
    </motion.div>
  );
}

/** 控制台外框：模拟 OpenXDR 控制台的一块面板。 */
export function Console({
  title,
  badge,
  children,
  className = "",
}: {
  title: string;
  badge?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`overflow-hidden rounded-2xl border border-white/10 bg-neutral-900/70 shadow-[0_40px_120px_-40px_rgba(16,185,129,0.25)] backdrop-blur ${className}`}
    >
      <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="ml-2 truncate text-xs text-neutral-400">{title}</span>
        {badge && <span className="ml-auto shrink-0">{badge}</span>}
      </div>
      {children}
    </div>
  );
}

export function DemoBadge({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-neutral-500">
      {label}
    </span>
  );
}

/** 宽屏才钉住滚动：窄屏一屏放不下整幅演示，直接给终态，免得手机上来回滑。 */
export function useWide() {
  const query = "(min-width: 1024px)";
  const [wide, setWide] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const m = window.matchMedia(query);
    const on = () => setWide(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return wide;
}

/** 滚动驱动的分步：外层撑出滚动距离，按进度落到第几步；窄屏恒为最后一步。 */
export function useScrollSteps(count: number) {
  const ref = useRef<HTMLDivElement>(null);
  const wide = useWide();
  const [step, setStep] = useState(0);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end end"] });
  useMotionValueEvent(scrollYProgress, "change", (p) =>
    setStep(Math.min(count - 1, Math.max(0, Math.floor(p * count * 1.05)))),
  );
  return { ref, wide, step: wide ? step : count - 1, progress: scrollYProgress };
}

const BAR = {
  emerald: "to-emerald-400",
  rose: "to-rose-400",
  amber: "to-amber-400",
  sky: "to-sky-400",
};

/** 分步清单：当前步高亮并展开说明，后面的变淡；左侧细线随滚动填满。窄屏全部展开。 */
export function StepList({
  steps,
  step,
  wide,
  progress,
  lead,
  tone = "emerald",
}: {
  steps: [string, string][];
  step: number;
  wide: boolean;
  progress: MotionValue<number>;
  lead: (i: number) => ReactNode;
  tone?: keyof typeof BAR;
}) {
  return (
    <div className="relative">
      <div className="absolute bottom-2 left-0 top-2 w-px bg-white/10" />
      {wide && (
        <motion.div
          className={`absolute bottom-2 left-0 top-2 w-px origin-top bg-gradient-to-b from-neutral-300 ${BAR[tone]}`}
          style={{ scaleY: progress }}
        />
      )}
      <ol className="space-y-1 pl-3">
        {steps.map(([name, desc], i) => {
          const on = wide ? i === step : true;
          return (
            <li
              key={name}
              className={`flex items-baseline gap-4 rounded-lg px-3 py-2 transition-all duration-500 ${
                wide && i === step ? "bg-white/[0.06]" : ""
              } ${wide && i > step ? "opacity-30" : ""}`}
            >
              <span className="w-16 shrink-0 text-right font-mono text-xs tabular-nums text-neutral-500">{lead(i)}</span>
              <span>
                <span className={`text-sm ${on ? "text-white" : "text-neutral-400"}`}>{name}</span>
                {on && <span className="mt-0.5 block text-xs leading-relaxed text-neutral-500">{desc}</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
