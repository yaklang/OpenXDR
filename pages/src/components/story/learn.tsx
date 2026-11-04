import { motion } from "motion/react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE, StepList, useScrollSteps } from "./chapter";

// 每一步发生在第几天，之后每天需要人看的事件降到多少（示意量级，与漏斗章节的终点 3 对齐）
const LEVELS = [
  { day: 1, level: 41 },
  { day: 3, level: 30 },
  { day: 6, level: 19 },
  { day: 10, level: 10 },
  { day: 18, level: 5 },
  { day: 30, level: 3 },
];
const DAYS = 30;

/** 每天的量：落在当前台阶上，加一点稳定的起伏；最后一天恰好是 3。 */
const SERIES = Array.from({ length: DAYS }, (_, i) => {
  const day = i + 1;
  const level = [...LEVELS].reverse().find((l) => l.day <= day)!.level;
  if (day === DAYS) return level;
  const wobble = ((day * 7) % 5) - 2;
  return Math.max(2, level + Math.round((wobble * level) / 12));
});
const MAX = Math.max(...SERIES);

type Card = { head: string; line: string; tag?: string };

const COPY = {
  "zh-CN": {
    kicker: "学习",
    title: (
      <>
        越用，
        <br />
        <span className="text-neutral-500">越安静。</span>
      </>
    ),
    body: "它不替你做决定。\n但你做过的每个决定，它都记得。",
    day: (d: number) => `第 ${d} 天`,
    steps: [
      ["刚接入", "每天四十来件事件等你复核，大多似曾相识"],
      ["AI 提议抑制", "同一类下载告警反复出现。AI 提议只压这个域名，90 天。你批准了"],
      ["说一次，就记住", "你告诉它备份机每天凌晨跑 rsync。从此研判都会参考这一条"],
      ["基线学完", "首次出现检测先学习、后告警。熟悉的进程与外连，不再打扰你"],
      ["结案建议，一键采纳", "AI 写好定性与说明，你确认后记在你名下，也成了它下次研判的案例"],
      ["一个月后", "每天只剩三件。件件值得看"],
    ] as [string, string][],
    console: "总览 · 每天需要你看的事件",
    demo: "示意数据",
    today: "当天需要你看",
    unit: "件",
    cards: [
      { head: "待复核 41 件", line: "其中 23 件来自同一个域名的下载告警" },
      { head: "抑制提议 · 90 天", line: "条件：域名 = updates.example.com", tag: "已批准 · 你" },
      { head: "已记住", line: "backup-01 每天 01:00 跑 rsync，属正常", tag: "来源 · 你" },
      { head: "首次出现 · 学习期结束", line: "已熟悉 214 个进程、38 个外连目的" },
      { head: "结案建议 · 低危良性", line: "管理员例行变更，与变更单时间吻合", tag: "已采纳 · 你" },
      { head: "待复核 3 件", line: "SSH 爆破得手、新增 sudo 账户、陌生进程监听 4444" },
    ] as Card[],
    axis: ["第 1 天", "第 30 天"],
  },
  en: {
    kicker: "Learn",
    title: (
      <>
        The longer it runs,
        <br />
        <span className="text-neutral-500">the quieter it gets.</span>
      </>
    ),
    body: "It never decides for you.\nBut it remembers every decision you make.",
    day: (d: number) => `Day ${d}`,
    steps: [
      ["Day one", "forty-odd incidents a day to review, most of them familiar"],
      ["AI proposes a suppression", "the same download alert keeps coming back. The AI proposes muting just that domain for 90 days. You approve"],
      ["Tell it once", "you mention the backup host runs rsync every night. Every triage takes it into account from now on"],
      ["Baselines learned", "first-seen detection learns before it alerts. Familiar processes and destinations stop bothering you"],
      ["Close in one click", "the AI drafts a verdict and notes; you confirm, it's recorded under your name and becomes a case it learns from"],
      ["A month later", "three a day. Every one worth your time"],
    ] as [string, string][],
    console: "Overview · incidents that need you, per day",
    demo: "Illustrative",
    today: "needed you that day",
    unit: "",
    cards: [
      { head: "41 to review", line: "23 of them are download alerts for one domain" },
      { head: "Suppression proposal · 90 days", line: "When: domain = updates.example.com", tag: "Approved · you" },
      { head: "Remembered", line: "backup-01 runs rsync at 01:00 daily — expected", tag: "From · you" },
      { head: "First-seen · learning complete", line: "214 processes and 38 destinations now familiar" },
      { head: "Close suggestion · benign, low risk", line: "Routine admin change, matches the change ticket", tag: "Accepted · you" },
      { head: "3 to review", line: "SSH brute force, new sudo account, unknown listener on 4444" },
    ] as Card[],
    axis: ["Day 1", "Day 30"],
  },
};

export function Learn() {
  const t = useCopy(COPY);
  const { ref, wide, step, progress } = useScrollSteps(LEVELS.length);
  const day = LEVELS[step].day;
  const card = t.cards[step];
  const last = step === LEVELS.length - 1;

  const head = <ChapterHead index="06" kicker={t.kicker} title={t.title} body={t.body} />;

  const demo = (
    <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
      <div className="p-5 sm:p-6">
        <div className="flex items-baseline gap-3">
          <motion.span
            key={day}
            initial={{ opacity: 0, y: 10, filter: "blur(6px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            transition={{ duration: 0.5, ease: EASE }}
            className={`font-mono text-6xl font-medium tabular-nums tracking-tight ${last ? "text-emerald-300" : "text-white"}`}
          >
            {SERIES[day - 1]}
          </motion.span>
          <span className="text-sm text-neutral-500">
            {t.unit && `${t.unit} · `}
            {t.day(day)} {t.today}
          </span>
        </div>

        {/* 单序列柱图：只画走到的天数，后面留平底占位不剧透；台阶落点标序号；悬停看当天数值 */}
        <div className="relative mt-8 flex h-44 items-end gap-[3px]" role="img" aria-label={`${t.console}: ${SERIES.join(", ")}`}>
          {SERIES.map((v, i) => {
            const d = i + 1;
            const mark = LEVELS.findIndex((l) => l.day === d);
            const reached = d <= day;
            return (
              <div key={d} className="relative flex h-full flex-1 items-end" title={reached ? `${t.day(d)}: ${v}` : undefined}>
                <motion.div
                  className={`w-full rounded-t-[4px] ${
                    d === day ? "bg-emerald-300" : reached ? "bg-emerald-400/45" : "bg-white/[0.06]"
                  }`}
                  initial={false}
                  animate={{ height: reached ? `${(v / MAX) * 100}%` : "3%" }}
                  transition={{ duration: 0.6, ease: EASE }}
                />
                {mark > 0 && (
                  <span
                    className={`absolute left-1/2 -translate-x-1/2 rounded-full px-1 font-mono text-[9px] transition-colors duration-500 ${
                      reached ? "bg-emerald-300 text-neutral-950" : "opacity-0"
                    }`}
                    style={{ bottom: `calc(${(v / MAX) * 100}% + 6px)` }}
                  >
                    {mark}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        <div className="mt-2 flex justify-between border-t border-white/10 pt-2 text-[10px] text-neutral-500">
          <span>{t.axis[0]}</span>
          <span>{t.axis[1]}</span>
        </div>

        <motion.div
          key={step}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: EASE }}
          className="mt-6 flex min-h-[72px] items-start gap-3 rounded-xl border border-white/10 bg-black/40 p-4"
          aria-live="polite"
        >
          <span className="mt-0.5 shrink-0 rounded-full bg-emerald-300 px-1.5 font-mono text-[10px] text-neutral-950">
            {step || "·"}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm text-white">{card.head}</p>
            <p className="mt-1 font-mono text-xs leading-relaxed text-neutral-400">{card.line}</p>
          </div>
          {card.tag && <span className="shrink-0 rounded-full bg-white/10 px-2 py-0.5 text-[10px] text-neutral-300">{card.tag}</span>}
        </motion.div>
      </div>
    </Console>
  );

  return (
    <section id="learn" className="relative scroll-mt-20">
      {!wide && <div className="px-4 pt-28 sm:px-6">{head}</div>}
      <div ref={ref} className={wide ? "relative h-[280vh]" : "relative"}>
        <div className={wide ? "sticky top-0 flex h-screen items-center overflow-hidden px-8" : "px-4 pb-28 pt-10 sm:px-6"}>
          <div className="mx-auto grid w-full max-w-[1400px] gap-10 lg:grid-cols-[minmax(0,4fr)_minmax(0,7fr)] lg:items-center">
            <div>
              {wide && <div className="mb-10">{head}</div>}
              <StepList steps={t.steps} step={step} wide={wide} progress={progress} lead={(i) => t.day(LEVELS[i].day)} />
            </div>
            {demo}
          </div>
        </div>
      </div>
    </section>
  );
}
