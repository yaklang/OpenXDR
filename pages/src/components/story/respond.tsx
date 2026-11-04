import { motion } from "motion/react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE, StepList, useScrollSteps } from "./chapter";

// 一次内网跳板攻击从落地到收场：每一步的时刻（示意，来自一次真实攻击的复盘），以及决策记录里多出的那一行
type Row = { time: string; host: string; action: string; state: "contain" | "block" | "review" | "trace" };

const STATE = {
  contain: "bg-rose-400",
  block: "bg-amber-300",
  review: "bg-emerald-300",
  trace: "bg-neutral-500",
};

const COPY = {
  "zh-CN": {
    kicker: "自主响应",
    title: (
      <>
        你还没醒，
        <br />
        <span className="text-neutral-500">它已经收场。</span>
      </>
    ),
    body: "确定的攻击，不必等人。\n它按谁是来源、谁是受害者下手，每一步都留下理由，随时可以撤回。",
    times: ["03:12", "03:41", "+5 秒", "+5 秒", "次日", "醒来"],
    steps: [
      ["跳板落地", "靶场里一个容器被拿下，开始对内网逐台试 SSH 口令"],
      ["喷洒成立", "第三台主机记下了来自同一地址的失败登录"],
      ["只断一个容器", "宿主机和它上面的其他容器照常运行"],
      ["受害方封锁来源", "三台主机封锁来源地址，没有一台被整机隔离"],
      ["AI 复核", "租约到期：来源已清理、再无新证据，解除封锁"],
      ["你醒来", "每一行决定都写着理由，任何一条都能一键撤回"],
    ] as [string, string][],
    console: "自主响应 · 决策记录",
    demo: "示意数据",
    rows: [
      { time: "03:12", host: "range-host", action: "容器 ctf-07 对 6 台主机试 SSH 口令", state: "trace" },
      { time: "03:41", host: "range-host", action: "内网横向喷洒成立（5 级）", state: "trace" },
      { time: "03:41", host: "range-host", action: "隔离容器 ctf-07", state: "contain" },
      { time: "03:41", host: "db-01 · web-02 · ci-03", action: "封锁 10.0.3.17", state: "block" },
      { time: "次日", host: "全部", action: "AI 复核：来源已清理，解除", state: "review" },
      { time: "—", host: "—", action: "6 条决定 · 0 次人工 · 均可撤回", state: "review" },
    ] as Row[],
  },
  en: {
    kicker: "Respond",
    title: (
      <>
        Before you wake,
        <br />
        <span className="text-neutral-500">it has already ended.</span>
      </>
    ),
    body: "A certain attack doesn't wait for anyone.\nIt acts on who is the source and who is the victim, writes down why, and lets you undo any of it.",
    times: ["03:12", "03:41", "+5s", "+5s", "next day", "morning"],
    steps: [
      ["A foothold", "a lab container is taken over and starts trying SSH passwords across the network"],
      ["Spray confirmed", "a third host logs failed logins from the same address"],
      ["One container goes dark", "the host and its other containers keep running"],
      ["Victims block the source", "three hosts block the source address; none of them is isolated"],
      ["AI review", "the lease expires: source cleaned up, no new evidence — lifted"],
      ["You wake up", "every decision carries its reason, and any of them undoes in one click"],
    ] as [string, string][],
    console: "Autonomous response · decision log",
    demo: "Illustrative",
    rows: [
      { time: "03:12", host: "range-host", action: "container ctf-07 tries SSH on 6 hosts", state: "trace" },
      { time: "03:41", host: "range-host", action: "internal lateral spray (severity 5)", state: "trace" },
      { time: "03:41", host: "range-host", action: "isolate container ctf-07", state: "contain" },
      { time: "03:41", host: "db-01 · web-02 · ci-03", action: "block 10.0.3.17", state: "block" },
      { time: "next day", host: "all", action: "AI review: source cleaned, lifted", state: "review" },
      { time: "—", host: "—", action: "6 decisions · 0 humans · all reversible", state: "review" },
    ] as Row[],
  },
};

export function Respond() {
  const t = useCopy(COPY);
  const { ref, wide, step, progress } = useScrollSteps(t.steps.length);

  const head = <ChapterHead index="04" kicker={t.kicker} title={t.title} body={t.body} tone="rose" />;

  // 决策记录逐行出现：走到第几步就显示到第几行，后面留空行占位不剧透
  const demo = (
    <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
      <ol className="divide-y divide-white/5 p-2 sm:p-3" aria-live="polite">
        {t.rows.map((row, i) => {
          const shown = i <= step;
          return (
            <li key={i} className="flex min-h-[56px] items-center gap-3 px-3 py-3">
              {shown ? (
                <motion.div
                  initial={{ opacity: 0, x: -12, filter: "blur(6px)" }}
                  animate={{ opacity: 1, x: 0, filter: "blur(0px)" }}
                  transition={{ duration: 0.5, ease: EASE }}
                  className="flex w-full items-center gap-3"
                >
                  <span className="w-16 shrink-0 font-mono text-xs tabular-nums text-neutral-500">{row.time}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-white">{row.action}</span>
                    <span className="block truncate font-mono text-[11px] text-neutral-500">{row.host}</span>
                  </span>
                  <span className={`h-2 w-2 shrink-0 rounded-full ${STATE[row.state]}`} />
                </motion.div>
              ) : (
                <span className="h-2 w-full rounded-full bg-white/[0.04]" />
              )}
            </li>
          );
        })}
      </ol>
    </Console>
  );

  return (
    <section id="respond" className="relative scroll-mt-20">
      {!wide && <div className="px-4 pt-28 sm:px-6">{head}</div>}
      <div ref={ref} className={wide ? "relative h-[280vh]" : "relative"}>
        <div className={wide ? "sticky top-0 flex h-screen items-center overflow-hidden px-8" : "px-4 pb-28 pt-10 sm:px-6"}>
          <div className="mx-auto grid w-full max-w-[1400px] gap-10 lg:grid-cols-[minmax(0,4fr)_minmax(0,7fr)] lg:items-center">
            <div>
              {wide && <div className="mb-10">{head}</div>}
              <StepList steps={t.steps} step={step} wide={wide} progress={progress} lead={(i) => t.times[i]} tone="rose" />
            </div>
            {demo}
          </div>
        </div>
      </div>
    </section>
  );
}
