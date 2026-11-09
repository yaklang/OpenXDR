import { CheckCircle2, MessageSquareQuote, Plus, RotateCcw, Sparkles } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE } from "./chapter";

// 同一夜的四个信号：缺了人知道的那一句，判断就错；补上，就判对。与研判、巡检、对话读同一份组内记忆的口径一致
type Verdict = { verdict: string; action: string };
type Case = {
  time: string;
  host: string;
  signal: string;
  missing: string;
  intent: string;
  source: string;
  outcome: string;
  without: Verdict;
  with: Verdict;
};

const COPY = {
  "zh-CN": {
    kicker: "意图",
    title: (
      <>
        它没有变聪明，
        <br />
        <span className="text-neutral-500">只是知道得更多。</span>
      </>
    ),
    body: "AI 判错，几乎都因为少了一块数据：\n那个地址是备份，那台机器已经下线。\n这些只有你知道。说出来，它就成了数据。",
    points: [
      "说话就是录入：对话里说一句，它就写进本组记忆",
      "研判、巡检、对话读同一份记忆，你写的排在最前",
      "它自己记下的结论 30 天后要复核；你写的不会过期",
      "资产的角色和重要程度，你改过一次，AI 就不再覆盖",
      "每一次批准、驳回、结案也是数据：下次研判会翻出你当时的结论",
    ],
    console: "研判 · 生产组 · 同一个夜晚",
    demo: "演示",
    wrong: "件判错",
    told: (n: number, all: number) => `你说过 ${n} / ${all} 句`,
    allRight: "四件全部判对，没有一件需要你。",
    hint: "点开它不知道的事，告诉它。",
    tell: "告诉它",
    from: "来源 · 你",
    right: "判对",
    tellAll: "全部告诉它",
    reset: "重来",
    cases: [
      {
        time: "01:00",
        host: "backup-01",
        signal: "向 10.20.0.4 持续外传 38 GB",
        missing: "它不知道 10.20.0.4 是谁",
        intent: "10.20.0.4 是异地备份机，backup-01 每天 01:00 往那边同步",
        source: "对话",
        outcome: "误封 · 当晚备份中断",
        without: { verdict: "疑似数据外传", action: "封锁 10.20.0.4" },
        with: { verdict: "计划内备份", action: "不处置，记入早报" },
      },
      {
        time: "03:12",
        host: "range-host",
        signal: "容器 ctf-07 对 10.0.1.0/24 逐台试 SSH 口令",
        missing: "它不知道靶场的边界在哪",
        intent: "靶场容器只准打 10.0.3.0/24，出了这个网段就是真攻击",
        source: "记忆页",
        outcome: "漏判 · 攻击者进了生产网",
        without: { verdict: "靶场演练流量", action: "降级，不处置" },
        with: { verdict: "越出靶场，横向喷洒", action: "隔离容器 ctf-07" },
      },
      {
        time: "04:30",
        host: "old-db",
        signal: "agent 失联 6 小时",
        missing: "它不知道这台机器已经退役",
        intent: "old-db 上周已经下线",
        source: "资产页 · 下线",
        outcome: "误报 · 凌晨把你叫醒",
        without: { verdict: "失联，疑似 agent 被停", action: "升级高危，推送飞书" },
        with: { verdict: "已下线主机", action: "不再监控，不推送" },
      },
      {
        time: "06:05",
        host: "web-02",
        signal: "下载并执行 updates.corp.example/agent.sh",
        missing: "它不知道这个域名是你们自己的",
        intent: "updates.corp.example 是我们的内部更新源",
        source: "对话",
        outcome: "打扰 · 又一件要你看",
        without: { verdict: "可疑的下载执行", action: "开事件，等你复核" },
        with: { verdict: "内部更新，良性", action: "自动结案，理由写在案" },
      },
    ] as Case[],
  },
  en: {
    kicker: "Intent",
    title: (
      <>
        It didn't get smarter.
        <br />
        <span className="text-neutral-500">It just knows more.</span>
      </>
    ),
    body: "When the AI gets it wrong, it's almost always a missing piece of data:\nthat address is the backup, that host was retired.\nOnly you know these things. Say them, and they become data.",
    points: [
      "Saying it is entering it: mention it in a conversation and it goes into the group's memory",
      "Triage, inspections and conversations all read the same memory, with yours on top",
      "What the AI notes on its own is re-checked after 30 days; what you write doesn't expire",
      "Correct a host's role or importance once, and the AI stops overwriting it",
      "Every approval, rejection and closure is data too: the next triage pulls up what you concluded",
    ],
    console: "Triage · prod · one night",
    demo: "Demo",
    wrong: "wrong calls",
    told: (n: number, all: number) => `you've said ${n} of ${all}`,
    allRight: "All four called right. None of them needed you.",
    hint: "Open what it doesn't know, and tell it.",
    tell: "Tell it",
    from: "From · you",
    right: "Right call",
    tellAll: "Tell it everything",
    reset: "Start over",
    cases: [
      {
        time: "01:00",
        host: "backup-01",
        signal: "38 GB flowing out to 10.20.0.4",
        missing: "It doesn't know who 10.20.0.4 is",
        intent: "10.20.0.4 is the offsite backup; backup-01 syncs there every day at 01:00",
        source: "conversation",
        outcome: "Wrong block · backup broken",
        without: { verdict: "Possible exfiltration", action: "block 10.20.0.4" },
        with: { verdict: "Scheduled backup", action: "no action, noted in the morning report" },
      },
      {
        time: "03:12",
        host: "range-host",
        signal: "container ctf-07 tries SSH across 10.0.1.0/24",
        missing: "It doesn't know where the lab ends",
        intent: "Lab containers may only hit 10.0.3.0/24 — anything beyond is a real attack",
        source: "memory page",
        outcome: "Missed · attacker reaches prod",
        without: { verdict: "Lab exercise traffic", action: "downgraded, no action" },
        with: { verdict: "Out of the lab, lateral spray", action: "isolate container ctf-07" },
      },
      {
        time: "04:30",
        host: "old-db",
        signal: "agent silent for 6 hours",
        missing: "It doesn't know this host was retired",
        intent: "old-db was decommissioned last week",
        source: "assets · retire",
        outcome: "False alarm · woke you at 4 a.m.",
        without: { verdict: "Offline, agent may be stopped", action: "escalate, page you on Feishu" },
        with: { verdict: "Retired host", action: "no monitoring, no page" },
      },
      {
        time: "06:05",
        host: "web-02",
        signal: "downloads and runs updates.corp.example/agent.sh",
        missing: "It doesn't know that domain is yours",
        intent: "updates.corp.example is our internal update server",
        source: "conversation",
        outcome: "Noise · one more for you",
        without: { verdict: "Suspicious download and run", action: "open an incident for you" },
        with: { verdict: "Internal update, benign", action: "closed automatically, reasons on record" },
      },
    ] as Case[],
  },
};

type Copy = (typeof COPY)["en"];

export function Intent() {
  const t = useCopy(COPY) as Copy;
  const [told, setTold] = useState<boolean[]>(() => t.cases.map(() => false));
  const said = told.filter(Boolean).length;
  const wrong = told.length - said;
  const toggle = (i: number) => setTold((s) => s.map((v, j) => (j === i ? !v : v)));

  return (
    <section id="intent" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="04" kicker={t.kicker} title={t.title} body={t.body} />
          <ul className="mt-10 space-y-4">
            {t.points.map((p) => (
              <li key={p} className="flex gap-3 text-sm leading-relaxed text-neutral-400">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                {p}
              </li>
            ))}
          </ul>
        </div>

        <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
          <div className="flex items-end justify-between gap-4 border-b border-white/10 px-5 py-5">
            <div className="flex items-baseline gap-3">
              <motion.span
                key={wrong}
                initial={{ opacity: 0, y: 10, filter: "blur(6px)" }}
                animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                transition={{ duration: 0.5, ease: EASE }}
                className={`font-mono text-6xl font-medium tabular-nums tracking-tight ${wrong ? "text-rose-300" : "text-emerald-300"}`}
              >
                {wrong}
              </motion.span>
              <span className="text-sm text-neutral-500">{t.wrong}</span>
            </div>
            <div className="flex flex-col items-end gap-2 pb-2">
              <span className="text-xs text-neutral-500">{t.told(said, told.length)}</span>
              <div className="flex gap-1" aria-hidden>
                {told.map((on, i) => (
                  <span
                    key={i}
                    className={`h-1.5 w-7 rounded-full transition-colors duration-500 ${on ? "bg-emerald-300" : "bg-rose-400/60"}`}
                  />
                ))}
              </div>
            </div>
          </div>

          <ol className="space-y-3 p-4 sm:p-5" aria-live="polite">
            {t.cases.map((c, i) => (
              <CaseRow key={c.host} c={c} on={told[i]} toggle={() => toggle(i)} t={t} />
            ))}
          </ol>

          <div className="flex items-center justify-between gap-4 border-t border-white/10 px-5 py-4 text-xs">
            <span className={wrong ? "text-neutral-500" : "text-emerald-300"}>{wrong ? t.hint : t.allRight}</span>
            {wrong ? (
              <button
                type="button"
                onClick={() => setTold(told.map(() => true))}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-emerald-300 px-3.5 py-1.5 text-sm font-medium text-neutral-950 hover:bg-emerald-200"
              >
                <Sparkles className="h-3.5 w-3.5" />
                {t.tellAll}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setTold(told.map(() => false))}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-white/15 px-3 py-1.5 text-sm text-white hover:bg-white/10"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                {t.reset}
              </button>
            )}
          </div>
        </Console>
      </div>
    </section>
  );
}

function CaseRow({ c, on, toggle, t }: { c: Case; on: boolean; toggle: () => void; t: Copy }) {
  const v = on ? c.with : c.without;
  return (
    <li className="rounded-xl border border-white/10 bg-black/30 p-3.5">
      <div className="flex items-center gap-3 font-mono text-xs">
        <span className="tabular-nums text-neutral-500">{c.time}</span>
        <span className="text-neutral-400">{c.host}</span>
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={on ? "with" : "without"}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.9 }}
            transition={{ duration: 0.3, ease: EASE }}
            className={`ml-auto shrink-0 rounded-full px-2 py-0.5 font-sans text-[10px] ${
              on ? "bg-emerald-400/15 text-emerald-300" : "bg-rose-400/15 text-rose-300"
            }`}
          >
            {on ? t.right : c.outcome}
          </motion.span>
        </AnimatePresence>
      </div>
      <p className="mt-1.5 text-sm text-white">{c.signal}</p>

      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={on ? "with" : "without"}
          initial={{ opacity: 0, x: -8, filter: "blur(4px)" }}
          animate={{ opacity: 1, x: 0, filter: "blur(0px)" }}
          exit={{ opacity: 0, x: 8, filter: "blur(4px)" }}
          transition={{ duration: 0.35, ease: EASE }}
          className="mt-2.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-sm"
        >
          <span className={`h-2 w-2 shrink-0 rounded-full ${on ? "bg-emerald-300" : "bg-rose-400"}`} />
          <span className="text-neutral-200">{v.verdict}</span>
          <span className="text-neutral-500">→ {v.action}</span>
        </motion.div>
      </AnimatePresence>

      <button
        type="button"
        onClick={toggle}
        aria-pressed={on}
        className={`mt-3 flex w-full items-start gap-2.5 rounded-lg border px-3 py-2 text-left text-xs transition-colors duration-300 ${
          on
            ? "border-emerald-300/30 bg-emerald-400/[0.07] text-emerald-50 hover:bg-emerald-400/[0.11]"
            : "border-dashed border-white/15 text-neutral-500 hover:border-emerald-300/40 hover:text-neutral-300"
        }`}
      >
        {on ? (
          <>
            <MessageSquareQuote className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />
            <span className="flex-1 leading-relaxed">
              “{c.intent}”
              <span className="mt-0.5 block text-[10px] text-emerald-300/70">
                {t.from} · {c.source}
              </span>
            </span>
          </>
        ) : (
          <>
            <span className="flex-1 leading-relaxed">{c.missing}</span>
            <span className="inline-flex shrink-0 items-center gap-1 text-emerald-300/80">
              <Plus className="h-3 w-3" />
              {t.tell}
            </span>
          </>
        )}
      </button>
    </li>
  );
}
