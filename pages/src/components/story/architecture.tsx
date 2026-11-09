import { ArrowDown, ArrowRight, CheckCircle2, CornerDownLeft } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState, type ReactNode } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE } from "./chapter";

// 五路数据源进同一份事实存储；AI 只读这份存储，做过的事再写回去。表名与 server/ent/schema 对应
type Table = "event" | "alert" | "incident" | "asset" | "intel" | "memory" | "decision" | "session" | "report" | "audit";
type Source = { id: string; label: string; sub: string; writes: Table[]; records: Rec[] };
type Rec = { ts: string; table: Table; subject: string; body: string };

const ORDER: Table[] = ["event", "alert", "incident", "asset", "intel", "memory", "decision", "session", "report", "audit"];
// AI 自己写回的表：决策、报告、审计
const BACK: Table[] = ["decision", "report", "audit"];
const CYCLE = 3600;

const COPY = {
  "zh-CN": {
    kicker: "架构",
    title: (
      <>
        机器的，人的，
        <br />
        <span className="text-neutral-500">都是一行数据。</span>
      </>
    ),
    body: "端点、流量、日志、情报，\n还有你说的每一句话、做的每一个决定，\n都进同一个库，走同一条路。\nAI 读的是它，写回的也是它。",
    points: [
      "一份事实存储：事件、告警、资产、记忆、决策、对话，都在同一个库里",
      "研判、巡检、对话、复核，读的都是本组的只读视图，没有第二条路",
      "它做过的每一件事也写回成数据：决策记录、报告、审计，下一轮照样读得到",
      "审计逐条封链：只拿到数据库的人，也改不了历史",
    ],
    console: "数据流 · 一切皆数据",
    demo: "示意",
    sources: "数据源",
    store: "一份事实存储",
    ai: "AI",
    act: "动作",
    loop: "动作写回同一份存储：决策 · 报告 · 审计",
    consumers: ["研判", "巡检", "对话", "复核"],
    actions: ["封锁", "隔离", "结案", "报告"],
    tables: {
      event: "事件",
      alert: "告警",
      incident: "事件单",
      asset: "资产",
      intel: "情报",
      memory: "记忆",
      decision: "决策",
      session: "对话",
      report: "报告",
      audit: "审计",
    } as Record<Table, string>,
    tape: "它看到的记录",
    you: "你的话，和遥测一样，是一行数据。",
    machine: "点一路数据源，看它写进哪几张表。",
    aiName: "AI",
    aiRec: { ts: "03:41:02", table: "decision", subject: "range-host", body: "隔离容器 ctf-07 · 依据：你的记忆「靶场只准打 10.0.3.0/24」" } as Rec,
    list: [
      {
        id: "agent",
        label: "端点",
        sub: "agent",
        writes: ["event", "asset"],
        records: [
          { ts: "03:12:07", table: "event", subject: "range-host", body: "进程 sshpass 启动 · 父进程 bash · 容器 ctf-07" },
          { ts: "03:12:09", table: "event", subject: "db-01", body: "root 登录失败 · 来自 10.0.3.17" },
        ],
      },
      {
        id: "sensor",
        label: "流量",
        sub: "sensor",
        writes: ["event"],
        records: [
          { ts: "03:12:08", table: "event", subject: "10.0.3.17 → 10.0.1.14:22", body: "TCP 会话 · 1.2 KB · 3 次握手失败" },
          { ts: "06:05:11", table: "event", subject: "web-02", body: "TLS · SNI updates.corp.example · JA3 已记录" },
        ],
      },
      {
        id: "syslog",
        label: "日志",
        sub: "syslog",
        writes: ["event"],
        records: [
          { ts: "03:13:40", table: "event", subject: "fw-edge", body: "deny 10.0.3.17 → 10.0.1.0/24" },
          { ts: "04:30:00", table: "event", subject: "switch-02", body: "port 14 down" },
        ],
      },
      {
        id: "intel",
        label: "情报",
        sub: "intel",
        writes: ["intel"],
        records: [
          { ts: "02:00:00", table: "intel", subject: "203.0.113.7", body: "C2 · 5 家引擎判恶意" },
          { ts: "02:00:00", table: "intel", subject: "x.evil.example", body: "恶意下载源" },
        ],
      },
      {
        id: "you",
        label: "你",
        sub: "对话 · 审批 · 结案",
        writes: ["memory", "decision", "incident", "session"],
        records: [
          { ts: "09:30:15", table: "memory", subject: "生产组", body: "「靶场容器只准打 10.0.3.0/24」" },
          { ts: "10:02:44", table: "decision", subject: "db-01", body: "批准 userdel -r tmpadmin" },
          { ts: "11:20:03", table: "incident", subject: "#812", body: "结案：良性 · 管理员例行变更" },
        ],
      },
    ] as Source[],
  },
  en: {
    kicker: "Architecture",
    title: (
      <>
        Machine or human,
        <br />
        <span className="text-neutral-500">it's all a row of data.</span>
      </>
    ),
    body: "Endpoints, network, logs, intel —\nand every word you say, every call you make.\nIt all lands in one store and travels one path.\nThe AI reads from it, and writes back to it.",
    points: [
      "One store of record: events, alerts, assets, memory, decisions and conversations, all in the same PostgreSQL",
      "Triage, inspections, conversations and reviews all read the group's read-only views. There is no second path",
      "Everything it does is written back as data — decisions, reports, audit — and read again next round",
      "The audit log is sealed as a chain: holding the database isn't enough to rewrite history",
    ],
    console: "Data flow · everything is data",
    demo: "Illustrative",
    sources: "Sources",
    store: "One store of record",
    ai: "AI",
    act: "Actions",
    loop: "actions are written back to the same store: decisions · reports · audit",
    consumers: ["Triage", "Inspect", "Chat", "Review"],
    actions: ["Block", "Isolate", "Close", "Report"],
    tables: {
      event: "events",
      alert: "alerts",
      incident: "incidents",
      asset: "assets",
      intel: "intel",
      memory: "memory",
      decision: "decisions",
      session: "chats",
      report: "reports",
      audit: "audit",
    } as Record<Table, string>,
    tape: "What it sees",
    you: "What you say is a row of data, just like telemetry.",
    machine: "Pick a source and see which tables it writes.",
    aiName: "AI",
    aiRec: { ts: "03:41:02", table: "decision", subject: "range-host", body: "isolate container ctf-07 · because of your memory “lab hits 10.0.3.0/24 only”" } as Rec,
    list: [
      {
        id: "agent",
        label: "Endpoint",
        sub: "agent",
        writes: ["event", "asset"],
        records: [
          { ts: "03:12:07", table: "event", subject: "range-host", body: "process sshpass started · parent bash · container ctf-07" },
          { ts: "03:12:09", table: "event", subject: "db-01", body: "root logon failed · from 10.0.3.17" },
        ],
      },
      {
        id: "sensor",
        label: "Network",
        sub: "sensor",
        writes: ["event"],
        records: [
          { ts: "03:12:08", table: "event", subject: "10.0.3.17 → 10.0.1.14:22", body: "TCP session · 1.2 KB · 3 failed handshakes" },
          { ts: "06:05:11", table: "event", subject: "web-02", body: "TLS · SNI updates.corp.example · JA3 recorded" },
        ],
      },
      {
        id: "syslog",
        label: "Logs",
        sub: "syslog",
        writes: ["event"],
        records: [
          { ts: "03:13:40", table: "event", subject: "fw-edge", body: "deny 10.0.3.17 → 10.0.1.0/24" },
          { ts: "04:30:00", table: "event", subject: "switch-02", body: "port 14 down" },
        ],
      },
      {
        id: "intel",
        label: "Intel",
        sub: "intel",
        writes: ["intel"],
        records: [
          { ts: "02:00:00", table: "intel", subject: "203.0.113.7", body: "C2 · flagged by 5 engines" },
          { ts: "02:00:00", table: "intel", subject: "x.evil.example", body: "malicious download host" },
        ],
      },
      {
        id: "you",
        label: "You",
        sub: "chat · approvals",
        writes: ["memory", "decision", "incident", "session"],
        records: [
          { ts: "09:30:15", table: "memory", subject: "prod", body: "“lab containers hit 10.0.3.0/24 only”" },
          { ts: "10:02:44", table: "decision", subject: "db-01", body: "approved userdel -r tmpadmin" },
          { ts: "11:20:03", table: "incident", subject: "#812", body: "closed: benign · routine admin change" },
        ],
      },
    ] as Source[],
  },
};

type Copy = (typeof COPY)["en"];

export function Architecture() {
  const t = useCopy(COPY) as Copy;
  const [pick, setPick] = useState(0);
  const [held, setHeld] = useState(false);
  const src = t.list[pick];
  const you = src.id === "you";

  // 没人点之前自己轮转，点过一次就停在你选的那一路
  useEffect(() => {
    if (held) return;
    const timer = setInterval(() => setPick((n) => (n + 1) % t.list.length), CYCLE);
    return () => clearInterval(timer);
  }, [held, t.list.length]);

  const choose = (i: number) => {
    setHeld(true);
    setPick(i);
  };

  return (
    <section id="architecture" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="01" kicker={t.kicker} title={t.title} body={t.body} />
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
          <div className="grid gap-3 p-4 sm:p-5 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1.35fr)_auto_minmax(0,0.9fr)] lg:items-stretch">
            <Column title={t.sources}>
              {t.list.map((s, i) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => choose(i)}
                  aria-pressed={i === pick}
                  className={`flex w-full items-baseline justify-between gap-2 rounded-lg border px-2.5 py-1.5 text-left transition-colors duration-300 ${
                    i === pick
                      ? s.id === "you"
                        ? "border-emerald-300/50 bg-emerald-400/[0.12] text-emerald-100"
                        : "border-white/30 bg-white/[0.08] text-white"
                      : s.id === "you"
                        ? "border-emerald-300/20 text-emerald-300/80 hover:bg-emerald-400/[0.06]"
                        : "border-white/10 text-neutral-400 hover:bg-white/[0.04]"
                  }`}
                >
                  <span className="text-sm">{s.label}</span>
                  <span className="truncate font-mono text-[10px] text-neutral-500">{s.sub}</span>
                </button>
              ))}
            </Column>

            <Pipe you={you} />

            <Column title={t.store}>
              <div className="grid grid-cols-2 gap-1.5">
                {ORDER.map((tb) => {
                  const lit = src.writes.includes(tb);
                  return (
                    <span
                      key={tb}
                      className={`rounded-md border px-2 py-1 text-center font-mono text-[11px] transition-all duration-500 ${
                        lit
                          ? you
                            ? "border-emerald-300/50 bg-emerald-400/[0.14] text-emerald-100"
                            : "border-white/30 bg-white/[0.09] text-white"
                          : BACK.includes(tb)
                            ? "border-dashed border-sky-300/25 text-sky-200/60"
                            : "border-white/[0.06] text-neutral-600"
                      }`}
                    >
                      {t.tables[tb]}
                    </span>
                  );
                })}
              </div>
            </Column>

            <Pipe you={false} />

            <div className="flex flex-col gap-3">
              <Column title={t.ai}>
                <div className="flex flex-wrap gap-1.5">
                  {t.consumers.map((c) => (
                    <span key={c} className="rounded-md bg-sky-400/10 px-2 py-1 text-[11px] text-sky-200">
                      {c}
                    </span>
                  ))}
                </div>
              </Column>
              <Column title={t.act}>
                <div className="flex flex-wrap gap-1.5">
                  {t.actions.map((a) => (
                    <span key={a} className="rounded-md bg-rose-400/10 px-2 py-1 text-[11px] text-rose-200">
                      {a}
                    </span>
                  ))}
                </div>
              </Column>
            </div>

            <Loop label={t.loop} />
          </div>

          <div className="border-t border-white/10 p-4 sm:p-5">
            <div className="flex items-center justify-between gap-3 text-[11px] text-neutral-500">
              <span className="font-mono uppercase tracking-[0.18em]">{t.tape}</span>
              <span className={you ? "text-emerald-300" : ""}>{you ? t.you : t.machine}</span>
            </div>
            <ol className="mt-3 min-h-[150px] space-y-1.5 font-mono text-[11px]" aria-live="polite">
              <AnimatePresence mode="popLayout" initial={false}>
                {src.records.map((r) => (
                  <Record key={`${src.id}-${r.ts}-${r.subject}`} r={r} who={src.label} you={you} t={t} />
                ))}
              </AnimatePresence>
              <Record r={t.aiRec} who={t.aiName} ai t={t} />
            </ol>
          </div>
        </Console>
      </div>
    </section>
  );
}

function Column({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 p-3">
      <p className="mb-2.5 font-mono text-[10px] uppercase tracking-[0.18em] text-neutral-500">{title}</p>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

/** 回环：动作写回存储，一个点从右往左流回去。 */
function Loop({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-dashed border-sky-300/20 px-3 py-2 font-mono text-[10px] text-sky-200/70 lg:col-span-5">
      <CornerDownLeft className="h-3.5 w-3.5 shrink-0" />
      <span className="shrink-0">{label}</span>
      <span className="relative h-px flex-1 bg-sky-300/15" aria-hidden>
        <motion.span
          className="absolute -top-[2px] h-[5px] w-[5px] rounded-full bg-sky-300"
          animate={{ left: ["100%", "0%"], opacity: [0, 1, 0] }}
          transition={{ duration: 2.2, repeat: Infinity, ease: "linear" }}
        />
      </span>
    </div>
  );
}

/** 两栏之间的管道：一个点沿着它流过去；宽屏横向，窄屏竖向。 */
function Pipe({ you }: { you: boolean }) {
  const dot = you ? "bg-emerald-300" : "bg-white/70";
  return (
    <div className="flex items-center justify-center text-neutral-600" aria-hidden>
      <div className="relative hidden h-px w-8 bg-white/10 lg:block">
        <motion.span
          className={`absolute -top-[2px] h-[5px] w-[5px] rounded-full ${dot}`}
          animate={{ left: ["0%", "100%"], opacity: [0, 1, 0] }}
          transition={{ duration: 1.4, repeat: Infinity, ease: "linear" }}
        />
        <ArrowRight className="absolute -right-2 -top-[6px] h-3 w-3" />
      </div>
      <ArrowDown className="h-4 w-4 lg:hidden" />
    </div>
  );
}

function Record({ r, who, you, ai, t }: { r: Rec; who: string; you?: boolean; ai?: boolean; t: Copy }) {
  const tone = ai ? "text-sky-300" : you ? "text-emerald-300" : "text-neutral-400";
  return (
    <motion.li
      layout
      initial={{ opacity: 0, y: 6, filter: "blur(4px)" }}
      animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      exit={{ opacity: 0, y: -6, filter: "blur(4px)" }}
      transition={{ duration: 0.4, ease: EASE }}
      className={`grid grid-cols-[4.5rem_3.5rem_minmax(0,1fr)] items-baseline gap-x-2 gap-y-0.5 rounded-md px-2 py-1.5 sm:grid-cols-[4.5rem_4.5rem_4.5rem_8rem_minmax(0,1fr)] ${
        ai ? "border border-dashed border-sky-300/20" : you ? "bg-emerald-400/[0.06]" : "bg-white/[0.03]"
      }`}
    >
      <span className="tabular-nums text-neutral-500">{r.ts}</span>
      <span className={`truncate ${tone}`}>{who}</span>
      <span className="truncate text-neutral-500">{t.tables[r.table]}</span>
      <span className="hidden truncate text-neutral-300 sm:block">{r.subject}</span>
      <span className="col-span-3 min-w-0 text-neutral-300 sm:col-span-1 sm:truncate">{r.body}</span>
    </motion.li>
  );
}
