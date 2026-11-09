import { Bot, CheckCircle2, FileText, Hand, ListTodo, Play, RotateCcw, Terminal } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE } from "./chapter";

type Item =
  | { kind: "user" | "ai"; text: string }
  | { kind: "exec"; host: string; cmd: string; out: string }
  | { kind: "gate"; host: string; cmd: string }
  | { kind: "track"; done: boolean; text: string }
  | { kind: "report"; title: string; summary: string };

type Decision = "approve" | "reject";

const COPY = {
  "zh-CN": {
    kicker: "运维",
    title: (
      <>
        你说一句，
        <br />
        <span className="text-neutral-500">它就去做。</span>
      </>
    ),
    body: "执行命令、查数据、记待办、写报告，都在组内主机上完成。\n到了危险的一步，审计员先把关；它来问你，是因为还缺你知道的那一块。",
    points: [
      "寻常命令，直接执行，不用每条都点批准",
      "高风险命令先送审计员：AI 发起的由 AI 审计员当场裁决，整夜也不会卡住；人发起的等组管理员",
      "对话在服务端运行。关掉浏览器，它也不会停",
      "它在隔离沙箱里干活：手里没有任何凭据，只能经平台受控的命令操作，查数据也只用本组的只读视图",
    ],
    hint: "试试「拒绝」，看它如何收场。",
    empty: "按下发送，看它巡检生产组。",
    console: "AI 助手 · 生产组",
    demo: "演示",
    send: "巡检一下生产组：磁盘、异常服务、可疑账户，能修的直接修。",
    sendLabel: "发送",
    gate: "命中高风险名单，送审计员评审（这里由你来当审计员）",
    approve: "批准",
    reject: "拒绝",
    approved: "已批准 · 你",
    rejected: "已拒绝 · 你",
    open: "待办",
    resolved: "已解决",
    replay: "重播",
    main: [
      { kind: "exec", host: "web-01", cmd: "df -h / | tail -1", out: "/dev/sda1   40G   37G  2.9G  93% /" },
      { kind: "exec", host: "web-01", cmd: "du -sh /var/log/journal", out: "11G\t/var/log/journal" },
      { kind: "exec", host: "web-01", cmd: "journalctl --vacuum-size=500M", out: "Vacuuming done, freed 10.4G of archived journals." },
      { kind: "ai", text: "web-01 根分区 93%，是 journal 日志堆积。已清理到 500M，现在 68%。" },
      { kind: "exec", host: "db-01", cmd: "getent group wheel", out: "wheel:x:10:ops,tmpadmin" },
      { kind: "exec", host: "db-01", cmd: "last -n 1 tmpadmin", out: "tmpadmin pts/0  203.0.113.7  Mon Oct 12 03:14 - 03:41" },
      { kind: "ai", text: "db-01 的 tmpadmin 在 wheel 组，凌晨 3 点从外网登录过，与事件「新增 sudo 账户」对得上。建议删除。" },
      { kind: "gate", host: "db-01", cmd: "userdel -r tmpadmin" },
    ],
    approveTail: [
      { kind: "ai", text: "已删除 tmpadmin，待办标为已解决。事件结案仍由你来拍板。" },
      { kind: "track", done: true, text: "db-01 可疑 sudo 账户 tmpadmin 已删除" },
      { kind: "report", title: "巡检生产组", summary: "web-01 磁盘已清理，可疑账户 tmpadmin 已删除，没有遗留待办" },
    ],
    rejectTail: [
      { kind: "ai", text: "好，不删，先登记成待办。它是谁的账号？告诉我一句，我记下来，下次巡检就不用再问。" },
      { kind: "track", done: false, text: "db-01 可疑 sudo 账户 tmpadmin 待确认" },
      { kind: "report", title: "巡检生产组", summary: "web-01 磁盘已清理；db-01 的 tmpadmin 待确认是否为合法账号" },
    ],
  },
  en: {
    kicker: "Operate",
    title: (
      <>
        You ask.
        <br />
        <span className="text-neutral-500">It gets it done.</span>
      </>
    ),
    body: "Run commands, query data, track findings, write reports — all on the group's hosts.\nAt a risky step, an auditor rules first; when it asks you, it's because it's missing what only you know.",
    points: [
      "Routine commands just run. No approving every line",
      "High-risk commands go to an auditor: the AI auditor rules on the AI's own commands on the spot, so nothing stalls overnight; a person's commands wait for a group admin",
      "Conversations run on the server. Close the browser; the work goes on",
      "It works in an isolated sandbox: no credentials of its own, only platform-controlled commands, and read-only views of its own group's data",
    ],
    hint: "Try “Reject” and see how it wraps up.",
    empty: "Press send and watch it check the prod group.",
    console: "AI assistant · prod",
    demo: "Demo",
    send: "Inspect the prod group: disks, failing services, suspicious accounts. Fix what you can.",
    sendLabel: "Send",
    gate: "On the high-risk list — sent to the auditor (here, that's you)",
    approve: "Approve",
    reject: "Reject",
    approved: "Approved · you",
    rejected: "Rejected · you",
    open: "Open",
    resolved: "Resolved",
    replay: "Replay",
    main: [
      { kind: "exec", host: "web-01", cmd: "df -h / | tail -1", out: "/dev/sda1   40G   37G  2.9G  93% /" },
      { kind: "exec", host: "web-01", cmd: "du -sh /var/log/journal", out: "11G\t/var/log/journal" },
      { kind: "exec", host: "web-01", cmd: "journalctl --vacuum-size=500M", out: "Vacuuming done, freed 10.4G of archived journals." },
      { kind: "ai", text: "web-01 root was at 93% from journal buildup. Trimmed to 500M, now at 68%." },
      { kind: "exec", host: "db-01", cmd: "getent group wheel", out: "wheel:x:10:ops,tmpadmin" },
      { kind: "exec", host: "db-01", cmd: "last -n 1 tmpadmin", out: "tmpadmin pts/0  203.0.113.7  Mon Oct 12 03:14 - 03:41" },
      { kind: "ai", text: "tmpadmin on db-01 is in wheel and logged in from outside at 3 a.m. — it matches the “new sudo account” incident. I suggest removing it." },
      { kind: "gate", host: "db-01", cmd: "userdel -r tmpadmin" },
    ],
    approveTail: [
      { kind: "ai", text: "tmpadmin removed and the finding marked resolved. Closing the incident is still your call." },
      { kind: "track", done: true, text: "Suspicious sudo account tmpadmin on db-01 removed" },
      { kind: "report", title: "Inspect the prod group", summary: "web-01 disk trimmed, suspicious account tmpadmin removed, nothing left open" },
    ],
    rejectTail: [
      { kind: "ai", text: "Understood, keeping it — logged as a finding. Whose account is it? Tell me once and I'll remember; the next inspection won't have to ask." },
      { kind: "track", done: false, text: "Suspicious sudo account tmpadmin on db-01 to confirm" },
      { kind: "report", title: "Inspect the prod group", summary: "web-01 disk trimmed; tmpadmin on db-01 awaits confirmation that it's legitimate" },
    ],
  },
} satisfies Record<string, { main: Item[]; approveTail: Item[]; rejectTail: Item[] } & Record<string, unknown>>;

type Copy = (typeof COPY)["en"];

export function Assistant() {
  const t = useCopy(COPY) as Copy;
  const [step, setStep] = useState(-1);
  const [decision, setDecision] = useState<Decision>();
  const list = useRef<HTMLDivElement>(null);

  const tail: Item[] = decision === "approve" ? t.approveTail : decision === "reject" ? t.rejectTail : [];
  const script: Item[] = [{ kind: "user", text: t.send }, ...t.main, ...tail];
  const shown = step < 0 ? [] : script.slice(0, step + 1);
  const waiting = shown.at(-1)?.kind === "gate" && !decision;
  const finished = step >= 0 && step >= script.length - 1 && !!decision;

  useEffect(() => {
    if (step < 0 || waiting || step >= script.length - 1) return;
    const timer = setTimeout(() => setStep((n) => n + 1), script[step + 1].kind === "exec" ? 900 : 1300);
    return () => clearTimeout(timer);
  }, [step, waiting, script.length]);

  // 只滚动对话框自身，不带动整页
  useEffect(() => {
    list.current?.scrollTo({ top: list.current.scrollHeight, behavior: "smooth" });
  }, [step, decision]);

  const reset = () => {
    setStep(-1);
    setDecision(undefined);
  };

  return (
    <section id="operate" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="06" kicker={t.kicker} title={t.title} body={t.body} tone="sky" />
          <ul className="mt-10 space-y-4">
            {t.points.map((p) => (
              <li key={p} className="flex gap-3 text-sm leading-relaxed text-neutral-400">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
                {p}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
            <div ref={list} className="h-[480px] space-y-3 overflow-y-auto p-5" aria-live="polite">
              {step < 0 && (
                <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-sm text-neutral-500">
                  <Bot className="h-8 w-8 text-sky-300/70" />
                  {t.empty}
                </div>
              )}
              {shown.map((item, i) => (
                <motion.div
                  key={`${i}-${item.kind}`}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.45, ease: EASE }}
                >
                  <Row item={item} decision={decision} decide={setDecision} t={t} />
                </motion.div>
              ))}
              {step >= 0 && !waiting && !finished && (
                <div className="flex items-center gap-1.5 pl-1 text-neutral-500">
                  {[0, 1, 2].map((d) => (
                    <motion.span
                      key={d}
                      className="h-1.5 w-1.5 rounded-full bg-neutral-500"
                      animate={{ opacity: [0.2, 1, 0.2] }}
                      transition={{ duration: 1, repeat: Infinity, delay: d * 0.2 }}
                    />
                  ))}
                </div>
              )}
            </div>
            <div className="border-t border-white/10 p-4">
              {step < 0 ? (
                <button
                  type="button"
                  onClick={() => setStep(0)}
                  className="flex w-full items-center gap-3 rounded-xl border border-sky-300/30 bg-sky-400/[0.07] px-4 py-3 text-left text-sm text-sky-50 transition-colors hover:bg-sky-400/[0.14]"
                >
                  <span className="flex-1">{t.send}</span>
                  <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-sky-300 px-3 py-1 text-xs font-medium text-neutral-950">
                    <Play className="h-3 w-3" />
                    {t.sendLabel}
                  </span>
                </button>
              ) : (
                <div className="flex items-center justify-between gap-4 text-xs text-neutral-500">
                  <span>{waiting ? t.hint : ""}</span>
                  {finished && (
                    <button
                      type="button"
                      onClick={reset}
                      className="inline-flex items-center gap-1.5 rounded-full border border-white/15 px-3 py-1.5 text-sm text-white hover:bg-white/10"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      {t.replay}
                    </button>
                  )}
                </div>
              )}
            </div>
          </Console>
        </div>
      </div>
    </section>
  );
}

function Row({
  item,
  decision,
  decide,
  t,
}: {
  item: Item;
  decision?: Decision;
  decide: (d: Decision) => void;
  t: Copy;
}) {
  switch (item.kind) {
    case "user":
      return (
        <div className="ml-auto max-w-[85%] rounded-2xl rounded-br-md bg-sky-400/15 px-4 py-2.5 text-sm text-sky-50">
          {item.text}
        </div>
      );
    case "ai":
      return (
        <div className="flex max-w-[90%] gap-2.5 text-sm leading-relaxed text-neutral-200">
          <Bot className="mt-0.5 h-4 w-4 shrink-0 text-sky-300" />
          <p>{item.text}</p>
        </div>
      );
    case "exec":
      return (
        <div className="rounded-lg border border-white/10 bg-black/40 font-mono text-xs">
          <div className="flex items-center gap-2 px-3 py-2 text-neutral-300">
            <Terminal className="h-3.5 w-3.5 text-neutral-500" />
            <span className="text-neutral-500">{item.host}</span>
            <span className="truncate">$ {item.cmd}</span>
          </div>
          <motion.pre
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.45 }}
            className="overflow-x-auto border-t border-white/5 px-3 py-2 text-neutral-500"
          >
            {item.out}
          </motion.pre>
        </div>
      );
    case "gate":
      return (
        <div
          className={`rounded-lg border font-mono text-xs ${
            decision === "reject" ? "border-white/10 bg-white/[0.02]" : "border-amber-300/40 bg-amber-400/[0.07]"
          }`}
        >
          <div className="flex items-center gap-2 px-3 py-2 text-neutral-200">
            <Hand className="h-3.5 w-3.5 text-amber-300" />
            <span className="text-neutral-500">{item.host}</span>
            <span className="truncate">$ {item.cmd}</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 border-t border-white/5 px-3 py-2.5 font-sans">
            {decision ? (
              <span className={decision === "approve" ? "text-emerald-300" : "text-neutral-400"}>
                {decision === "approve" ? t.approved : t.rejected}
                {decision === "approve" && <span className="ml-3 font-mono text-neutral-500">exit 0</span>}
              </span>
            ) : (
              <>
                <span className="flex-1 text-amber-200">{t.gate}</span>
                <button
                  type="button"
                  onClick={() => decide("approve")}
                  className="rounded-full bg-amber-300 px-3.5 py-1 text-xs font-medium text-neutral-950 hover:bg-amber-200"
                >
                  {t.approve}
                </button>
                <button
                  type="button"
                  onClick={() => decide("reject")}
                  className="rounded-full border border-white/20 px-3.5 py-1 text-xs text-white hover:bg-white/10"
                >
                  {t.reject}
                </button>
              </>
            )}
          </div>
        </div>
      );
    case "track":
      return (
        <div className="flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-neutral-300">
          <ListTodo className="h-3.5 w-3.5 text-neutral-500" />
          <span
            className={`rounded px-1.5 py-0.5 ${item.done ? "bg-emerald-400/15 text-emerald-300" : "bg-amber-400/15 text-amber-300"}`}
          >
            {item.done ? t.resolved : t.open}
          </span>
          {item.text}
        </div>
      );
    case "report":
      return (
        <div className="flex items-start gap-2 rounded-lg border border-emerald-400/25 bg-emerald-400/[0.06] px-3 py-2.5 text-sm text-emerald-100">
          <FileText className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
          <div className="min-w-0">
            <p className="font-medium">{item.title}</p>
            <p className="mt-0.5 text-xs text-emerald-100/70">{item.summary}</p>
          </div>
          <span className="ml-auto shrink-0 text-xs text-emerald-300/70">HTML · PDF</span>
        </div>
      );
  }
}
