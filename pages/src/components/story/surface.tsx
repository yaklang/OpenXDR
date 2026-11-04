import { Globe, HelpCircle } from "lucide-react";
import { motion } from "motion/react";
import { useLayoutEffect, useRef, useState } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE, StepList, useScrollSteps } from "./chapter";

// 示意数据：风险分 = 暴露级别 × 端口风险 × 重要程度，与 server/internal/assetmap 同一口径
type Service = { port: string; name: string; exposure: number; portRisk: number; public?: boolean };
type Asset = { host: string; role: string; weight: number; services: Service[] };

const ZONES: { key: "external" | "dmz" | "internal"; assets: Asset[]; blind?: string }[] = [
  {
    key: "external",
    assets: [
      {
        host: "gw-01",
        role: "gateway",
        weight: 5,
        services: [
          { port: "22/tcp", name: "SSH", exposure: 20, portRisk: 3, public: true },
          { port: "443/tcp", name: "HTTPS", exposure: 20, portRisk: 1, public: true },
        ],
      },
    ],
  },
  {
    key: "dmz",
    assets: [{ host: "web-01", role: "web", weight: 4, services: [{ port: "8080/tcp", name: "HTTP", exposure: 6, portRisk: 2 }] }],
  },
  {
    key: "internal",
    assets: [{ host: "db-01", role: "db", weight: 5, services: [{ port: "5432/tcp", name: "PostgreSQL", exposure: 2, portRisk: 3 }] }],
    blind: "10.0.1.77",
  },
];

// 依赖边：from 是资产或互联网，to 是被访问的那一行服务；blind 一条在最后一步才出现
const EDGES = [
  { from: "internet", to: "gw-01 22/tcp" },
  { from: "internet", to: "gw-01 443/tcp" },
  { from: "gw-01", to: "web-01 8080/tcp" },
  { from: "web-01", to: "db-01 5432/tcp" },
  { from: "web-01", to: "blind", blind: true },
];

// 每一步解锁什么
const S = { ports: 1, edges: 2, zones: 3, risk: 4, blind: 5 };

const COPY = {
  "zh-CN": {
    kicker: "看清",
    title: (
      <>
        每一个入口，
        <br />
        <span className="text-neutral-500">都在明处。</span>
      </>
    ),
    body: "不用画拓扑，也不用填表。\n往下滚，看一张攻击面自己长出来。",
    steps: [
      ["主机上线", "agent 接入，资产自动登记，AI 标好角色与重要程度"],
      ["端口浮现", "监听端口与属主进程，每分钟比对一次"],
      ["连成依赖", "真实发生过的连接，汇成依赖边"],
      ["划分区域", "按网段、云环境与 IP，分进公网区、隔离区、内网"],
      ["排出风险", "暴露 × 端口风险 × 重要程度，按规则算，不经过模型"],
      ["照出盲区", "连过却没接入的机器，一台不漏"],
    ] as [string, string][],
    console: "资产 · 攻击面",
    demo: "演示",
    internet: "互联网",
    zones: { external: "公网区", dmz: "隔离区", internal: "内网" },
    roles: { gateway: "网关", web: "Web 服务", db: "数据库" } as Record<string, string>,
    weight: "重要",
    publicHit: "有公网访问",
    blind: "未接入",
    stats: ["主机", "对外服务", "依赖", "区域", "盲区"],
    exposure: "暴露",
    portRisk: "端口风险",
    sources: "来源：14 个公网地址，近 24 小时 2,310 次连接",
    sourcesNone: "来源：只有内网主机访问过",
    hint: "点一行服务，看它的分怎么算",
  },
  en: {
    kicker: "See",
    title: (
      <>
        Every way in,
        <br />
        <span className="text-neutral-500">in plain sight.</span>
      </>
    ),
    body: "No diagrams to draw. No spreadsheets to fill.\nScroll, and watch an attack surface build itself.",
    steps: [
      ["Hosts come online", "agents enroll, assets register, AI labels role and importance"],
      ["Ports surface", "listeners and their processes, checked every minute"],
      ["Dependencies form", "real connections become dependency edges"],
      ["Zones drawn", "by subnet, cloud and IP: public, DMZ, internal"],
      ["Risk ranked", "exposure × port risk × importance — by rule, no model involved"],
      ["Blind spots revealed", "machines seen on the wire but never onboarded"],
    ] as [string, string][],
    console: "Assets · Attack surface",
    demo: "Demo",
    internet: "Internet",
    zones: { external: "Public", dmz: "DMZ", internal: "Internal" },
    roles: { gateway: "Gateway", web: "Web", db: "Database" } as Record<string, string>,
    weight: "weight",
    publicHit: "Public access",
    blind: "not onboarded",
    stats: ["Hosts", "Services", "Edges", "Zones", "Blind spots"],
    exposure: "Exposure",
    portRisk: "Port risk",
    sources: "Sources: 14 public addresses, 2,310 connections in 24 h",
    sourcesNone: "Sources: internal hosts only",
    hint: "Click a service to see how its score adds up",
  },
};

const score = (a: Asset, s: Service) => s.exposure * s.portRisk * a.weight;
const fade = (on: boolean) => `transition-all duration-700 ${on ? "opacity-100" : "opacity-0"}`;

/** 量出各节点位置，画从源右缘到目标左缘的曲线；容器尺寸变了重算。 */
function useEdges(wrap: React.RefObject<HTMLDivElement | null>) {
  const [paths, setPaths] = useState<string[]>([]);
  useLayoutEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const measure = () => {
      const base = el.getBoundingClientRect();
      const box = (id: string) => el.querySelector(`[data-node="${id}"]`)?.getBoundingClientRect();
      setPaths(
        EDGES.map(({ from, to }) => {
          const a = box(from);
          const b = box(to);
          if (!a || !b) return "";
          const x1 = a.right - base.left;
          const y1 = a.top + a.height / 2 - base.top;
          const x2 = b.left - base.left;
          const y2 = b.top + b.height / 2 - base.top;
          const mid = (x1 + x2) / 2;
          return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
        }),
      );
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [wrap]);
  return paths;
}

export function Surface() {
  const t = useCopy(COPY);
  const { ref, wide, step, progress } = useScrollSteps(t.steps.length);
  const wrap = useRef<HTMLDivElement>(null);
  const paths = useEdges(wrap);
  const [picked, setPicked] = useState("gw-01 22/tcp");
  const all = ZONES.flatMap((z) => z.assets.flatMap((a) => a.services.map((s) => ({ a, s }))));
  const sel = all.find(({ a, s }) => `${a.host} ${s.port}` === picked) ?? all[0];
  const stats = [3, all.length, EDGES.length - 1, ZONES.length, 1];
  const statStep = [0, S.ports, S.edges, S.zones, S.blind];

  const head = <ChapterHead index="05" kicker={t.kicker} title={t.title} body={t.body} tone="amber" />;

  const demo = (
    <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
      <div ref={wrap} className="relative grid gap-3 p-4 sm:grid-cols-[auto_repeat(3,minmax(0,1fr))] sm:gap-6 sm:p-5">
        <svg className="pointer-events-none absolute inset-0 hidden h-full w-full sm:block" aria-hidden>
          {paths.map((d, i) =>
            d ? (
              <motion.path
                key={i}
                d={d}
                fill="none"
                strokeWidth={1.5}
                strokeDasharray={EDGES[i].blind ? "4 4" : undefined}
                className={EDGES[i].blind ? "stroke-neutral-500" : "stroke-amber-300/60"}
                initial={false}
                animate={{ pathLength: step >= (EDGES[i].blind ? S.blind : S.edges) ? 1 : 0, opacity: step >= (EDGES[i].blind ? S.blind : S.edges) ? 1 : 0 }}
                transition={{ duration: 0.9, ease: EASE, delay: i * 0.08 }}
              />
            ) : null,
          )}
        </svg>

        <div data-node="internet" className="flex items-center gap-2 text-[11px] text-neutral-400 sm:flex-col sm:justify-center sm:gap-1 sm:self-center">
          <Globe className="h-5 w-5 text-amber-300" />
          {t.internet}
        </div>

        {ZONES.map((zone) => (
          <div
            key={zone.key}
            className={`relative rounded-xl border p-2 transition-colors duration-700 sm:p-3 ${
              step >= S.zones ? "border-white/10 bg-white/[0.02]" : "border-transparent"
            }`}
          >
            <p className={`mb-2 text-[10px] uppercase tracking-wider text-amber-200/80 sm:mb-3 ${fade(step >= S.zones)}`}>
              {t.zones[zone.key]}
            </p>
            <div className="space-y-3">
              {zone.assets.map((a) => (
                <div key={a.host} data-node={a.host} className="relative rounded-lg border border-white/10 bg-neutral-950">
                  <div className="border-b border-white/5 px-2 py-2 sm:px-3">
                    <p className="font-mono text-xs text-white">{a.host}</p>
                    <p className="mt-0.5 truncate text-[10px] text-neutral-500">
                      {t.roles[a.role]} · {t.weight} {a.weight}
                    </p>
                  </div>
                  {a.services.map((s) => {
                    const id = `${a.host} ${s.port}`;
                    const hot = step >= S.risk && id === picked;
                    return (
                      <button
                        key={s.port}
                        type="button"
                        data-node={id}
                        disabled={step < S.risk}
                        onClick={() => setPicked(id)}
                        aria-pressed={hot}
                        className={`flex w-full items-center gap-1.5 px-2 py-1.5 text-left text-[11px] sm:px-3 ${fade(step >= S.ports)} ${
                          hot ? "bg-amber-400/15 text-amber-100" : "text-neutral-400 enabled:hover:bg-white/5"
                        }`}
                      >
                        <span className="font-mono">{s.port}</span>
                        <span className="truncate sm:hidden xl:inline">{s.name}</span>
                        {s.public && <Globe className="h-3 w-3 shrink-0 text-amber-300" aria-label={t.publicHit} />}
                        <span className={`ml-auto font-mono tabular-nums ${fade(step >= S.risk)}`}>{score(a, s)}</span>
                      </button>
                    );
                  })}
                </div>
              ))}
              {zone.blind && (
                <motion.div
                  data-node="blind"
                  initial={false}
                  animate={{ opacity: step >= S.blind ? 1 : 0, scale: step >= S.blind ? 1 : 0.9 }}
                  transition={{ duration: 0.6, ease: EASE }}
                  className="rounded-lg border border-dashed border-white/25 px-2 py-2 text-[10px] text-neutral-400 sm:px-3"
                >
                  <p className="flex items-center gap-1.5 font-mono text-[11px] text-neutral-200">
                    <HelpCircle className="h-3.5 w-3.5 shrink-0 text-amber-300" />
                    {zone.blind}
                  </p>
                  <p className="mt-0.5">{t.blind}</p>
                </motion.div>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="border-t border-white/10 p-5">
        <dl className="grid grid-cols-5 gap-2">
          {t.stats.map((label, i) => (
            <div key={label}>
              <dt className="truncate text-[10px] text-neutral-500">{label}</dt>
              <dd className={`font-mono text-xl tabular-nums ${step >= statStep[i] ? "text-white" : "text-neutral-700"}`}>
                {step >= statStep[i] ? stats[i] : "–"}
              </dd>
            </div>
          ))}
        </dl>
        <div className={`mt-4 min-h-[88px] ${fade(step >= S.risk)}`} aria-live="polite">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="font-mono text-sm text-white">{picked}</span>
            <span className="text-xs text-neutral-500">{sel.s.name}</span>
            {sel.s.public && <span className="rounded-full bg-amber-400/15 px-2 py-0.5 text-[10px] text-amber-200">{t.publicHit}</span>}
          </div>
          <p className="mt-2 flex flex-wrap items-baseline gap-x-2 gap-y-1 font-mono text-sm text-neutral-400">
            <span>
              {t.exposure} <span className="text-white">{sel.s.exposure}</span>
            </span>
            ×
            <span>
              {t.portRisk} <span className="text-white">{sel.s.portRisk}</span>
            </span>
            ×
            <span>
              {t.weight} <span className="text-white">{sel.a.weight}</span>
            </span>
            =<span className="text-2xl font-medium text-amber-300">{score(sel.a, sel.s)}</span>
          </p>
          <p className="mt-1 text-xs text-neutral-500">
            {sel.s.public ? t.sources : t.sourcesNone} · {t.hint}
          </p>
        </div>
      </div>
    </Console>
  );

  return (
    <section id="surface" className="relative scroll-mt-20">
      {!wide && <div className="px-4 pt-28 sm:px-6">{head}</div>}
      <div ref={ref} className={wide ? "relative h-[340vh]" : "relative"}>
        <div className={wide ? "sticky top-0 flex h-screen items-center overflow-hidden px-8" : "px-4 pb-28 pt-10 sm:px-6"}>
          <div className="mx-auto grid w-full max-w-[1400px] gap-10 lg:grid-cols-[minmax(0,4fr)_minmax(0,7fr)] lg:items-center">
            <div>
              {wide && <div className="mb-10">{head}</div>}
              <StepList steps={t.steps} step={step} wide={wide} progress={progress} tone="amber" lead={(i) => `0${i + 1}`} />
            </div>
            {demo}
          </div>
        </div>
      </div>
    </section>
  );
}
