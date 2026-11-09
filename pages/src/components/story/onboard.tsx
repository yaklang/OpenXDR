import { Check, FileText, Lock, RotateCcw, Upload } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState, type DragEvent } from "react";
import { useCopy } from "@/i18n";
import { ChapterHead, Console, DemoBadge, EASE, type Flow } from "./chapter";

const HOSTS = [
  { name: "web-01", ip: "10.0.1.11", os: "ubuntu 24.04", user: "root" },
  { name: "db-01", ip: "10.0.1.21", os: "rocky linux 9", user: "ops" },
  { name: "gw-01", ip: "10.0.1.31", os: "debian 12", user: "root" },
];

// 整段演示由一个时钟推进，各阶段都从 tick 推出来：-1 未开始。
const TICK_MS = 420;
const PREVIEW_AT = 5;
const ENROLL_AT = 10;
const END = 22;

/** 第 i 台主机的接入进度：-1 排队，0~3 正在进行的步骤，4 在线。 */
function stageOf(tick: number, i: number) {
  return Math.max(-1, Math.min(4, Math.floor((tick - ENROLL_AT - i) / 2)));
}

const COPY = {
  "zh-CN": {
    kicker: "接入",
    title: (
      <>
        一份文档，
        <br />
        <span className="text-neutral-500">整个机房上线。</span>
      </>
    ),
    body: "不用逐台登录。把交接文档拖进来，\n主机和凭据自动识别、加密保存、按组接入。\n上线那一刻，检测和巡检就开始了。",
    flow: { reads: [{ you: "交接文档" }], writes: ["资产", "凭据（加密）", "分组"] } as Flow,
    docName: "运维交接.md",
    docHeading: "生产环境主机",
    docHint: "拖住这份文档，放进导入框",
    auto: "拖不了？替我放进去",
    imported: "已导入",
    console: "资产 · 从文档导入",
    demo: "演示",
    drop: "把运维文档拖到这里",
    dropFormats: "Markdown 表格、YAML、JSON 都行；os 列认发行版名，agent 上线后以实测为准",
    release: "松手开始导入",
    parsing: "识别主机与凭据…",
    realFile: (name: string) => `收到「${name}」——演示不读取文件内容，下面是示例数据`,
    cols: ["主机", "系统", "凭据", "接入"],
    sealed: "已加密",
    steps: ["SSH 登录", "下发 agent", "签发主机证书", "上线"],
    queued: "排队",
    online: "在线",
    done: "3 台主机已接入「生产」组。明早十点，第一份巡检报告。",
    replay: "重来一次",
    notes: [
      "凭据加密落库，模型永远看不到原文",
      "每台主机一张专属证书，谁也冒充不了谁",
      "以后的升级，自动完成",
    ],
  },
  en: {
    kicker: "Onboard",
    title: (
      <>
        One document.
        <br />
        <span className="text-neutral-500">Your whole fleet, online.</span>
      </>
    ),
    body: "No logging in host by host. Drop in your handover doc.\nHosts and credentials are found, encrypted and onboarded by group.\nDetection and checkups start the moment they're online.",
    flow: { reads: [{ you: "handover doc" }], writes: ["assets", "credentials (encrypted)", "groups"] } as Flow,
    docName: "ops-handover.md",
    docHeading: "Production hosts",
    docHint: "Grab this document and drop it into the import box",
    auto: "Can't drag? Drop it for me",
    imported: "Imported",
    console: "Assets · Import from document",
    demo: "Demo",
    drop: "Drop your ops document here",
    dropFormats: "Markdown tables, YAML or JSON; the os column takes distro names, verified by the agent once online",
    release: "Release to import",
    parsing: "Finding hosts and credentials…",
    realFile: (name: string) => `Got "${name}" — the demo doesn't read files, sample data below`,
    cols: ["Host", "OS", "Credential", "Onboarding"],
    sealed: "Encrypted",
    steps: ["SSH login", "Ship agent", "Issue host cert", "Online"],
    queued: "Queued",
    online: "Online",
    done: "3 hosts onboarded into “prod”. First checkup report tomorrow at 10:00.",
    replay: "Replay",
    notes: [
      "Credentials encrypted at rest. The model never sees them",
      "One identity-bound certificate per host. No host can pose as another",
      "Upgrades from here on happen on their own",
    ],
  },
};

const docLines = (heading: string) => [
  `## ${heading}`,
  "| hostname | address | os | user | password |",
  "|---|---|---|---|---|",
  ...HOSTS.map((h) => `| ${h.name} | ${h.ip} | ${h.os} | ${h.user} | ••••••••• |`),
];

export function Onboard() {
  const t = useCopy(COPY);
  const zoneRef = useRef<HTMLDivElement>(null);
  // 拖拽松手时浏览器还会补发一次 click，靠它区分「拖了」和「点了」。
  const dragged = useRef(false);
  const [tick, setTick] = useState(-1);
  const [over, setOver] = useState(false);
  const [fileName, setFileName] = useState<string>();
  const running = tick >= 0 && tick < END;

  useEffect(() => {
    if (!running) return;
    const timer = setTimeout(() => setTick((n) => n + 1), TICK_MS);
    return () => clearTimeout(timer);
  }, [running, tick]);

  const start = (name?: string) => {
    if (tick >= 0) return;
    setFileName(name);
    setOver(false);
    setTick(0);
  };
  const reset = () => {
    setTick(-1);
    setFileName(undefined);
  };
  const overZone = (x: number, y: number) => {
    const r = zoneRef.current?.getBoundingClientRect();
    return !!r && x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
  };
  // 也接受从桌面拖进来的真实文件，但只取文件名，不读内容。
  const onFileDrop = (e: DragEvent) => {
    e.preventDefault();
    start(e.dataTransfer.files[0]?.name);
  };

  return (
    <section id="onboard" className="relative scroll-mt-20 px-4 py-28 sm:px-6 lg:px-8">
      <div className="mx-auto grid max-w-[1400px] gap-14 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-center">
        <div>
          <ChapterHead index="02" kicker={t.kicker} title={t.title} body={t.body} flow={t.flow} />

          <div className="mt-10">
            <p className="mb-3 text-sm text-neutral-500">{t.docHint}</p>
            <motion.button
              type="button"
              drag={tick < 0}
              dragSnapToOrigin
              dragElastic={0.9}
              whileDrag={{ scale: 1.06, rotate: -3, zIndex: 50, cursor: "grabbing" }}
              onDragStart={() => (dragged.current = true)}
              onDrag={(_, info) => setOver(overZone(info.point.x - window.scrollX, info.point.y - window.scrollY))}
              onDragEnd={(_, info) => {
                setTimeout(() => (dragged.current = false));
                if (overZone(info.point.x - window.scrollX, info.point.y - window.scrollY)) start();
                else setOver(false);
              }}
              onClick={() => !dragged.current && start()}
              disabled={tick >= 0}
              aria-label={t.auto}
              className="relative block w-full max-w-sm cursor-grab touch-none select-none rounded-xl border border-white/15 bg-neutral-900 p-4 text-left shadow-2xl shadow-black/60 transition-opacity disabled:cursor-default disabled:opacity-40"
            >
              <div className="flex items-center gap-2 text-sm font-medium text-white">
                <FileText className="h-4 w-4 text-emerald-300" />
                {t.docName}
                {tick >= 0 && (
                  <span className="ml-auto inline-flex items-center gap-1 text-xs text-emerald-300">
                    <Check className="h-3 w-3" />
                    {t.imported}
                  </span>
                )}
              </div>
              <pre className="mt-3 overflow-hidden font-mono text-[11px] leading-5 text-neutral-500">
                {docLines(t.docHeading).join("\n")}
              </pre>
            </motion.button>
            <button
              type="button"
              onClick={() => start()}
              disabled={tick >= 0}
              className="mt-4 text-sm text-neutral-400 underline decoration-white/20 underline-offset-4 transition-colors hover:text-white disabled:opacity-0"
            >
              {t.auto}
            </button>
          </div>
        </div>

        <div>
          <Console title={t.console} badge={<DemoBadge label={t.demo} />}>
            <div
              ref={zoneRef}
              onDragOver={(e) => {
                e.preventDefault();
                setOver(true);
              }}
              onDragLeave={() => setOver(false)}
              onDrop={onFileDrop}
              className="min-h-[380px] p-5"
              aria-live="polite"
            >
              {tick < 0 ? (
                <DropZone over={over} t={t} />
              ) : tick < PREVIEW_AT ? (
                <Parsing tick={tick} label={t.parsing} lines={docLines(t.docHeading)} />
              ) : (
                <HostTable tick={tick} t={t} />
              )}
              {fileName && tick >= 0 && (
                <p className="mt-4 text-xs text-neutral-500">{t.realFile(fileName)}</p>
              )}
            </div>
          </Console>

          <AnimatePresence>
            {tick >= END && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.6, ease: EASE }}
                className="mt-5 flex flex-col gap-4 rounded-2xl border border-emerald-400/20 bg-emerald-400/[0.06] p-5 sm:flex-row sm:items-center"
              >
                <p className="flex-1 text-sm text-emerald-100">{t.done}</p>
                <button
                  type="button"
                  onClick={reset}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-white/15 px-4 py-2 text-sm text-white transition-colors hover:bg-white/10"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  {t.replay}
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          <ul className="mt-8 grid gap-3 sm:grid-cols-3">
            {t.notes.map((note) => (
              <li key={note} className="border-l border-white/10 pl-3 text-sm leading-relaxed text-neutral-400">
                {note}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

type Copy = (typeof COPY)["en"];

function DropZone({ over, t }: { over: boolean; t: Copy }) {
  return (
    <div
      className={`flex h-[340px] flex-col items-center justify-center rounded-xl border-2 border-dashed transition-all duration-300 ${
        over
          ? "scale-[1.01] border-emerald-300 bg-emerald-400/10 shadow-[0_0_80px_-10px_rgba(52,211,153,0.45)]"
          : "border-white/15 bg-white/[0.02]"
      }`}
    >
      <motion.div animate={over ? { y: -6 } : { y: [0, -6, 0] }} transition={over ? {} : { duration: 2.4, repeat: Infinity }}>
        <Upload className={`h-9 w-9 ${over ? "text-emerald-300" : "text-neutral-500"}`} />
      </motion.div>
      <p className="mt-4 text-base text-white">{over ? t.release : t.drop}</p>
      <p className="mt-1 text-sm text-neutral-500">{t.dropFormats}</p>
    </div>
  );
}

function Parsing({ tick, label, lines }: { tick: number; label: string; lines: string[] }) {
  const line = Math.min(tick + 1, lines.length - 1);
  return (
    <div>
      <p className="mb-4 text-sm text-emerald-300">{label}</p>
      <div className="relative rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-xs leading-7">
        {lines.map((text, i) => (
          <div
            key={i}
            className={`rounded px-2 transition-colors duration-300 ${
              i === line ? "bg-emerald-400/15 text-emerald-100" : i < line ? "text-neutral-400" : "text-neutral-600"
            }`}
          >
            {text}
          </div>
        ))}
      </div>
    </div>
  );
}

function HostTable({ tick, t }: { tick: number; t: Copy }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="text-xs text-neutral-500">
            {t.cols.map((c, i) => (
              <th key={c} className={`pb-3 font-normal ${i === 1 ? "hidden sm:table-cell" : ""}`}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {HOSTS.map((h, i) =>
            tick < PREVIEW_AT + i ? null : (
              <motion.tr
                key={h.name}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.5, ease: EASE }}
                className="border-t border-white/5"
              >
                <td className="py-3.5">
                  <div className="font-medium text-white">{h.name}</div>
                  <div className="font-mono text-xs text-neutral-500">{h.ip}</div>
                </td>
                <td className="hidden text-neutral-300 sm:table-cell">{h.os}</td>
                <td>
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-white/5 px-2 py-1 text-xs text-neutral-300">
                    <Lock className="h-3 w-3 text-emerald-300" />
                    {h.user}
                    <span className="hidden sm:inline">· {t.sealed}</span>
                  </span>
                </td>
                <td className="w-28 sm:w-56">
                  <Stage stage={stageOf(tick, i)} t={t} />
                </td>
              </motion.tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  );
}

function Stage({ stage, t }: { stage: number; t: Copy }) {
  if (stage >= 4)
    return (
      <span className="inline-flex items-center gap-2 text-sm text-emerald-300">
        <span className="relative flex h-2 w-2">
          <span className="absolute h-full w-full animate-ping rounded-full bg-emerald-300 opacity-60" />
          <span className="relative h-2 w-2 rounded-full bg-emerald-400" />
        </span>
        {t.online}
      </span>
    );
  return (
    <div>
      <div className="flex gap-1">
        {t.steps.map((step, s) => (
          <span
            key={step}
            className={`h-1.5 flex-1 rounded-full transition-colors duration-500 ${
              s < stage ? "bg-emerald-400" : s === stage ? "animate-pulse bg-emerald-400/60" : "bg-white/10"
            }`}
          />
        ))}
      </div>
      <p className="mt-1.5 text-xs text-neutral-500">{stage < 0 ? t.queued : t.steps[stage]}</p>
    </div>
  );
}
