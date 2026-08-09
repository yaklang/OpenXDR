"use client";

import { Check, MoveRight } from "lucide-react";
import { motion, useReducedMotion, type Variants } from "motion/react";
import { useLocale } from "@/i18n";

const EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

const sources = [
  { code: "ED", en: ["Endpoint", "process + file"], zh: ["端点", "进程 + 文件"] },
  { code: "NW", en: ["Network", "flow + protocol"], zh: ["网络", "流量 + 协议"] },
  { code: "LG", en: ["Logs", "identity + cloud"], zh: ["日志", "身份 + 云"] },
];

const mappings = [
  ["process.path", "actor.process.file.path"],
  ["dst.ip", "dst_endpoint.ip"],
  ["user", "actor.user.name"],
];

function SourcesVisual() {
  const locale = useLocale();
  const streaming = locale === "zh-CN" ? "采集中" : "Streaming";
  const localizedSources = sources.map((source) => {
    const [name, meta] = locale === "zh-CN" ? source.zh : source.en;
    return { ...source, name, meta };
  });
  return (
    <div className="flex h-full flex-col justify-center gap-2.5">
      {localizedSources.map((source) => (
        <div
          key={source.code}
          className="flex items-center gap-3 rounded-xl border border-neutral-200 bg-white px-3.5 py-2.5 dark:border-neutral-800 dark:bg-neutral-950"
        >
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-neutral-100 text-[10px] font-semibold tracking-wide text-neutral-600 dark:bg-neutral-900 dark:text-neutral-400">
            {source.code}
          </span>
          <span className="min-w-0 flex-1 truncate text-sm">
            <span className="font-medium text-neutral-900 dark:text-white">
              {source.name}
            </span>
            <span className="text-neutral-500 dark:text-neutral-500">
              {" "}
              · {source.meta}
            </span>
          </span>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-neutral-100 px-2.5 py-1 text-[11px] font-medium text-neutral-600 dark:bg-neutral-900 dark:text-neutral-400">
            <Check className="h-3 w-3" />
            {streaming}
          </span>
        </div>
      ))}
    </div>
  );
}

function MappingVisual() {
  return (
    <div className="flex h-full flex-col justify-center gap-2.5">
      {mappings.map(([from, to]) => (
        <div
          key={from}
          className="grid grid-cols-[1fr_auto_1fr] items-center gap-2"
        >
          <span className="truncate rounded-lg border border-neutral-200 bg-white px-2.5 py-2 font-mono text-xs text-neutral-700 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-300">
            {from}
          </span>
          <MoveRight className="h-3.5 w-3.5 text-neutral-400 dark:text-neutral-600" />
          <span className="truncate rounded-lg border border-neutral-200 bg-white px-2.5 py-2 font-mono text-xs text-neutral-700 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-300">
            {to}
          </span>
        </div>
      ))}
    </div>
  );
}

function SyncVisual() {
  const locale = useLocale();
  const reduce = useReducedMotion();
  const syncStats =
    locale === "zh-CN"
      ? [
          ["证据汇聚", "进程 + 流量 + 身份"],
          ["降噪关卡", "去重 → 抑制 → 关联"],
          ["Agent 交接", "事件图"],
        ]
      : [
          ["Evidence joined", "process + flow + identity"],
          ["Noise gates", "dedupe → suppress → correlate"],
          ["Agent handoff", "incident graph"],
        ];
  return (
    <div className="flex h-full flex-col justify-center gap-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-neutral-900 dark:text-white">
          {locale === "zh-CN" ? "关联循环" : "Correlation loop"}
        </span>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-neutral-100 px-2.5 py-1 text-[11px] font-medium text-neutral-600 dark:bg-neutral-900 dark:text-neutral-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400" />
          {locale === "zh-CN" ? "实时" : "Live"}
        </span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
        <motion.div
          initial={reduce ? false : { scaleX: 0 }}
          whileInView={{ scaleX: 1 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.8, delay: 1.15, ease: EASE }}
          className="h-full origin-left rounded-full bg-neutral-900 dark:bg-white"
        />
      </div>
      <dl className="flex flex-col gap-1.5">
        {syncStats.map(([label, value]) => (
          <div
            key={label}
            className="flex items-center justify-between text-xs"
          >
            <dt className="text-neutral-500 dark:text-neutral-500">{label}</dt>
            <dd className="font-mono text-neutral-700 dark:text-neutral-300">
              {value}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function HowItWorks8() {
  const locale = useLocale();
  const reduce = useReducedMotion();
  const copy =
    locale === "zh-CN"
      ? {
          heading: "从原始遥测到可解释事件。",
          description:
            "核心处理链是确定且可检查的。证据完成归一化、去重与关联后，AI 才会介入。",
          steps: [
            {
              title: "采集不阻塞",
              copy: "大批量遥测数据可在数据通道中排队与恢复。心跳、策略和响应命令使用独立的低延迟控制通道。",
              visual: SourcesVisual,
            },
            {
              title: "在边界完成归一化",
              copy: "采集器保留原生细节，服务端则将资产、用户、进程、文件和网络端点对齐到共享的 OCSF 风格模型。",
              visual: MappingVisual,
            },
            {
              title: "先关联，再交给 AI",
              copy: "规则、情报、抑制与实体关联先压缩数据流。AI 只调查携带完整证据的剩余事件。",
              visual: SyncVisual,
            },
          ],
        }
      : {
          heading: "From raw telemetry to an explainable incident.",
          description:
            "The hot path is deterministic and inspectable. AI enters only after evidence has been normalized, deduplicated, and linked.",
          steps: [
            {
              title: "Collect without blocking",
              copy: "Bulk telemetry can queue and recover through the data channel. Heartbeats, policy, and response commands stay on a separate low-latency control path.",
              visual: SourcesVisual,
            },
            {
              title: "Normalize at the boundary",
              copy: "Collectors keep native detail while the server aligns assets, users, processes, files, and network endpoints into a shared OCSF-style model.",
              visual: MappingVisual,
            },
            {
              title: "Correlate before AI",
              copy: "Rules, intelligence, suppression, and entity correlation reduce the stream first. AI investigates the surviving incident with its evidence attached.",
              visual: SyncVisual,
            },
          ],
        };

  const container: Variants = {
    hidden: {},
    show: { transition: { staggerChildren: 0.1 } },
  };

  const item: Variants = {
    hidden: { opacity: 0, y: reduce ? 0 : 24 },
    show: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.65, ease: EASE },
    },
  };

  return (
    <section
      aria-labelledby="hiw8-heading"
      id="pipeline"
      className="w-full bg-white px-4 py-16 dark:bg-neutral-950 sm:px-6 sm:py-20 lg:px-8 lg:py-24"
    >
      <div className="mx-auto w-full max-w-[1400px]">
        <motion.div
          initial={{ opacity: 0, y: reduce ? 0 : 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-80px" }}
          transition={{ duration: 0.6, ease: EASE }}
          className="mx-auto max-w-2xl text-center"
        >
          <h2
            id="hiw8-heading"
            className="text-3xl font-medium leading-[1.1] tracking-tight text-neutral-900 text-balance dark:text-white sm:text-4xl lg:text-5xl"
          >
            {copy.heading}
          </h2>
          <p className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-neutral-600 dark:text-neutral-400 sm:text-lg">
            {copy.description}
          </p>
        </motion.div>

        <motion.ol
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          className="mt-14 grid list-none grid-cols-1 gap-12 sm:mt-16 lg:mt-20 lg:grid-cols-3 lg:gap-x-12"
        >
          {copy.steps.map((step, index) => {
            const Visual = step.visual;
            const segment =
              index === 0
                ? "left-0 -right-6"
                : index === copy.steps.length - 1
                  ? "-left-6 right-0"
                  : "-left-6 -right-6";
            return (
              <motion.li
                key={step.title}
                variants={item}
                className="border-t border-neutral-200 pt-10 first:border-t-0 first:pt-0 dark:border-neutral-800 lg:border-t-0 lg:pt-0"
              >
                <div
                  aria-hidden="true"
                  className="rounded-2xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-900 lg:h-56"
                >
                  <Visual />
                </div>
                <div className="relative mt-8 flex h-10 items-center">
                  <div
                    aria-hidden="true"
                    className={`absolute top-1/2 hidden h-px -translate-y-1/2 bg-neutral-200 dark:bg-neutral-800 lg:block ${segment}`}
                  />
                  <motion.div
                    aria-hidden="true"
                    initial={reduce ? false : { scaleX: 0 }}
                    whileInView={{ scaleX: 1 }}
                    viewport={{ once: true, margin: "-80px" }}
                    transition={{
                      duration: 0.35,
                      delay: 0.3 + index * 0.35,
                      ease: "linear",
                    }}
                    className={`absolute top-1/2 hidden h-px origin-left -translate-y-1/2 bg-neutral-900 dark:bg-white lg:block ${segment}`}
                  />
                  <span className="relative z-10 flex h-10 w-10 items-center justify-center rounded-full bg-neutral-900 font-mono text-sm font-medium text-white dark:bg-white dark:text-neutral-950">
                    {index + 1}
                  </span>
                </div>
                <h3 className="mt-6 text-xl font-semibold tracking-tight text-neutral-900 text-balance dark:text-white sm:text-2xl">
                  {step.title}
                </h3>
                <p className="mt-3 max-w-sm text-sm leading-relaxed text-neutral-600 dark:text-neutral-400 sm:text-[15px]">
                  {step.copy}
                </p>
              </motion.li>
            );
          })}
        </motion.ol>
      </div>
    </section>
  );
}
