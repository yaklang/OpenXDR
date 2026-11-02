import { useId } from 'react'

// 导航、登录页与浏览器标签共用同一份品牌图标。
export function Logo({ size = 28 }: { size?: number }) {
  return <img src="/favicon.svg" width={size} height={size} alt="OpenXDR" style={{ flexShrink: 0 }} />
}

// Gemini 四芒星图标：用于 AI 助手欢迎页、消息流头像与思考状态动画
export function GeminiSparkle({ size = 24, active = false, className }: { size?: number; active?: boolean; className?: string }) {
  const gradId = useId()
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 28 28"
      fill="none"
      aria-hidden="true"
      className={[ 'gemini-sparkle', active ? 'gemini-sparkle-active' : '', className ].filter(Boolean).join(' ')}
      style={{ flexShrink: 0 }}
    >
      <defs>
        <linearGradient id={gradId} x1="2" y1="2" x2="26" y2="26" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#4285f4" />
          <stop offset="50%" stopColor="#9b72cb" />
          <stop offset="100%" stopColor="#d96570" />
        </linearGradient>
      </defs>
      <path
        d="M14 2C14 8.627 19.373 14 26 14C19.373 14 14 19.373 14 26C14 19.373 8.627 14 2 14C8.627 14 14 8.627 14 2Z"
        fill={`url(#${gradId})`}
      />
    </svg>
  )
}

