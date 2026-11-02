import { App as AntApp, ConfigProvider, theme } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { useI18n } from '../i18n'

export type ThemeMode = 'system' | 'light' | 'dark'

const ThemeContext = createContext<{ dark: boolean; mode: ThemeMode; setMode: (m: ThemeMode) => void; toggle: () => void }>({
  dark: false, mode: 'system', setMode: () => {}, toggle: () => {},
})

const query = '(prefers-color-scheme: dark)'
const stored = (): ThemeMode => {
  const v = localStorage.getItem('theme')
  return v === 'light' || v === 'dark' ? v : 'system'
}

// Google Gemini / Material 3 调色板：亮暗两套采用柔和色调表面（Tonal Surface）分出层次，弱化生硬描边
const PALETTE = {
  light: {
    primary: '#0b57d0', success: '#1e8e3e', warning: '#e37400', error: '#d93025',
    layout: '#f4f7fc', sider: '#eaf0f9', panel: '#ffffff', elevated: '#ffffff',
    text: '#1f1f1f', text2: '#444746', text3: '#747775', border: '#c4c7c5', hairline: 'rgba(11,87,208,.075)',
    fill: 'rgba(11,87,208,.09)', fill2: '#e7eef8', fill3: '#eff4fb', fill4: '#f6f9fe',
    menuSelectedBg: '#d3e3fd', menuSelectedColor: '#041e49',
  },
  dark: {
    primary: '#4c8df6', success: '#34a853', warning: '#fbbc04', error: '#ea4335',
    layout: '#131314', sider: '#1b1c1e', panel: '#1e1f22', elevated: '#282a2e',
    text: '#e3e3e3', text2: '#c4c7c5', text3: '#8e918f', border: '#444746', hairline: 'rgba(255,255,255,.075)',
    fill: 'rgba(168,199,250,.14)', fill2: '#282a2e', fill3: '#222428', fill4: 'rgba(255,255,255,.04)',
    menuSelectedBg: 'rgba(168,199,250,.18)', menuSelectedColor: '#c2e7ff',
  },
}

// 外观默认跟随系统，账号菜单里可以固定成亮色或暗色；选择记在本地
export function ThemeProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n()
  const [mode, setModeState] = useState<ThemeMode>(stored)
  const [systemDark, setSystemDark] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const m = window.matchMedia(query)
    const on = () => setSystemDark(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])
  const dark = mode === 'system' ? systemDark : mode === 'dark'
  useEffect(() => { document.documentElement.dataset.theme = dark ? 'dark' : 'light' }, [dark])
  const setMode = (m: ThemeMode) => {
    if (m === 'system') localStorage.removeItem('theme')
    else localStorage.setItem('theme', m)
    setModeState(m)
  }
  const toggle = () => setMode(dark ? 'light' : 'dark')
  const c = PALETTE[dark ? 'dark' : 'light']
  return (
    <ThemeContext.Provider value={{ dark, mode, setMode, toggle }}>
      <ConfigProvider
        locale={locale === 'zh' ? zhCN : enUS}
        // 两个汉字的按钮不插空格：「保存」「关闭」和其他按钮读起来一致
        button={{ autoInsertSpace: false }}
        // 标签一律浅色填充无描边，胶囊质感
        tag={{ variant: 'filled' }}
        theme={{
          algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
          token: {
            colorPrimary: c.primary,
            colorInfo: c.primary,
            colorLink: dark ? '#a8c7fa' : c.primary,
            colorError: c.error,
            colorWarning: c.warning,
            colorSuccess: c.success,
            colorText: c.text,
            colorTextSecondary: c.text2,
            colorTextTertiary: c.text3,
            colorTextQuaternary: dark ? '#5e6060' : '#9aa0a6',
            colorBgLayout: c.layout,
            colorBgContainer: c.panel,
            colorBgElevated: c.elevated,
            colorBorder: c.border,
            colorBorderSecondary: c.hairline,
            colorSplit: c.hairline,
            colorFill: c.fill,
            colorFillSecondary: c.fill2,
            colorFillTertiary: c.fill3,
            colorFillQuaternary: c.fill4,
            borderRadius: 12,
            borderRadiusLG: 18,
            borderRadiusSM: 8,
            fontFamily: '"Google Sans", Inter, -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Hiragino Sans GB", "Segoe UI", "Microsoft YaHei", sans-serif',
            fontFamilyCode: '"Google Sans Mono", "JetBrains Mono", ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace',
            // 柔和漫射投影，靠色调表面区分主次
            boxShadow: dark ? '0 8px 28px rgba(0,0,0,.48)' : '0 6px 24px rgba(11,87,208,.08), 0 1px 4px rgba(0,0,0,.04)',
            boxShadowSecondary: dark ? '0 14px 44px rgba(0,0,0,.6)' : '0 12px 36px rgba(11,87,208,.11), 0 2px 8px rgba(0,0,0,.05)',
            boxShadowTertiary: 'none',
            controlOutline: dark ? 'rgba(168,199,250,.32)' : 'rgba(11,87,208,.2)',
            motionDurationMid: '0.2s',
          },
          components: {
            // Gemini 壳层：侧栏采用柔和次级表面色，与主画布自然过渡
            Layout: { headerHeight: 60, headerPadding: '0 24px', headerBg: 'transparent', lightSiderBg: c.sider, siderBg: c.sider, bodyBg: c.layout },
            Menu: {
              itemBg: 'transparent',
              subMenuItemBg: 'transparent',
              itemHeight: 40,
              itemMarginBlock: 3,
              itemMarginInline: 12,
              itemBorderRadius: 999,
              groupTitleFontSize: 11,
              groupTitleColor: c.text3,
              iconMarginInlineEnd: 12,
              activeBarBorderWidth: 0,
              itemColor: c.text2,
              itemSelectedBg: c.menuSelectedBg,
              itemSelectedColor: c.menuSelectedColor,
              itemHoverBg: c.fill2,
            },
            Card: { headerFontSize: 15.5, headerHeight: 58, headerFontSizeSM: 14.5, borderRadiusLG: 22, bodyPadding: 24, bodyPaddingSM: 18 },
            Table: {
              headerBg: 'transparent', headerColor: c.text3, headerSplitColor: 'transparent',
              borderColor: c.hairline, rowHoverBg: c.fill4,
              cellPaddingBlock: 14, cellPaddingInline: 16,
              cellPaddingBlockSM: 11, cellPaddingInlineSM: 14,
              headerSortActiveBg: 'transparent', headerSortHoverBg: 'transparent',
              rowSelectedBg: dark ? 'rgba(168,199,250,.14)' : 'rgba(11,87,208,.07)', rowSelectedHoverBg: dark ? 'rgba(168,199,250,.2)' : 'rgba(11,87,208,.11)',
            },
            Descriptions: { itemPaddingBottom: 12 },
            // 按钮默认采用 Gemini / Material 3 胶囊圆角，次要按钮为柔和表面色无描边（Tonal Button）
            Button: {
              borderRadius: 999, borderRadiusSM: 999, borderRadiusLG: 999,
              primaryShadow: 'none', defaultShadow: 'none', dangerShadow: 'none',
              defaultBg: c.fill2, defaultBorderColor: 'transparent', defaultHoverBg: c.fill, defaultHoverBorderColor: 'transparent',
              defaultActiveBg: c.fill, defaultActiveBorderColor: 'transparent', defaultColor: c.text, defaultHoverColor: c.text,
              fontWeight: 500,
            },
            Segmented: { trackBg: c.fill2, itemSelectedBg: dark ? '#383a3e' : '#ffffff', trackPadding: 3, borderRadius: 999, borderRadiusSM: 999, borderRadiusLG: 999 },
            Tabs: { itemColor: c.text2, inkBarColor: c.primary, itemSelectedColor: c.primary, itemHoverColor: c.text, titleFontSize: 14 },
            Input: { activeShadow: `0 0 0 3px ${dark ? 'rgba(168,199,250,.25)' : 'rgba(11,87,208,.15)'}` },
            Select: { activeOutlineColor: dark ? 'rgba(168,199,250,.25)' : 'rgba(11,87,208,.15)' },
            Tag: { defaultBg: c.fill2, defaultColor: c.text2, borderRadiusSM: 999 },
            Statistic: { contentFontSize: 28 },
            Modal: { titleFontSize: 18, borderRadiusLG: 24 },
            Drawer: { footerPaddingBlock: 14 },
            Tooltip: { colorBgSpotlight: dark ? '#303134' : 'rgba(31,31,31,.92)', borderRadius: 8 },
          },
        }}
      >
        <AntApp>{children}</AntApp>
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
