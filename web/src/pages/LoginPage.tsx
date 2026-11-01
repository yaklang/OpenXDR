import { LockOutlined, MoonOutlined, SunOutlined, TranslationOutlined, UserOutlined } from '@ant-design/icons'
import { useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Space, Tooltip, Typography, theme } from 'antd'
import { useState } from 'react'
import { login } from '../api'
import { useTheme } from '../app/theme'
import { GeminiSparkle, Logo } from '../components/Logo'
import { useI18n, type MsgKey } from '../i18n'
import { errText } from '../components/format'

const POINTS: MsgKey[] = ['loginPoint1', 'loginPoint2', 'loginPoint3']

// 左侧品牌介绍、右侧登录表单；窄屏只留表单
export function LoginPage() {
  const { t, locale, setLocale } = useI18n()
  const { dark, toggle } = useTheme()
  const { token } = theme.useToken()
  const client = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (v: { username: string; password: string }) => {
    setBusy(true)
    setError(null)
    try {
      const me = await login(v.username, v.password)
      client.removeQueries({ predicate: query => query.queryKey[0] !== 'me' })
      client.setQueryData(['me'], me)
    } catch (e) {
      setError(errText(e, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-hero">
        <Space size={12} align="center">
          <Logo size={44} />
          <span className="login-hero-name">OpenXDR</span>
        </Space>
        <div className="login-hero-title">{t('loginHeroTitle')}</div>
        <div className="login-hero-sub">{t('loginSubtitle')}</div>
        <div className="login-hero-points">
          {POINTS.map(k => (
            <div key={k} className="login-hero-point-row">
              <span className="login-hero-point-icon"><GeminiSparkle size={16} /></span>
              <span className="login-hero-point">{t(k)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="login-panel" style={{ background: token.colorBgLayout }}>
        <div className="login-panel-Actions">
          <Space size={8}>
            <Tooltip title={dark ? t('lightMode') : t('darkMode')}>
              <Button shape="round" icon={dark ? <SunOutlined /> : <MoonOutlined />} onClick={toggle} aria-label={dark ? t('lightMode') : t('darkMode')} />
            </Tooltip>
            <Button shape="round" icon={<TranslationOutlined />} onClick={() => setLocale(locale === 'zh' ? 'en' : 'zh')}>
              {locale === 'zh' ? 'EN' : '中文'}
            </Button>
          </Space>
        </div>
        <div className="login-form">
          <div className="login-mobile-brand"><Logo size={36} /><span className="brand-name">OpenXDR</span></div>
          <Typography.Title level={2} style={{ marginBottom: 8, fontWeight: 600, letterSpacing: '-.022em' }}>{t('signInTitle')}</Typography.Title>
          <Typography.Text type="secondary">{t('signInHint')}</Typography.Text>
          <Form disabled={busy} layout="vertical" size="large" onFinish={submit} requiredMark={false} style={{ marginTop: 28 }}>
            <Form.Item label={t('username')} name="username" rules={[{ required: true, message: t('usernameRequired') }]}>
              <Input prefix={<UserOutlined />} placeholder={t('username')} autoComplete="username" autoFocus />
            </Form.Item>
            <Form.Item label={t('password')} name="password" rules={[{ required: true, message: t('passwordRequired') }]}>
              <Input.Password prefix={<LockOutlined />} placeholder={t('password')} autoComplete="current-password" />
            </Form.Item>
            {error && <Alert type="error" title={error} showIcon style={{ marginBottom: 18 }} />}
            <Button type="primary" shape="round" htmlType="submit" block loading={busy} style={{ marginTop: 8, height: 44, fontWeight: 500 }}>
              {t('signIn')}
            </Button>
          </Form>
        </div>
      </div>
    </div>
  )
}
