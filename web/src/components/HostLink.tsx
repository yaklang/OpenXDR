import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { fetchAssets } from '../api'

// 主机名：能对上受管资产就链到资产详情，否则原样显示
export function HostLink({ id, fallback }: { id: string | null | undefined; fallback?: string }) {
  // 历史事件里的主机可能已下线，名字照样要显示
  const { data: hosts = {} } = useQuery({ queryKey: ['assets', 'retired'], queryFn: () => fetchAssets(true), select: as => Object.fromEntries(as.map(a => [a.id, a.hostname])) })
  if (!id) return <>{fallback ?? '-'}</>
  const name = hosts[id]
  return name ? <Link to={`/assets/${id}`}>{name}</Link> : <>{fallback ?? id.slice(-8)}</>
}
