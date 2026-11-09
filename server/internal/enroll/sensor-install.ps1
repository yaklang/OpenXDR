# OpenXDR 流量探针一键安装（Windows，管理员 PowerShell）。在控制台「添加主机 → 流量探针」复制命令执行：
#   & ([scriptblock]::Create((irm <控制台>/api/enroll/sensor-install.ps1))) <控制台> <令牌> [网卡]
# 抓包走系统自带的 Packet Monitor 实时 API（Windows 11 / Windows Server 2022 2022-06 更新以上），不装任何驱动。
# 不指定网卡就抓本机所有网卡；指定时填网卡名或描述里的一段。系统不支持时安装前就停下，不留半套。
# 以 SYSTEM 身份的计划任务常驻：开机启动，另每分钟检查一次，进程不在就拉起。重复执行即重装。
param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Token, [string]$Iface = 'all')
$ErrorActionPreference = 'Stop'
if (([uri]$Base).Scheme -ne 'https') { throw '接入需要可信 HTTPS 控制台地址' }
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '需要管理员权限，请用"以管理员身份运行"的 PowerShell 执行'
}
# 网卡参数进配置文件，只收单行文本
if ($Iface -match '[\r\n=]') { throw "网卡参数不合法：$Iface" }

$dir = Join-Path $env:ProgramData 'OpenXDR'
$bin = Join-Path $dir 'openxdr-sensor.exe'
$new = Join-Path $dir 'openxdr-sensor.new.exe'
$task = 'OpenXDR Sensor'

New-Item -ItemType Directory -Force -Path $dir | Out-Null
# 私钥与证书所在目录只留 SYSTEM 与管理员（与 agent 同一目录、同一口径）
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法限制凭据目录访问权限' }

Write-Host '下载 sensor（windows-amd64）'
Invoke-WebRequest -UseBasicParsing -Uri "$Base/api/enroll/sensor/windows-amd64" -OutFile $new
& $new version | Out-Null
if ($LASTEXITCODE -ne 0) { throw '新版 sensor 自检失败' }
# 先确认系统有实时包流 API，再列出能抓的网卡；不支持就到此为止。
# PowerShell 5.1 在 Stop 下会把外部程序的 stderr 当成异常抛出，这一步临时放宽，自己看退出码
$ErrorActionPreference = 'Continue'
$nics = & $new interfaces 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($code -ne 0) {
    Remove-Item -Force $new -ErrorAction SilentlyContinue
    throw "本机不能运行流量探针：$nics"
}
Write-Host '本机网卡（描述 / 名称）：'
$nics | ForEach-Object { Write-Host "  $_" }
if ($Iface -ne 'all' -and -not ($nics | Where-Object { $_ -like "*$Iface*" })) {
    Remove-Item -Force $new -ErrorAction SilentlyContinue
    throw "没有匹配「$Iface」的网卡"
}

Write-Host '签发探针证书并接入'
$request = (& $new enroll-request $dir) -join "`n"
if ($LASTEXITCODE -ne 0) { throw '生成接入请求失败' }
try {
    $grant = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Base/api/enroll/register" `
        -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $request
} catch {
    # 被拒绝时把 server 给的原因原样告诉用户，而不是只有状态码
    $reason = $_.ErrorDetails.Message
    if (-not $reason -and $_.Exception.Response) {
        $reason = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
    }
    throw "接入被拒绝：$reason"
}
$grant.Content | & $new enroll-apply $dir
if ($LASTEXITCODE -ne 0) { throw '写入接入配置失败' }
# Windows 没有 systemd 的 Environment=：抓哪块网卡写进 sensor.env，sensor 启动时自己读
# 不带 BOM 的 UTF-8：追加处若写进 BOM，这一行的键就认不出了
[IO.File]::AppendAllText((Join-Path $dir 'sensor.env'), "SENSOR_IFACE=$Iface`n", (New-Object Text.UTF8Encoding($false)))

if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-Process openxdr-sensor -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $bin) { Move-Item -Force $bin "$bin.prev" }
Move-Item -Force $new $bin

$action = New-ScheduledTaskAction -Execute $bin
# 与 agent 同一套常驻方式：失败重启只管任务没拉起来，升级后的退出靠每分钟一次的检查拉起
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$triggers = @((New-ScheduledTaskTrigger -AtStartup), $watchdog)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest | Out-Null
Start-ScheduledTask -TaskName $task
Write-Host "完成：$env:COMPUTERNAME 的流量探针已接入，抓包网卡 $Iface，几秒后可在控制台资产详情看到抓包状态"
