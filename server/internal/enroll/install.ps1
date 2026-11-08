# OpenXDR agent 一键安装（Windows，管理员 PowerShell）。在控制台「添加主机」复制命令执行：
#   & ([scriptblock]::Create((irm <控制台>/api/enroll/install.ps1))) <控制台> <令牌>
# 以 SYSTEM 身份的计划任务常驻：开机启动，另每分钟检查一次，进程不在就拉起
# （自动升级后的退出、意外崩溃都靠它恢复）。日志在 OpenXDR\logs\agent.log。重复执行即重装。
param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Token)
$ErrorActionPreference = 'Stop'
if (([uri]$Base).Scheme -ne 'https') { throw '接入需要可信 HTTPS 控制台地址' }
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw '需要管理员权限，请用"以管理员身份运行"的 PowerShell 执行'
}

$dir = Join-Path $env:ProgramData 'OpenXDR'
$bin = Join-Path $dir 'openxdr-agent.exe'
$new = Join-Path $dir 'openxdr-agent.new.exe'
$task = 'OpenXDR Agent'

New-Item -ItemType Directory -Force -Path $dir | Out-Null
# 私钥与证书所在目录只留 SYSTEM 与管理员
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法限制凭据目录访问权限' }

Write-Host '下载 agent（windows-amd64）'
Invoke-WebRequest -UseBasicParsing -Uri "$Base/api/enroll/agent/windows-amd64" -OutFile $new
& $new version | Out-Null
if ($LASTEXITCODE -ne 0) { throw '新版 agent 自检失败' }

Write-Host '签发主机证书并接入'
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

if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
}
Get-Process openxdr-agent -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $bin) { Move-Item -Force $bin "$bin.prev" }
Move-Item -Force $new $bin

# 托盘（只显示防护状态）装到 Program Files：agent 目录放着私钥、普通用户进不去，Program Files 普通用户能执行、
# 只有管理员能改。agent 启动时在 HKLM Run 里登记，用户下次登录出现。分发目录里没有托盘程序就跳过，不影响接入
$trayDir = Join-Path $env:ProgramFiles 'OpenXDR'
$tray = Join-Path $trayDir 'openxdr-tray.exe'
try {
    New-Item -ItemType Directory -Force -Path $trayDir | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/api/enroll/tray/windows-amd64" -OutFile "$tray.new"
    Get-Process openxdr-tray -ErrorAction SilentlyContinue | Stop-Process -Force
    Move-Item -Force "$tray.new" $tray
} catch {
    Remove-Item -Force "$tray.new" -ErrorAction SilentlyContinue
    Write-Host '分发目录没有托盘程序，跳过'
}

$action = New-ScheduledTaskAction -Execute $bin
# 「失败时重新启动」只管任务没拉起来，进程以非零码退出（升级后的 75）不会触发，实机验证过；
# 升级后的重启全靠这个检查：通常 1 分钟内拉起；碰上旧进程还在排空（最多约 40 秒）的那一次被跳过，最坏约 2 分钟
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
$triggers = @((New-ScheduledTaskTrigger -AtStartup), $watchdog)
# 已在运行时跳过新实例，重复触发只起到"不在就拉起"的作用
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $task -Action $action -Trigger $triggers -Settings $settings `
    -User 'SYSTEM' -RunLevel Highest | Out-Null
Start-ScheduledTask -TaskName $task
Write-Host "完成：$env:COMPUTERNAME 已接入，几秒后会出现在控制台资产列表"
