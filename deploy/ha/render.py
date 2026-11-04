#!/usr/bin/env python3
"""把 HA 模板渲染到 runtime/；密钥只来自环境变量，不进入 Git。"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import quote


REQUIRED_SECRETS = (
    "OPENXDR_PASSWORD",
    "POSTGRES_PASSWORD",
    "REPLICATION_PASSWORD",
    "PATRONI_RESTAPI_PASSWORD",
    "NATS_ROUTE_PASSWORD",
    "VRRP_PASSWORD",
)


def render(source: Path, target: Path, values: dict[str, str]) -> None:
    content = source.read_text()
    for key, value in values.items():
        content = content.replace(f"__{key}__", value)
    if "__" in content:
        unresolved = sorted({part.split("__", 1)[0] for part in content.split("__")[1::2]})
        raise SystemExit(f"{source}: 未解析模板变量: {unresolved}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    target.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", choices=("node1", "node2"), required=True)
    parser.add_argument("--witness", required=True)
    parser.add_argument("--output", type=Path, default=Path("runtime"))
    args = parser.parse_args()

    missing = [name for name in REQUIRED_SECRETS if not os.environ.get(name)]
    if missing:
        raise SystemExit("缺少环境变量: " + ", ".join(missing))

    url_safe = re.compile(r"[A-Za-z0-9._~-]+")
    for name in ("OPENXDR_PASSWORD", "NATS_ROUTE_PASSWORD"):
        if not url_safe.fullmatch(os.environ[name]):
            raise SystemExit(f"{name} 只能包含 URL-safe 字符 A-Z a-z 0-9 . _ ~ -")
    if not re.fullmatch(r"[A-Za-z0-9]{1,8}", os.environ["VRRP_PASSWORD"]):
        raise SystemExit("VRRP_PASSWORD 必须是 1-8 位字母或数字")
    if any("__" in os.environ[name] for name in REQUIRED_SECRETS):
        raise SystemExit("密码不能包含模板分隔符 __")

    node1 = args.node == "node1"
    values = {
        "NODE_NAME": f"openxdr-{args.node}",
        "NODE_IP": "10.1.1.198" if node1 else "10.1.1.197",
        "PEER_IP": "10.1.1.197" if node1 else "10.1.1.198",
        "DCS_HOST": args.witness,
        "WITNESS_HOST": args.witness,
        "KEEPALIVED_STATE": "MASTER" if node1 else "BACKUP",
        "KEEPALIVED_PRIORITY": "150" if node1 else "140",
        "OPENXDR_PASSWORD_YAML": json.dumps(os.environ["OPENXDR_PASSWORD"]),
        "POSTGRES_PASSWORD_YAML": json.dumps(os.environ["POSTGRES_PASSWORD"]),
        "REPLICATION_PASSWORD_YAML": json.dumps(os.environ["REPLICATION_PASSWORD"]),
        "PATRONI_RESTAPI_PASSWORD_YAML": json.dumps(os.environ["PATRONI_RESTAPI_PASSWORD"]),
        "NATS_ROUTE_PASSWORD_CONF": json.dumps(os.environ["NATS_ROUTE_PASSWORD"]),
        "NATS_ROUTE_PASSWORD_URL": quote(os.environ["NATS_ROUTE_PASSWORD"], safe=""),
        "VRRP_PASSWORD": os.environ["VRRP_PASSWORD"],
    }
    root = Path(__file__).resolve().parents[2]
    render(root / "deploy/ha/patroni.yml", args.output / "patroni.yml", values)
    render(root / "deploy/ha/nats.conf", args.output / "nats.conf", values)
    render(root / "deploy/ha/keepalived.conf", args.output / "keepalived.conf", values)
    # post-bootstrap.sh 建 openxdr 角色用；以文件挂进 patroni 容器，不经环境变量传
    password_file = args.output / "openxdr-db-password"
    password_file.write_text(os.environ["OPENXDR_PASSWORD"])
    password_file.chmod(0o600)


if __name__ == "__main__":
    main()
