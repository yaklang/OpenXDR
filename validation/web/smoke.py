"""对已构建的控制台做离线浏览器回归；所有 API 都由本地固定数据替代。"""

import argparse
import json
import re
import threading
import traceback
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import gettempdir
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
GROUP = "00000000-0000-4000-8000-000000000001"
ASSETS = ["00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"]
SESSION = "00000000-0000-4000-8000-000000000004"


def row_id(n):
    return f"00000000-0000-4000-8000-{n + 100:012x}"


def check(condition, message):
    # Python -O 会删除普通 assert；验证脚本的失败条件必须始终生效。
    if not condition:
        raise AssertionError(message)


class Fixtures:
    def __init__(self):
        self.now = datetime.now(timezone.utc).isoformat()
        self.failed = set()
        self.unexpected = []
        self.overrides = {}
        self.counts = {"incidents": {ASSETS[0]: 51, ASSETS[1]: 1}, "findings": {ASSETS[0]: 501, ASSETS[1]: 51}}
        self.assets = [dict(id=aid, hostname=name, os="windows", ipAddrs=[f"192.0.2.{i + 10}"],
                            groupId=GROUP, agentId=aid, firstSeen=self.now, lastSeen=self.now)
                       for i, (aid, name) in enumerate(zip(ASSETS, ["FIRST-WIN", "SECOND-WIN"]))]

    def rows(self, kind, asset_id):
        base = dict(createdAt=self.now, status="open", severity=4, groupId=GROUP, aiVerdict=None,
                    closureProposal=None, triagedAt=None, triageCount=0, alertCount=1)
        if kind == "findings":
            base = dict(status="open", severity="medium", groupId=GROUP, key="test-telemetry",
                        firstSeen=self.now, lastSeen=self.now, detail="离线测试待办", sessionId=SESSION)
        prefix = "事件" if kind == "incidents" else "待办"
        hostname = next(asset["hostname"] for asset in self.assets if asset["id"] == asset_id)
        if asset_id == ASSETS[1]:
            prefix = "第二台" + prefix
        return [dict(base, id=row_id(i + ASSETS.index(asset_id) * 10000), title=f"{prefix}-{i}", assetId=asset_id, hostname=hostname) | self.overrides.get((kind, i), {})
                for i in range(self.counts[kind][asset_id])]

    def payload(self, path, params):
        if path == "/api/me":
            return dict(username="admin", role="admin"), None
        if path == "/api/groups":
            return [dict(id=GROUP, name="离线测试组", role="admin", assetCount=2, createdAt=self.now)], None
        if path == "/api/setup":
            return dict(accepted=True, onboarded=True), None
        if path == "/api/settings/notify":
            return dict(url="", format="generic", linkBase="", minSeverity=3), None
        if path == "/api/assets":
            return self.assets, None
        if path in [f"/api/assets/{aid}/profile" for aid in ASSETS]:
            return dict(zone=dict(name="", kind="internal", source="auto"), exposure="internal", listening=[],
                        outbound=[], inbound=[], publicDestinations=0, aiEnabled=False), None
        if path == "/api/stats":
            return dict(events24h=0, alerts24h=0, openIncidents=0, reviewIncidents=0,
                        assetsTotal=2, assetsOnline=2, alertsBySeverity={}, incidentsByStatus={},
                        topRules=None, alertTrend=[dict(hour=self.now, count=0)]), None
        if path in ["/api/incidents", "/api/findings"]:
            kind = path.rsplit("/", 1)[1]
            rows = self.rows(kind, params.get("assetId", [ASSETS[0]])[0])
            if "ids" in params:
                ids = params["ids"][0].split(",")
                rows = [row for row in rows if row["id"] in ids]
            status = params.get("status", [None])[0]
            if status and status not in ("unresolved", "review"):
                rows = [row for row in rows if row["status"] == status]
            offset, limit = int(params.get("offset", [0])[0]), int(params.get("limit", [500])[0])
            return rows[offset:offset + limit], len(rows)
        if path == f"/api/incidents/{row_id(0)}":
            return dict(self.rows("incidents", ASSETS[0])[0], alerts=[], graph=dict(nodes=[], edges=[])), None
        session = dict(id=SESSION, created_at=self.now, kind="chat", group_id=GROUP, initiator="admin",
                       model="offline-test", title="离线关联对象测试", status="idle",
                       subjects=[f"incident:{row_id(0)}", f"finding:{row_id(500)}"])
        if path == "/api/agent-sessions":
            return [session], None
        if path == f"/api/agent-sessions/{SESSION}":
            return session, None
        if path in ["/api/events", "/api/commands", "/api/tasks", "/api/approvals", "/api/suppressions", "/api/zones",
                    "/api/agent-reports", f"/api/agent-sessions/{SESSION}/messages"]:
            return [], 0
        if path == "/api/intel":
            return [dict(id=row_id(900), kind="domain", value="manual.example.test", source="manual", severity=3, matchedCount=0)], None
        raise ValueError(f"未定义的离线接口: {path}")

    def route(self, route):
        parsed = urlparse(route.request.url)
        if parsed.hostname != "127.0.0.1":
            self.unexpected.append("外部请求: " + parsed.netloc)
            route.abort()
            return
        if not parsed.path.startswith("/api/"):
            route.continue_()
            return
        try:
            if route.request.method != "GET":
                raise ValueError(f"未定义的操作: {route.request.method} {parsed.path}")
            if parsed.path in self.failed:
                route.fulfill(status=500, content_type="text/plain", body="离线测试注入的读取失败")
                return
            body, total = self.payload(parsed.path, parse_qs(parsed.query))
            route.fulfill(status=200, content_type="application/json", body=json.dumps(body),
                          headers={} if total is None else {"X-Total-Count": str(total)})
        except Exception as error:
            self.unexpected.append(str(error))
            route.fulfill(status=500, content_type="text/plain", body="离线接口未定义")


class StaticHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if not Path(self.translate_path(self.path)).is_file():
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, *args):
        pass


def reconnect(page):
    page.context.set_offline(True)
    page.wait_for_timeout(100)
    page.context.set_offline(False)


def asset_navigation(page, base, fixtures):
    page.goto(f"{base}/assets/{ASSETS[0]}?tab=events")
    expect(page.locator('[role=tab][aria-selected=true]')).to_have_text("近 7 天事件")
    page.get_by_role("button", name="运维待办 501", exact=True).click()
    expect(page.get_by_role("tabpanel").get_by_text("待办-0", exact=True)).to_be_visible()
    check(parse_qs(urlparse(page.url).query)["tab"] == ["findings"], f"标签 URL 未更新: {page.url}")
    page.reload()
    expect(page.get_by_role("tabpanel").get_by_text("待办-0", exact=True)).to_be_visible()
    page.go_back()
    expect(page.locator('[role=tab][aria-selected=true]')).to_have_text("近 7 天事件")
    page.go_forward()
    expect(page.get_by_role("tabpanel").get_by_text("待办-0", exact=True)).to_be_visible()
    page.goto(f"{base}/assets/{ASSETS[0]}?tab=invalid")
    expect(page.locator('[role=tab][aria-selected=true]')).to_contain_text("安全事件")


def asset_pagination(page, base, fixtures):
    for kind, prefix, last_page in [("incidents", "事件", 6), ("findings", "待办", 51)]:
        page.goto(f"{base}/assets/{ASSETS[0]}?tab={kind}")
        panel = page.get_by_role("tabpanel")
        expect(panel.get_by_text(f"{prefix}-0", exact=True)).to_be_visible()
        expect(panel.locator(".ant-pagination-options-size-changer")).to_have_count(0)
        panel.locator(f".ant-pagination-item-{last_page}").click()
        expect(panel.get_by_text(f"{prefix}-{(last_page - 1) * 10}", exact=True)).to_be_visible()
        fixtures.counts[kind][ASSETS[0]] = 1
        reconnect(page)
        expect(panel.get_by_text(f"{prefix}-0", exact=True)).to_be_visible()
        fixtures.counts[kind][ASSETS[0]] = 51
        reconnect(page)
        panel.locator(".ant-pagination-item-6").click()
        expect(panel.get_by_text(f"{prefix}-50", exact=True)).to_be_visible()
        page.locator(".app-search").click()
        page.get_by_placeholder("输入主机名、IP、事件标题、会话或页面名").fill("SECOND-WIN")
        page.get_by_role("option").filter(has_text="SECOND-WIN").click()
        if kind == "findings":
            page.get_by_role("button", name="运维待办 51", exact=True).click()
        expect(page.get_by_role("tabpanel").get_by_text(f"第二台{prefix}-0", exact=True)).to_be_visible()


def asset_errors(page, base, fixtures):
    fixtures.counts["incidents"][ASSETS[0]] = 0
    fixtures.counts["findings"][ASSETS[0]] = 0
    page.goto(f"{base}/assets/{ASSETS[0]}?tab=findings")
    labels = ["未结案事件", "运维待办", "近 7 天事件"]
    for label in labels:
        expect(page.get_by_role("button", name=f"{label} 0", exact=True)).to_be_visible()
    fixtures.failed = {"/api/incidents", "/api/findings", "/api/events"}
    reconnect(page)
    expect(page.get_by_role("tabpanel").get_by_text("加载失败", exact=True)).to_be_visible()
    for label in labels:
        expect(page.get_by_role("button", name=f"{label} -", exact=True)).to_be_visible()
    fixtures.failed.clear()
    for label, tab_label in zip(labels, ["安全事件", "运维待办", "近 7 天事件"]):
        page.get_by_role("button", name=f"{label} -", exact=True).click()
        panel = page.get_by_role("tabpanel", name=re.compile(tab_label))
        expect(panel).to_be_visible()
        panel.get_by_role("button", name="重试", exact=True).click()
        expect(page.get_by_role("button", name=f"{label} 0", exact=True)).to_be_visible()


def queue_pagination(page, base, fixtures):
    for kind, prefix, last_page, size in [("incidents", "事件", 2, 50), ("findings", "待办", 26, 20)]:
        original_count = fixtures.counts[kind][ASSETS[0]]
        page.goto(f"{base}/{kind}?status=open&page=999")
        expect(page.get_by_text(f"{prefix}-{(last_page - 1) * size}", exact=True)).to_be_visible()
        check(parse_qs(urlparse(page.url).query)["page"] == [str(last_page)], f"越界页码未回退: {page.url}")
        fixtures.counts[kind][ASSETS[0]] = size
        reconnect(page)
        expect(page.get_by_text(f"{prefix}-0", exact=True)).to_be_visible()
        check(parse_qs(urlparse(page.url).query)["status"] == ["open"], f"筛选条件丢失: {page.url}")
        fixtures.counts[kind][ASSETS[0]] = original_count
        reconnect(page)
        page.locator(f".ant-pagination-item-{last_page}").click()
        expect(page.get_by_text(f"{prefix}-{(last_page - 1) * size}", exact=True)).to_be_visible()
    page.goto(f"{base}/findings")
    page.locator(".ant-pagination-item-2").click()
    selected = page.get_by_role("row").filter(has=page.get_by_text("待办-20", exact=True)).get_by_role("checkbox")
    selected.check()
    page.go_back()
    expect(page.get_by_text("待办-0", exact=True)).to_be_visible()
    page.go_forward()
    expect(selected).not_to_be_checked()


def overview_errors(page, base, fixtures):
    fixtures.counts["findings"][ASSETS[0]] = 0
    for path, target in [("/api/findings", "/findings"), ("/api/assets", "/assets"), ("/api/approvals", "/approvals")]:
        fixtures.failed = {path}
        with page.expect_response(lambda response: urlparse(response.url).path == path and response.status == 500):
            page.goto(f"{base}/overview")
        count = page.locator(f'.action-row[href="{target}"] .action-count')
        expect(count).to_have_text("-")
        expect(page.get_by_text("全部处理完毕", exact=True)).to_have_count(0)
        fixtures.failed.clear()
        with page.expect_response(lambda response: urlparse(response.url).path == path and response.status == 200):
            reconnect(page)
        expect(count).to_have_text("0")
        expect(page.get_by_text("全部处理完毕", exact=True)).to_be_visible()
        fixtures.failed.add(path)
        with page.expect_response(lambda response: urlparse(response.url).path == path and response.status == 500):
            reconnect(page)
        expect(count).to_have_text("-")
        expect(page.get_by_text("全部处理完毕", exact=True)).to_have_count(0)


def subject_errors(page, base, fixtures):
    for path, title in [(f"/api/incidents/{row_id(0)}", "事件-0"), ("/api/findings", "待办-500")]:
        fixtures.failed = {path}
        page.goto(f"{base}/chat/{SESSION}")
        subjects = page.locator(".subjects-bar")
        expect(subjects.get_by_text("加载失败", exact=True)).to_be_visible()
        fixtures.failed.clear()
        subjects.get_by_role("button", name="重试", exact=True).click()
        expect(subjects.get_by_text(title, exact=True)).to_be_visible()
        expect(subjects.get_by_text("加载失败", exact=True)).to_have_count(0)
    fixtures.counts["findings"][ASSETS[0]] = 501
    subjects.get_by_role("link", name="待办-500", exact=True).click()
    expect(page.get_by_text("仅显示引用的待办", exact=True)).to_be_visible()
    check(parse_qs(urlparse(page.url).query)["ids"] == [row_id(500)], f"未定位引用的待办: {page.url}")
    expect(page.get_by_text("待办-500", exact=True)).to_be_visible()
    expect(page.get_by_text("待办-0", exact=True)).to_have_count(0)


def finding_actions(page, base, fixtures):
    title = "未采集 Windows 登录审计事件，登录失败及异常登录无法排查；需要核对采集配置与最近一次运行结果"
    fixtures.overrides["findings", 0] = {"title": title}
    fixtures.assets[0]["hostname"] = "OPENXDR-TESTWIN-LONG-HOSTNAME-" * 3
    page.goto(f"{base}/findings")
    row = page.get_by_role("row").filter(has=page.get_by_text(title, exact=True))
    expect(row).to_be_visible()
    session_link = row.get_by_role("link", name="查看会话", exact=True)
    tops = session_link.evaluate("""element => {
        const range = document.createRange();
        range.selectNodeContents(element);
        return [...range.getClientRects()].filter(r => r.width > 0).map(r => r.top);
    }""")
    check(tops and max(tops) - min(tops) < 1, "查看会话文字被拆成多行")
    boxes = row.locator(".table-actions > *").evaluate_all("elements => elements.map(e => { const r = e.getBoundingClientRect(); return [r.left, r.top, r.right, r.bottom] })")
    for i, a in enumerate(boxes):
        for b in boxes[i + 1:]:
            overlap = min(a[2], b[2]) - max(a[0], b[0]) > 1 and min(a[3], b[3]) - max(a[1], b[1]) > 1
            check(not overlap, "待办操作控件相互重叠")
    page.locator(".ant-table-content").evaluate("element => { element.scrollLeft = element.scrollWidth }")
    row.get_by_role("button", name="已处理", exact=True).click()
    dialog = page.get_by_role("dialog")
    expect(dialog).to_be_visible()
    dialog.get_by_role("button", name="取消", exact=True).click()
    expect(dialog).not_to_be_visible()
    check(page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "待办表格导致整页横向溢出")
    session_link.click()
    expect(page).to_have_url(f"{base}/chat/{SESSION}")


def route_recovery(page, base, fixtures):
    fixtures.overrides["findings", 0] = {"status": "offline-broken-status"}
    page.goto(f"{base}/findings?status=all")
    expect(page.get_by_text("页面暂时无法显示", exact=True)).to_be_visible()
    expect(page.locator(".app-search")).to_be_visible()
    expect(page.get_by_text("Unexpected Application Error!", exact=True)).to_have_count(0)
    expect(page.locator("pre")).to_have_count(0)
    fixtures.overrides.clear()
    page.get_by_role("button", name="重新加载页面", exact=True).click()
    expect(page.get_by_text("待办-0", exact=True)).to_be_visible()
    fixtures.overrides["findings", 0] = {"status": "offline-broken-status"}
    page.reload()
    expect(page.get_by_text("页面暂时无法显示", exact=True)).to_be_visible()
    page.get_by_role("link", name="回到首页", exact=True).click()
    expect(page).to_have_url(f"{base}/chat")
    expect(page.get_by_text("页面暂时无法显示", exact=True)).to_have_count(0)
    page.evaluate("localStorage.setItem('locale', 'en')")
    page.goto(f"{base}/findings?status=all")
    expect(page.get_by_text("This page could not be displayed", exact=True)).to_be_visible()
    fixtures.overrides.clear()
    page.get_by_role("button", name="Reload page", exact=True).click()
    expect(page.get_by_text("待办-0", exact=True)).to_be_visible()
    chunk = "**/assets/OverviewPage-*.js"
    # 缺失脚本既可能返回 404，也可能被 SPA 回退规则替换成 200 HTML。
    for status in [404, 200]:
        page.route(chunk, lambda route: route.fulfill(status=status, content_type="text/html", body="<html>offline missing chunk</html>"))
        page.goto(f"{base}/overview")
        expect(page.get_by_text("This page could not be displayed", exact=True)).to_be_visible()
        page.unroute(chunk)
        page.get_by_role("button", name="Reload page", exact=True).click()
        expect(page.locator('.action-row[href="/findings"]')).to_be_visible()


def intel_settings(page, base, fixtures):
    view = dict(baseUrl="https://llm.example.test/v1", model="offline", piModel="offline", ptr=True,
                vtAlertMin=3, apiKeySet=False, vtKeySet=False, abuseCHKeySet=False, canSaveSecrets=True,
                source={key: "env" for key in ["baseUrl", "model", "piModel", "ptr", "vtAlertMin", "apiKey", "vtKey", "abuseCHKey"]})
    patches = []

    def settings(route):
        check(route.request.method in ["GET", "PUT"], "未定义的情报设置操作")
        if route.request.method == "PUT":
            patch = route.request.post_data_json
            check(set(patch) <= {"abuseCHKey", "reset"}, f"提交了无关设置字段: {patch}")
            patches.append(patch)
            if "abuseCHKey" in patch:
                key = patch["abuseCHKey"]
                view.update(abuseCHKeySet=bool(key), abuseCHKeyHint=key[-4:] if key else "")
                view["source"]["abuseCHKey"] = "console"
            if patch.get("reset") == ["abuseCHKey"]:
                view.update(abuseCHKeySet=True, abuseCHKeyHint="0000")
                view["source"]["abuseCHKey"] = "env"
        route.fulfill(status=200, content_type="application/json", body=json.dumps(view))

    page.route(f"{base}/api/settings/ai", settings)
    page.goto(f"{base}/settings?tab=intel")
    field = page.get_by_label("abuse.ch Auth-Key", exact=True)
    expect(field).to_have_attribute("type", "password")
    field.fill("offline-fake-key-1234")
    save = page.get_by_role("button", name="保存", exact=True)
    with page.expect_response(lambda response: response.request.method == "PUT"):
        save.click()
    expect(field).to_have_value("")
    expect(field).to_have_attribute("placeholder", re.compile("1234"))
    check(patches == [{"abuseCHKey": "offline-fake-key-1234"}], patches)
    with page.expect_response(lambda response: response.request.method == "PUT"):
        save.click()
    check(patches[-1] == {}, "空白输入不应清空已保存的密钥")
    page.get_by_role("button", name="清空", exact=True).click()
    expect(field).not_to_have_attribute("placeholder", re.compile("1234"))
    check(patches[-1] == {"abuseCHKey": ""}, patches)
    page.get_by_role("button", name="恢复默认", exact=True).click()
    dialog = page.get_by_role("dialog")
    dialog.get_by_role("button", name="确定", exact=True).click()
    expect(dialog).not_to_be_visible()
    expect(field).to_have_attribute("placeholder", re.compile("0000"))
    check(patches[-1] == {"reset": ["abuseCHKey"]}, patches)


def intel_errors(page, base, fixtures):
    state = dict(failed=True, enabled=True, save_failed=False)
    writes = []

    def feeds(route):
        check(route.request.method in ["GET", "PUT"], "未定义的情报订阅操作")
        if route.request.method == "PUT":
            patch = route.request.post_data_json
            check(set(patch) == {"enabled"}, patch)
            writes.append(patch)
        if state["failed"]:
            route.fulfill(status=500, content_type="text/plain", body="离线配置读取失败")
            return
        if route.request.method == "PUT":
            state["enabled"] = "threatfox" in patch["enabled"]
            if state["save_failed"]:
                route.fulfill(status=500, content_type="text/plain", body="离线模拟：配置已保存，但同步失败")
                return
        body = dict(intervalHours=6, hits=[], feeds=[dict(id="threatfox", name="ThreatFox", severity=4,
                    count=0, hits=0, enabled=state["enabled"], syncedAt=None, attemptedAt=fixtures.now,
                    error="请配置 abuse.ch Auth-Key")])
        route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

    page.route(f"{base}/api/intel/feeds", feeds)
    page.goto(f"{base}/intel")
    expect(page.get_by_text("加载失败", exact=True)).to_be_visible()
    sync = page.get_by_role("button", name=re.compile("立即同步"))
    expect(sync).to_be_disabled()
    expect(page.get_by_text("manual.example.test", exact=True)).to_be_visible()
    expect(page.get_by_role("switch")).to_have_count(0)
    check(not writes, "读取失败不能自动写入开关配置")
    state["failed"] = False
    page.get_by_role("button", name="重试", exact=True).click()
    expect(sync).to_be_enabled()
    expect(page.get_by_text("暂无成功同步记录", exact=True)).to_be_visible()
    expect(page.get_by_text(re.compile("最近尝试"))).to_be_visible()
    switch = page.get_by_role("switch", name="ThreatFox", exact=True)
    expect(switch).to_be_checked()
    switch.click()
    expect(switch).not_to_be_checked()
    check(writes == [{"enabled": []}], writes)
    state["save_failed"] = True
    switch.click()
    expect(switch).to_be_checked()
    check(writes == [{"enabled": []}, {"enabled": ["threatfox"]}], writes)
    expect(switch).to_be_enabled()


def main():
    scenarios = {fn.__name__: fn for fn in [asset_navigation, asset_pagination, asset_errors, queue_pagination, overview_errors, subject_errors, finding_actions, route_recovery, intel_settings, intel_errors]}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=ROOT / "web/dist")
    parser.add_argument("--output", type=Path, default=Path(gettempdir()) / "openxdr-web-smoke")
    parser.add_argument("--theme", choices=["light", "dark"], default="light", help="测试主题，默认 light")
    parser.add_argument("--scenario", choices=scenarios, action="append", help="仅运行指定场景，可重复传入")
    args = parser.parse_args()
    selected = [scenarios[name] for name in args.scenario] if args.scenario else list(scenarios.values())
    if not (args.dist / "index.html").is_file():
        parser.error("缺少 web/dist/index.html，请先执行 npm --prefix web run build")
    args.output.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(StaticHandler, directory=str(args.dist.resolve())))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    results = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            for width in [1440, 390]:
                for scenario in selected:
                    fixtures, errors = Fixtures(), []
                    context = browser.new_context(viewport={"width": width, "height": 950}, service_workers="block")
                    context.add_init_script(f"localStorage.setItem('theme', {json.dumps(args.theme)});")
                    context.add_init_script("localStorage.setItem('tourDone','1');if (!localStorage.getItem('locale')) localStorage.setItem('locale','zh');")
                    context.route("**/*", fixtures.route)
                    page = context.new_page()
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    result = dict(scenario=scenario.__name__, width=width, theme=args.theme, passed=False)
                    try:
                        scenario(page, f"http://127.0.0.1:{server.server_port}", fixtures)
                        expect(page.locator("html")).to_have_attribute("data-theme", args.theme)
                        check(not fixtures.unexpected, fixtures.unexpected)
                        check(not errors, errors)
                        check(page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "页面横向溢出")
                        result["passed"] = True
                    except Exception:
                        result["error"] = traceback.format_exc()
                        page.screenshot(path=str(args.output / f"{scenario.__name__}-{width}.png"), full_page=True)
                    finally:
                        result["unexpected"] = fixtures.unexpected
                        result["pageErrors"] = errors
                        results.append(result)
                        context.close()
                    print(json.dumps(result, ensure_ascii=False), flush=True)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        (args.output / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if len(results) == len(selected) * 2 and all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
