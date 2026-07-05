"""Condor CLI — entry point."""
from __future__ import annotations

import asyncio
import datetime
import json
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .core.models import Severity, ScanResult
from .platforms.flowise import FlowisePlatform
from .platforms.generic import GenericPlatform
from .platforms.langflow import LangflowPlatform
from .platforms.dify import DifyPlatform
from .platforms.autogen import AutoGenPlatform
from .platforms.n8n import N8nPlatform
from .platforms.llamaindex import LlamaIndexPlatform
from .platforms.crewai import CrewAIPlatform
from .platforms.langgraph import LangGraphPlatform
from .platforms.ollama import OllamaPlatform
from .platforms.openai_compat import OpenAICompatPlatform
from .platforms.openwebui import OpenWebUIPlatform
from .platforms.hayhooks import HayhooksPlatform
from .platforms.letta import LettaPlatform
from .platforms.qdrant import QdrantPlatform
from .platforms.chroma import ChromaPlatform
from .modules.asi01_goal_hijack import GoalHijackModule
from .modules.asi02_tool_misuse import ToolMisuseModule
from .modules.asi03_privilege import PrivilegeAbuseModule
from .modules.asi04_supply_chain import SupplyChainModule
from .modules.asi05_code_exec import CodeExecutionModule
from .modules.asi06_memory_poisoning import MemoryPoisoningModule
from .modules.asi07_inter_agent import InterAgentModule
from .modules.asi08_cascading import CascadingFailuresModule
from .modules.asi09_trust import TrustExploitationModule
from .modules.asi10_rogue import RogueAgentsModule

app     = typer.Typer(name="condor", help="Agentic AI security testing framework (OWASP ASI Top 10)", add_completion=False)
console = Console()


def _load_plugins() -> None:
    """Discover and register third-party modules/platforms via entry_points."""
    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group="condor.modules"):
            try:
                _ALL_MODULES[ep.name] = ep.load()
            except Exception:
                pass
        for ep in entry_points(group="condor.platforms"):
            try:
                _PLATFORMS[ep.name] = ep.load()
            except Exception:
                pass
    except Exception:
        pass

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}

_ALL_MODULES = {
    "goal-hijack":      GoalHijackModule,
    "tool-misuse":      ToolMisuseModule,
    "privilege-abuse":  PrivilegeAbuseModule,
    "supply-chain":     SupplyChainModule,
    "code-execution":   CodeExecutionModule,
    "memory-poisoning":    MemoryPoisoningModule,
    "inter-agent":         InterAgentModule,
    "cascading-failures":  CascadingFailuresModule,
    "trust-exploitation":  TrustExploitationModule,
    "rogue-agents":        RogueAgentsModule,
}

_PLATFORMS = {
    "flowise":       FlowisePlatform,
    "generic":       GenericPlatform,
    "langflow":      LangflowPlatform,
    "dify":          DifyPlatform,
    "autogen":       AutoGenPlatform,
    "n8n":           N8nPlatform,
    "llamaindex":    LlamaIndexPlatform,
    "crewai":        CrewAIPlatform,
    "langgraph":     LangGraphPlatform,
    "ollama":        OllamaPlatform,
    "openai-compat": OpenAICompatPlatform,
    "openwebui":     OpenWebUIPlatform,
    "hayhooks":      HayhooksPlatform,
    "letta":         LettaPlatform,
    "qdrant":        QdrantPlatform,
    "chroma":        ChromaPlatform,
}

_VALID_FORMATS = ("json", "sarif", "both", "table", "html", "junit")


@app.command()
def scan(
    url: Annotated[Optional[str], typer.Option("--url", "-u", help="Base URL of the agentic platform")] = None,
    platform: Annotated[str, typer.Option("--platform", "-p", help="Platform: flowise | generic | langflow | dify | autogen")] = "generic",
    module: Annotated[Optional[str], typer.Option("--module", "-m", help="all | <module-name>")] = None,
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    timeout: Annotated[int, typer.Option("--timeout")] = 30,
    fail_on: Annotated[Optional[str], typer.Option("--fail-on", help="Exit 1 if findings at this severity or above")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="Output format: json | sarif | both | table")] = "json",
    targets: Annotated[Optional[Path], typer.Option("--targets", "-t", help="File with one URL [platform] per line")] = None,
    exclude_module: Annotated[Optional[List[str]], typer.Option("--exclude-module", "-x", help="Skip a module (repeatable)")] = None,
    concurrency: Annotated[int, typer.Option("--concurrency", help="Max parallel targets in batch scan")] = 5,
    api_key: Annotated[Optional[str], typer.Option("--api-key", "-k", help="API key for authenticated instances", envvar="CONDOR_API_KEY")] = None,
    username: Annotated[Optional[str], typer.Option("--username", help="Username for basic/login auth", envvar="CONDOR_USERNAME")] = None,
    password: Annotated[Optional[str], typer.Option("--password", help="Password for basic/login auth", envvar="CONDOR_PASSWORD")] = None,
    proxy: Annotated[Optional[str], typer.Option("--proxy", help="HTTP/S proxy URL (e.g. http://127.0.0.1:8080)", envvar="CONDOR_PROXY")] = None,
    insecure: Annotated[bool, typer.Option("--insecure", help="Skip TLS certificate verification")] = False,
    stdout: Annotated[bool, typer.Option("--stdout", help="Emit JSON to stdout (suppresses progress bar and summary)")] = False,
    min_severity: Annotated[Optional[str], typer.Option("--min-severity", help="Only show findings at this severity or above")] = None,
    baseline: Annotated[Optional[Path], typer.Option("--baseline", help="Baseline file to suppress known findings")] = None,
    save_baseline: Annotated[Optional[Path], typer.Option("--save-baseline", help="Save findings as new baseline file")] = None,
    config: Annotated[Optional[Path], typer.Option("--config", "-c", help="Path to condor.yaml config file")] = None,
    notify_slack_url:   Annotated[Optional[str], typer.Option("--notify-slack",   help="Slack webhook URL",         envvar="CONDOR_NOTIFY_SLACK")]   = None,
    notify_teams_url:   Annotated[Optional[str], typer.Option("--notify-teams",   help="Teams webhook URL",         envvar="CONDOR_NOTIFY_TEAMS")]   = None,
    defectdojo_url:     Annotated[Optional[str], typer.Option("--defectdojo-url",  help="DefectDojo base URL",      envvar="CONDOR_DEFECTDOJO_URL")]  = None,
    defectdojo_key:     Annotated[Optional[str], typer.Option("--defectdojo-key",  help="DefectDojo API token",     envvar="CONDOR_DEFECTDOJO_KEY")]  = None,
    defectdojo_product: Annotated[Optional[str], typer.Option("--defectdojo-product", help="DefectDojo product name")] = None,
) -> None:
    """Scan an agentic AI platform for security vulnerabilities."""
    _load_plugins()

    from .config import load_config, apply_config_defaults
    cfg = load_config(config)
    opts = apply_config_defaults(
        cfg,
        platform=platform if platform != "generic" else None,
        module=module,
        timeout=timeout if timeout != 30 else None,
        fail_on=fail_on,
        fmt=fmt if fmt != "json" else None,
        api_key=api_key,
        username=username,
        password=password,
        proxy=proxy,
        min_severity=min_severity,
    )
    platform   = opts.get("platform") or platform
    module     = opts.get("module") or module
    timeout    = opts.get("timeout") or timeout
    fail_on    = opts.get("fail_on") or fail_on
    fmt        = opts.get("fmt") or fmt
    api_key    = opts.get("api_key") or api_key
    username   = opts.get("username") or username
    password   = opts.get("password") or password
    proxy      = opts.get("proxy") or proxy
    min_severity = opts.get("min_severity") or min_severity

    if url and targets:
        console.print("[red]--url and --targets are mutually exclusive[/red]")
        raise typer.Exit(2)
    if not url and not targets:
        console.print("[red]Provide --url <URL> or --targets <file>[/red]")
        raise typer.Exit(2)
    if fmt not in _VALID_FORMATS:
        console.print(f"[red]Invalid --format '{fmt}'. Choose from: {', '.join(_VALID_FORMATS)}[/red]")
        raise typer.Exit(2)
    if min_severity and min_severity not in [s.value for s in Severity]:
        console.print(f"[red]Invalid --min-severity '{min_severity}'. Choose from: critical, high, medium, low, info[/red]")
        raise typer.Exit(2)
    if targets:
        asyncio.run(_scan_batch(targets, platform, module, output_dir, timeout, fail_on, fmt, exclude_module, concurrency, api_key, username, password, proxy, not insecure, stdout_mode=stdout, min_severity=min_severity, baseline_path=baseline, save_baseline_path=save_baseline, notify_slack_url=notify_slack_url, notify_teams_url=notify_teams_url, defectdojo_url=defectdojo_url, defectdojo_key=defectdojo_key, defectdojo_product=defectdojo_product))
    else:
        asyncio.run(_scan(url, platform, module, output_dir, timeout, fail_on, fmt, exclude_module, api_key=api_key, username=username, password=password, proxy=proxy, verify_ssl=not insecure, stdout_mode=stdout, min_severity=min_severity, baseline_path=baseline, save_baseline_path=save_baseline, notify_slack_url=notify_slack_url, notify_teams_url=notify_teams_url, defectdojo_url=defectdojo_url, defectdojo_key=defectdojo_key, defectdojo_product=defectdojo_product))


def _dedup_findings(findings: list) -> list:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.owasp_id, f.title, f.endpoint)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


async def _scan(
    url: str,
    platform_name: str,
    module_filter: str | None,
    output_dir: Path | None,
    timeout: int,
    fail_on: str | None,
    fmt: str,
    exclude_module: list[str] | None = None,
    verbose: bool = True,
    *,
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    proxy: str | None = None,
    verify_ssl: bool = True,
    stdout_mode: bool = False,
    min_severity: str | None = None,
    baseline_path: Path | None = None,
    save_baseline_path: Path | None = None,
    notify_slack_url: str | None = None,
    notify_teams_url: str | None = None,
    defectdojo_url: str | None = None,
    defectdojo_key: str | None = None,
    defectdojo_product: str | None = None,
) -> None:
    platform_cls = _PLATFORMS.get(platform_name)
    if not platform_cls:
        console.print(f"[red]Unknown platform: {platform_name}. Available: {', '.join(_PLATFORMS)}[/red]")
        raise typer.Exit(2)

    if output_dir is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path("condor-sessions") / f"scan-{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Resolve modules
    if module_filter is None or module_filter == "all":
        active = list(_ALL_MODULES.items())
    elif module_filter in _ALL_MODULES:
        active = [(module_filter, _ALL_MODULES[module_filter])]
    else:
        console.print(f"[red]Unknown module: {module_filter}. Available: {', '.join(_ALL_MODULES)}[/red]")
        raise typer.Exit(2)

    # Apply exclusions
    if exclude_module:
        unknown = [x for x in exclude_module if x not in _ALL_MODULES]
        if unknown:
            console.print(f"[yellow]Warning: unknown module(s) in --exclude-module: {', '.join(unknown)}[/yellow]")
        active = [(n, cls) for n, cls in active if n not in exclude_module]

    show_ui = verbose and not stdout_mode
    if show_ui:
        console.print(f"\n[bold cyan]Condor v{__version__}[/bold cyan]  Agentic AI Security Scanner")
        console.print(f"Target   : {url}")
        console.print(f"Platform : {platform_name}")
        console.print(f"Modules  : {', '.join(n for n, _ in active)}")
        console.print()

    plat = platform_cls(url, timeout=timeout, api_key=api_key, username=username, password=password, proxy=proxy, verify_ssl=verify_ssl)
    modules_run = []
    started_at = datetime.datetime.now(datetime.timezone.utc)

    async with plat:
        if not await plat.health_check():
            console.print(f"[red]Platform not reachable at {url}[/red]")
            raise typer.Exit(2)

        if show_ui:
            console.print("[bold]Enumerating surface...[/bold]")
        surface = await plat.enumerate()
        if show_ui:
            console.print(f"  Flows    : {len(surface.flows)}")
            console.print(f"  Tools    : {len(surface.tools)}")
            console.print(f"  Auth     : {'required' if surface.auth_required else '[yellow]not required[/yellow]'}")
            if surface.version:
                console.print(f"  Version  : {surface.version}")
            console.print()

        all_findings: list = []
        modules_run = [n for n, _ in active]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=stdout_mode,
            disable=stdout_mode,
        ) as progress:
            prog_task = progress.add_task("Scanning...", total=len(active))

            async def _run_one(name: str, mod_cls) -> list:
                mod = mod_cls()
                results = await mod.run(surface, plat)
                progress.advance(prog_task)
                if show_ui and results:
                    for f in results:
                        color = _SEV_COLOR.get(f.severity.value, "white")
                        progress.console.print(
                            f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title} [dim]({f.confidence}%)[/dim]"
                        )
                return results

            gathered = await asyncio.gather(*[_run_one(n, cls) for n, cls in active])
            for batch in gathered:
                all_findings.extend(batch)

    findings = _dedup_findings(all_findings)

    from .remediation import enrich_findings
    findings = enrich_findings(findings, platform_name)

    # Apply baseline suppression
    if baseline_path:
        from .baseline import load_baseline, apply_baseline
        bl = load_baseline(baseline_path)
        result_pre = ScanResult(target=url, platform=platform_name, findings=findings, modules_run=modules_run, surface=surface)
        result_post = apply_baseline(result_pre, bl)
        findings = result_post.findings
        suppressed = result_post.surface.raw_info.get("suppressed_count", 0) if result_post.surface else 0
        if show_ui and suppressed:
            console.print(f"[dim]Suppressed {suppressed} baseline finding(s)[/dim]")

    finished_at = datetime.datetime.now(datetime.timezone.utc)
    result = ScanResult(
        target=url,
        platform=platform_name,
        findings=findings,
        modules_run=modules_run,
        surface=surface,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=(finished_at - started_at).total_seconds(),
    )

    # Notifications and integrations (run after result is assembled, before filtering)
    if notify_slack_url:
        try:
            from .integrations.notify import notify_slack
            await notify_slack(notify_slack_url, result)
        except Exception as exc:
            if show_ui:
                console.print(f"[yellow]Slack notification failed: {exc}[/yellow]")
    if notify_teams_url:
        try:
            from .integrations.notify import notify_teams
            await notify_teams(notify_teams_url, result)
        except Exception as exc:
            if show_ui:
                console.print(f"[yellow]Teams notification failed: {exc}[/yellow]")
    if defectdojo_url and defectdojo_key and defectdojo_product:
        try:
            from .integrations.defectdojo import export_to_defectdojo
            await export_to_defectdojo(result, defectdojo_url, defectdojo_key, defectdojo_product)
            if show_ui:
                console.print(f"[green]DefectDojo export complete: {defectdojo_product}[/green]")
        except Exception as exc:
            if show_ui:
                console.print(f"[yellow]DefectDojo export failed: {exc}[/yellow]")

    # Save baseline if requested
    if save_baseline_path:
        from .baseline import save_baseline
        save_baseline(result, save_baseline_path)
        if show_ui:
            console.print(f"[green]Baseline saved: {save_baseline_path}[/green]")

    # Apply min-severity filter for display/output
    displayed = result
    if min_severity:
        sev_obj = Severity(min_severity)
        tidx = _SEVERITY_ORDER.index(sev_obj)
        filtered = [f for f in findings if _SEVERITY_ORDER.index(f.severity) <= tidx]
        displayed = ScanResult(target=url, platform=platform_name, findings=filtered, modules_run=modules_run, surface=surface,
                               started_at=started_at, finished_at=finished_at, duration_seconds=result.duration_seconds)

    # Write outputs
    report_path = output_dir / "report.json"
    sarif_path  = output_dir / "report.sarif"
    html_path   = output_dir / "report.html"
    junit_path  = output_dir / "report.xml"

    if stdout_mode:
        import sys
        sys.stdout.write(displayed.model_dump_json(indent=2))
        sys.stdout.write("\n")
        sys.stdout.flush()
    else:
        if fmt in ("json", "both"):
            report_path.write_text(displayed.model_dump_json(indent=2), encoding="utf-8")
        if fmt in ("sarif", "both"):
            from .sarif import to_sarif
            sarif_path.write_text(json.dumps(to_sarif(displayed, __version__), indent=2), encoding="utf-8")
        if fmt == "html":
            from .html_report import to_html
            html_path.write_text(to_html(displayed, __version__), encoding="utf-8")
        if fmt == "junit":
            from .junit_report import to_junit
            junit_path.write_text(to_junit(displayed), encoding="utf-8")

        if show_ui:
            _print_summary(displayed)
            if fmt in ("json", "both"):
                console.print(f"Report : {report_path}")
            if fmt in ("sarif", "both"):
                console.print(f"SARIF  : {sarif_path}")
            if fmt == "html":
                console.print(f"HTML   : {html_path}")
            if fmt == "junit":
                console.print(f"JUnit  : {junit_path}")

    if fail_on:
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Invalid severity: {fail_on}[/red]")
            raise typer.Exit(2)
        tidx = _SEVERITY_ORDER.index(threshold)
        if any(_SEVERITY_ORDER.index(f.severity) <= tidx for f in findings):
            raise typer.Exit(1)


def _parse_targets_file(path: Path) -> list[tuple[str, str]]:
    """Parse a targets file. Each line: URL [platform]. Lines starting with # are ignored."""
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        url_part = parts[0]
        plat_part = parts[1] if len(parts) > 1 else "generic"
        targets.append((url_part, plat_part))
    return targets


async def _scan_batch(
    targets_file: Path,
    default_platform: str,
    module_filter: str | None,
    output_dir: Path | None,
    timeout: int,
    fail_on: str | None,
    fmt: str,
    exclude_module: list[str] | None,
    concurrency: int,
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    proxy: str | None = None,
    verify_ssl: bool = True,
    *,
    stdout_mode: bool = False,
    min_severity: str | None = None,
    baseline_path: Path | None = None,
    save_baseline_path: Path | None = None,
    notify_slack_url: str | None = None,
    notify_teams_url: str | None = None,
    defectdojo_url: str | None = None,
    defectdojo_key: str | None = None,
    defectdojo_product: str | None = None,
) -> None:
    try:
        targets = _parse_targets_file(targets_file)
    except Exception as e:
        console.print(f"[red]Could not read targets file: {e}[/red]")
        raise typer.Exit(1)

    if not targets:
        console.print("[red]No targets found in file[/red]")
        raise typer.Exit(1)

    if output_dir is None:
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = Path("condor-sessions") / f"batch-{ts}"

    console.print(f"\n[bold cyan]Condor v{__version__}[/bold cyan]  Batch scan — {len(targets)} target(s)  (concurrency={concurrency})")
    console.print()

    sem = asyncio.Semaphore(concurrency)

    def _safe(u: str) -> str:
        return u.replace("://", "_").replace("/", "_").replace(":", "_").strip("_")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        batch_task = progress.add_task("Batch scan", total=len(targets))

        async def bounded(url: str, plat_name: str, target_dir: Path) -> bool:
            async with sem:
                try:
                    await _scan(url, plat_name, module_filter, target_dir, timeout, fail_on, fmt, exclude_module, verbose=False, api_key=api_key, username=username, password=password, proxy=proxy, verify_ssl=verify_ssl, stdout_mode=False, min_severity=min_severity, baseline_path=baseline_path, save_baseline_path=None, notify_slack_url=notify_slack_url, notify_teams_url=notify_teams_url, defectdojo_url=defectdojo_url, defectdojo_key=defectdojo_key, defectdojo_product=defectdojo_product)
                    progress.console.print(f"  [green]✓[/green] {url}")
                    return True
                except SystemExit as exc:
                    progress.console.print(f"  [red]✗[/red] {url}")
                    return exc.code in (0, None)
                finally:
                    progress.advance(batch_task)

        tasks = [
            bounded(url, plat_name, output_dir / _safe(url))
            for url, plat_name in targets
        ]
        results = await asyncio.gather(*tasks)

    if not all(results):
        raise typer.Exit(1)


def _print_summary(result: ScanResult) -> None:
    table = Table(title="Summary", show_header=True)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, count in result.finding_count.items():
        color = _SEV_COLOR.get(sev, "white")
        table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))
    if not result.findings:
        table.add_row("[green]No findings[/green]", "0")
    console.print(table)


@app.command("list-modules")
def list_modules() -> None:
    """List available scan modules."""
    table = Table(title="Modules")
    table.add_column("Name")
    table.add_column("OWASP")
    table.add_column("Description")
    for name, cls in _ALL_MODULES.items():
        m = cls()
        table.add_row(name, m.owasp_id.value, m.description)
    console.print(table)


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"condor {__version__}")


_SCAFFOLD_MODULE_TEMPLATE = '''\
"""ASI{nn} — {title}: <one-line description>."""
from __future__ import annotations

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform


class {class_name}(BaseModule):
    name        = "{slug}"
    owasp_id    = OWASPCategory.ASI{nn}
    description = "<short description> (ASI{nn})"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        # TODO: implement detection logic
        return findings
'''

_SCAFFOLD_TEST_TEMPLATE = '''\
"""Tests for ASI{nn} — {slug} module."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.modules.asi{nn}_{slug} import {class_name}
from condor.core.models import AgentSurface, OWASPCategory, Severity


def _mock_response(status: int = 200, json_data=None, text: str = "", headers=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data if json_data is not None else {{}}
    r.text = text
    r.content = text.encode()
    r.headers = headers or {{"content-type": "application/json"}}
    return r


@pytest.fixture
def surface():
    return AgentSurface(platform="generic", base_url="http://localhost:8080")


@pytest.fixture
def plat():
    p = MagicMock()
    p.base_url = "http://localhost:8080"
    p.get = AsyncMock(return_value=_mock_response(404))
    p.post = AsyncMock(return_value=_mock_response(404))
    return p


@pytest.mark.asyncio
async def test_{slug_under}_no_findings(surface, plat):
    mod = {class_name}()
    assert mod.owasp_id == OWASPCategory.ASI{nn}
    findings = await mod.run(surface, plat)
    assert isinstance(findings, list)
'''


@app.command()
def scaffold(
    name: Annotated[str, typer.Option("--name", "-n", help="Module slug (e.g. my-custom-check)")],
    asi: Annotated[str, typer.Option("--asi", "-a", help="ASI number (e.g. 01)")] = "01",
) -> None:
    """Generate boilerplate for a new ASI module."""
    import re

    if not re.match(r"^[a-z][a-z0-9_-]*$", name):
        console.print("[red]--name must be lowercase alphanumeric, hyphens, or underscores[/red]")
        raise typer.Exit(1)

    nn = asi.zfill(2)
    slug = name
    slug_under = name.replace("-", "_")
    class_name = "".join(w.capitalize() for w in name.replace("-", "_").split("_")) + "Module"
    title = name.replace("-", " ").replace("_", " ").title()

    here = Path(__file__).parent
    mod_path = here / "modules" / f"asi{nn}_{slug_under}.py"
    test_path = here.parent / "tests" / f"test_asi{nn}_{slug_under}.py"

    if mod_path.exists():
        console.print(f"[red]Module already exists: {mod_path}[/red]")
        raise typer.Exit(1)
    if test_path.exists():
        console.print(f"[red]Test file already exists: {test_path}[/red]")
        raise typer.Exit(1)

    mod_path.write_text(
        _SCAFFOLD_MODULE_TEMPLATE.format(nn=nn, title=title, slug=slug, slug_under=slug_under, class_name=class_name),
        encoding="utf-8",
    )
    test_path.write_text(
        _SCAFFOLD_TEST_TEMPLATE.format(nn=nn, slug=slug, slug_under=slug_under, class_name=class_name),
        encoding="utf-8",
    )

    console.print(f"[green]Module :[/green] {mod_path}")
    console.print(f"[green]Tests  :[/green] {test_path}")
    console.print(f"\n[yellow]Register in cli.py → _ALL_MODULES:[/yellow]")
    console.print(f'    "{slug}": {class_name},  # from .modules.asi{nn}_{slug_under}')
