"""Condor CLI — entry point."""
from __future__ import annotations

import asyncio
import datetime
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .core.models import Severity, ScanResult
from .platforms.flowise import FlowisePlatform
from .platforms.generic import GenericPlatform
from .platforms.langflow import LangflowPlatform
from .platforms.dify import DifyPlatform
from .platforms.autogen import AutoGenPlatform
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
    "flowise":  FlowisePlatform,
    "generic":  GenericPlatform,
    "langflow": LangflowPlatform,
    "dify":     DifyPlatform,
    "autogen":  AutoGenPlatform,
}


@app.command()
def scan(
    url: Annotated[Optional[str], typer.Option("--url", "-u", help="Base URL of the agentic platform")] = None,
    platform: Annotated[str, typer.Option("--platform", "-p", help="Platform: flowise | generic")] = "generic",
    module: Annotated[Optional[str], typer.Option("--module", "-m", help="all | <module-name>")] = None,
    output_dir: Annotated[Optional[Path], typer.Option("--output-dir", "-o")] = None,
    timeout: Annotated[int, typer.Option("--timeout")] = 30,
    fail_on: Annotated[Optional[str], typer.Option("--fail-on", help="Exit 1 if findings at this severity or above")] = None,
    sarif: Annotated[bool, typer.Option("--sarif")] = False,
    targets: Annotated[Optional[Path], typer.Option("--targets", "-t", help="File with one URL [platform] per line")] = None,
) -> None:
    """Scan an agentic AI platform for security vulnerabilities."""
    if url and targets:
        console.print("[red]--url and --targets are mutually exclusive[/red]")
        raise typer.Exit(1)
    if not url and not targets:
        console.print("[red]Provide --url <URL> or --targets <file>[/red]")
        raise typer.Exit(1)
    if targets:
        asyncio.run(_scan_batch(targets, platform, module, output_dir, timeout, fail_on, sarif))
    else:
        asyncio.run(_scan(url, platform, module, output_dir, timeout, fail_on, sarif))


async def _scan(
    url: str,
    platform_name: str,
    module_filter: str | None,
    output_dir: Path | None,
    timeout: int,
    fail_on: str | None,
    sarif: bool,
) -> None:
    platform_cls = _PLATFORMS.get(platform_name)
    if not platform_cls:
        console.print(f"[red]Unknown platform: {platform_name}. Available: {', '.join(_PLATFORMS)}[/red]")
        raise typer.Exit(1)

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
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]Condor v{__version__}[/bold cyan]  Agentic AI Security Scanner")
    console.print(f"Target   : {url}")
    console.print(f"Platform : {platform_name}")
    console.print(f"Modules  : {', '.join(n for n, _ in active)}")
    console.print()

    plat = platform_cls(url, timeout=timeout)
    findings = []
    modules_run = []

    async with plat:
        if not await plat.health_check():
            console.print(f"[red]Platform not reachable at {url}[/red]")
            raise typer.Exit(1)

        console.print("[bold]Enumerating surface...[/bold]")
        surface = await plat.enumerate()
        console.print(f"  Flows    : {len(surface.flows)}")
        console.print(f"  Tools    : {len(surface.tools)}")
        console.print(f"  Auth     : {'required' if surface.auth_required else '[yellow]not required[/yellow]'}")
        if surface.version:
            console.print(f"  Version  : {surface.version}")
        console.print()

        for name, mod_cls in active:
            mod = mod_cls()
            console.print(f"[bold yellow][{mod.owasp_id.value}][/bold yellow] {mod.description}")
            results = await mod.run(surface, plat)
            findings.extend(results)
            modules_run.append(name)
            if results:
                for f in results:
                    color = _SEV_COLOR.get(f.severity.value, "white")
                    console.print(f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title} [dim]({f.confidence}%)[/dim]")
            else:
                console.print("  [green]No findings[/green]")
            console.print()

    result = ScanResult(target=url, platform=platform_name, findings=findings, modules_run=modules_run, surface=surface)

    # Write report.json
    report_path = output_dir / "report.json"
    report_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    if sarif:
        from .sarif import to_sarif
        sarif_path = output_dir / "report.sarif"
        sarif_path.write_text(json.dumps(to_sarif(result, __version__), indent=2), encoding="utf-8")

    _print_summary(result)
    console.print(f"\nReport : {report_path}")
    if sarif:
        console.print(f"SARIF  : {output_dir / 'report.sarif'}")

    if fail_on:
        try:
            threshold = Severity(fail_on)
        except ValueError:
            console.print(f"[red]Invalid severity: {fail_on}[/red]")
            raise typer.Exit(1)
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
    sarif: bool,
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

    console.print(f"\n[bold cyan]Condor v{__version__}[/bold cyan]  Batch scan — {len(targets)} target(s)")
    console.print()

    had_failure = False
    for url, platform_name in targets:
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_").strip("_")
        target_dir = output_dir / safe_name
        try:
            await _scan(url, platform_name, module_filter, target_dir, timeout, fail_on, sarif)
        except SystemExit as exc:
            if exc.code not in (0, None):
                had_failure = True

    if had_failure:
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
