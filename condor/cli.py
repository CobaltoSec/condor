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
    "flowise":     FlowisePlatform,
    "generic":     GenericPlatform,
    "langflow":    LangflowPlatform,
    "dify":        DifyPlatform,
    "autogen":     AutoGenPlatform,
    "n8n":         N8nPlatform,
    "llamaindex":  LlamaIndexPlatform,
    "crewai":      CrewAIPlatform,
}

_VALID_FORMATS = ("json", "sarif", "both", "table")


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
    api_key: Annotated[Optional[str], typer.Option("--api-key", "-k", help="API key for authenticated instances")] = None,
    username: Annotated[Optional[str], typer.Option("--username", help="Username for basic/login auth")] = None,
    password: Annotated[Optional[str], typer.Option("--password", help="Password for basic/login auth")] = None,
) -> None:
    """Scan an agentic AI platform for security vulnerabilities."""
    if url and targets:
        console.print("[red]--url and --targets are mutually exclusive[/red]")
        raise typer.Exit(1)
    if not url and not targets:
        console.print("[red]Provide --url <URL> or --targets <file>[/red]")
        raise typer.Exit(1)
    if fmt not in _VALID_FORMATS:
        console.print(f"[red]Invalid --format '{fmt}'. Choose from: {', '.join(_VALID_FORMATS)}[/red]")
        raise typer.Exit(1)
    if targets:
        asyncio.run(_scan_batch(targets, platform, module, output_dir, timeout, fail_on, fmt, exclude_module, concurrency, api_key, username, password))
    else:
        asyncio.run(_scan(url, platform, module, output_dir, timeout, fail_on, fmt, exclude_module, api_key=api_key, username=username, password=password))


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

    # Apply exclusions
    if exclude_module:
        unknown = [x for x in exclude_module if x not in _ALL_MODULES]
        if unknown:
            console.print(f"[yellow]Warning: unknown module(s) in --exclude-module: {', '.join(unknown)}[/yellow]")
        active = [(n, cls) for n, cls in active if n not in exclude_module]

    if verbose:
        console.print(f"\n[bold cyan]Condor v{__version__}[/bold cyan]  Agentic AI Security Scanner")
        console.print(f"Target   : {url}")
        console.print(f"Platform : {platform_name}")
        console.print(f"Modules  : {', '.join(n for n, _ in active)}")
        console.print()

    plat = platform_cls(url, timeout=timeout, api_key=api_key, username=username, password=password)
    findings = []
    modules_run = []

    async with plat:
        if not await plat.health_check():
            console.print(f"[red]Platform not reachable at {url}[/red]")
            raise typer.Exit(1)

        if verbose:
            console.print("[bold]Enumerating surface...[/bold]")
        surface = await plat.enumerate()
        if verbose:
            console.print(f"  Flows    : {len(surface.flows)}")
            console.print(f"  Tools    : {len(surface.tools)}")
            console.print(f"  Auth     : {'required' if surface.auth_required else '[yellow]not required[/yellow]'}")
            if surface.version:
                console.print(f"  Version  : {surface.version}")
            console.print()

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(active))
            for name, mod_cls in active:
                mod = mod_cls()
                progress.update(task, description=f"[bold yellow][{mod.owasp_id.value}][/bold yellow] {mod.description}")
                results = await mod.run(surface, plat)
                findings.extend(results)
                modules_run.append(name)
                if verbose and results:
                    for f in results:
                        color = _SEV_COLOR.get(f.severity.value, "white")
                        progress.console.print(
                            f"  [{color}][{f.severity.value.upper()}][/{color}] {f.title} [dim]({f.confidence}%)[/dim]"
                        )
                progress.advance(task)

    result = ScanResult(target=url, platform=platform_name, findings=findings, modules_run=modules_run, surface=surface)

    # Write outputs
    report_path = output_dir / "report.json"
    sarif_path  = output_dir / "report.sarif"

    if fmt in ("json", "both"):
        report_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    if fmt in ("sarif", "both"):
        from .sarif import to_sarif
        sarif_path.write_text(json.dumps(to_sarif(result, __version__), indent=2), encoding="utf-8")

    _print_summary(result)

    if fmt in ("json", "both"):
        console.print(f"Report : {report_path}")
    if fmt in ("sarif", "both"):
        console.print(f"SARIF  : {sarif_path}")

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
    fmt: str,
    exclude_module: list[str] | None,
    concurrency: int,
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
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
                    await _scan(url, plat_name, module_filter, target_dir, timeout, fail_on, fmt, exclude_module, verbose=False, api_key=api_key, username=username, password=password)
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
