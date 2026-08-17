"""
P3 Agent CLI — runs on remote machine.

Commands:
  p3-agent enroll <token>  — enroll with Controller
  p3-agent run             — start agent loop
  p3-agent status          — show agent status
"""

import asyncio
import sys

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()
app = typer.Typer(name="p3-agent", help="P3 Agent — remote agent client")


@app.command("enroll")
def enroll(token: str = typer.Argument(..., help="Enrollment token from Controller")):
    """Enroll this agent with P3 Controller using one-time token."""
    from ..client import P3AgentClient

    console.print("[bold]Enrolling agent...[/bold]")

    agent = P3AgentClient()
    try:
        result = asyncio.run(agent.enroll(token))
    except Exception as e:
        console.print(f"[red]Enrollment failed: {e}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold green]Agent enrolled![/bold green]\n\n"
        f"  Agent ID: {result['agent_id']}\n"
        f"  Status: {result['status']}\n"
        f"  Permissions: {result.get('permissions', {})}\n"
        f"  Server: {result.get('server_url', '?')}",
        title="P3 Agent",
    ))

    console.print("\n[green]Identity key saved locally. Agent is ready to run.[/green]")
    console.print("[bold]Next: p3-agent run[/bold]")


@app.command("run")
def run():
    """Start the agent loop — poll for commands, execute in sandbox."""
    from ..client import P3AgentClient

    agent = P3AgentClient()
    if not agent.load_identity():
        console.print("[red]Not enrolled — run 'p3-agent enroll <token>' first[/red]")
        raise typer.Exit(1)

    console.print(f"[bold green]P3 Agent {agent.protocol.agent_id} starting...[/bold green]")
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Agent stopped[/yellow]")


@app.command("status")
def status():
    """Show agent status."""
    from ..client import P3AgentClient
    from pathlib import Path
    import json

    agent = P3AgentClient()
    identity_path = agent._identity_path

    if not identity_path.exists():
        console.print("[yellow]Not enrolled[/yellow]")
        return

    with open(identity_path) as f:
        data = json.load(f)

    console.print(Panel(
        f"  Agent ID: {data['agent_id']}\n"
        f"  Controller: {data.get('controller_url', '?')}\n"
        f"  Enrolled: {data.get('enrolled_at', '?')}\n"
        f"  Permissions: {data.get('permissions', {})}",
        title="P3 Agent Status",
    ))
