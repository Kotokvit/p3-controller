"""
P3 Controller CLI — admin interface.

Commands:
  p3 login github          — add GitHub PAT (validated, encrypted)
  p3 agent create <name>   — create agent, get key + enrollment token
  p3 agent list            — list all agents
  p3 agent revoke <name>   — revoke an agent
  p3 agent permissions     — show/modify permissions
  p3 server                — start Controller server
  p3 test                  — end-to-end test
"""

import asyncio
import json
import sys
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from p3controller.config import P3Config
from p3controller.storage.database import P3Database
from p3controller.security.crypto import generate_agent_key, parse_agent_key, hash_secret

console = Console()
app = typer.Typer(name="p3", help="P3 Controller — Secure AI Agent Control Plane")

agent_app = typer.Typer(name="agent", help="Agent management")
app.add_typer(agent_app, name="agent")

github_app = typer.Typer(name="github", help="GitHub credential management")
app.add_typer(github_app, name="github")


def get_controller_url(cfg: P3Config) -> str:
    host = cfg.get("server", "host", default="127.0.0.1")
    port = cfg.get("server", "port", default=8443)
    return f"https://{host}:{port}"


async def admin_post(path: str, data: dict, cfg: P3Config) -> dict:
    url = get_controller_url(cfg)
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            f"{url}{path}",
            json=data,
            headers={"X-Admin-Key": "p3-admin-local"},
        )
        if resp.status_code != 200:
            console.print(f"[red]Error: {resp.status_code} {resp.text}[/red]")
            raise typer.Exit(1)
        return resp.json()


async def admin_get(path: str, cfg: P3Config) -> dict:
    url = get_controller_url(cfg)
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(
            f"{url}{path}",
            headers={"X-Admin-Key": "p3-admin-local"},
        )
        if resp.status_code != 200:
            console.print(f"[red]Error: {resp.status_code} {resp.text}[/red]")
            raise typer.Exit(1)
        return resp.json()


# ── GitHub ─────────────────────────────────────────────────

@github_app.command("add")
def github_add():
    """Add a GitHub Personal Access Token (encrypted, validated)."""
    token = Prompt.ask("GitHub PAT", password=True)
    if not token.startswith("github_pat_") and not token.startswith("ghp_"):
        console.print("[yellow]Warning: token doesn't look like a GitHub PAT[/yellow]")

    token_type = "fine_grained" if token.startswith("github_pat_") else "classic"

    cfg = P3Config()
    result = asyncio.run(admin_post(
        "/api/v1/admin/github/credentials",
        {"token": token, "token_type": token_type},
        cfg,
    ))

    console.print(Panel(
        f"[green]✓[/green] GitHub credential added\n"
        f"  Owner: {result.get('owner', '?')}\n"
        f"  ID: {result.get('credential_id', '?')}\n"
        f"  Type: {result.get('token_type', '?')}",
        title="GitHub",
    ))


# ── Agent ──────────────────────────────────────────────────

@agent_app.command("create")
def agent_create(
    name: str = typer.Argument(..., help="Agent name"),
    profile: str = typer.Option("developer", help="Profile: sandbox|developer|trusted"),
):
    """Create a new agent and get enrollment token."""
    cfg = P3Config()

    # Interactive permission selection
    console.print(f"\n[bold]Creating agent:[/bold] {name}")
    console.print(f"[bold]Profile:[/bold] {profile}")

    profile_info = {
        "sandbox": "Docker only — no GPU, no network, no GitHub",
        "developer": "Docker + GPU + network + GitHub (recommended)",
        "trusted": "Like developer + extra mounts (admin-configured)",
    }
    console.print(f"  {profile_info.get(profile, '')}\n")

    result = asyncio.run(admin_post(
        "/api/v1/admin/agents",
        {"name": name, "profile": profile},
        cfg,
    ))

    console.print(Panel(
        f"[bold green]Agent created![/bold green]\n\n"
        f"[bold]Agent ID:[/bold]\n  {result['agent_id']}\n\n"
        f"[bold]Agent Key:[/bold]\n  {result['agent_key']}\n\n"
        f"[bold]Enrollment token:[/bold] (one-time, {result['expires_in']}s)\n  [yellow]{result['enrollment_token']}[/yellow]\n\n"
        f"[dim]Run on remote machine:[/dim]\n  [bold]p3-agent enroll {result['enrollment_token']}[/bold]",
        title="P3 Agent",
    ))

    console.print("\n[yellow]⚠ Save the Agent Key securely. Enrollment token expires soon.[/yellow]")


@agent_app.command("list")
def agent_list():
    """List all agents."""
    cfg = P3Config()
    result = asyncio.run(admin_get("/api/v1/admin/agents", cfg))

    agents = result.get("agents", [])
    if not agents:
        console.print("[dim]No agents created yet[/dim]")
        return

    table = Table(title="P3 Agents")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Status", style="green")
    table.add_column("Profile")
    table.add_column("Created")

    for a in agents:
        status = a.get("status", "?")
        status_style = {"active": "green", "pending": "yellow", "revoked": "red"}.get(status, "")
        table.add_row(
            a.get("id", "?"),
            a.get("name", "?"),
            f"[{status_style}]{status}[/{status_style}]",
            a.get("profile", "?"),
            time.strftime("%Y-%m-%d %H:%M", time.localtime(a.get("created_at", 0))),
        )

    console.print(table)


@agent_app.command("revoke")
def agent_revoke(name: str = typer.Argument(..., help="Agent name or ID")):
    """Revoke an agent — all future requests will be denied."""
    cfg = P3Config()
    # Find agent by name
    result = asyncio.run(admin_get("/api/v1/admin/agents", cfg))
    agents = result.get("agents", [])
    agent_id = None
    for a in agents:
        if a["name"] == name or a["id"] == name:
            agent_id = a["id"]
            break

    if not agent_id:
        console.print(f"[red]Agent '{name}' not found[/red]")
        raise typer.Exit(1)

    asyncio.run(admin_post(f"/api/v1/admin/agents/{agent_id}/revoke", {}, cfg))
    console.print(f"[red]Agent {name} ({agent_id}) revoked[/red]")


# ── Server ─────────────────────────────────────────────────

@app.command("server")
def server_start(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8443),
):
    """Start the P3 Controller server."""
    import uvicorn
    from p3controller.server.app import create_app

    cfg = P3Config()
    cfg.load()
    app = create_app(cfg)

    console.print(Panel(
        f"[bold green]P3 Controller starting[/bold green]\n"
        f"  Host: {host}\n"
        f"  Port: {port}\n"
        f"  Config: {cfg.config_dir}",
        title="P3",
    ))

    uvicorn.run(app, host=host, port=port, ssl_keyfile=None, ssl_certfile=None)


# ── Test ───────────────────────────────────────────────────

@app.command("test")
def run_test():
    """Run end-to-end test of Controller + Agent + Warden."""
    from tests.e2e import run_e2e_test
    asyncio.run(run_e2e_test())


import time  # for strftime in agent_list
