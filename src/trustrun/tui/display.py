"""TUI display — builds Rich renderables from TuiState."""

from __future__ import annotations

import time
from datetime import datetime, timedelta

from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trustrun.tui.state import TuiState, ViewMode


class TuiDisplay:
    """Builds Rich Layout objects from the current TuiState."""

    def __init__(self, start_time: float | None = None) -> None:
        self._start_time = start_time or time.time()

    def render(self, state: TuiState, height: int = 24, width: int = 80) -> Layout:
        """Build the full screen layout from current state."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body"),
            Layout(name="footer", size=4),
        )

        layout["header"].update(self._render_header(state))

        if state.mode == ViewMode.TABLE:
            layout["body"].update(self._render_table(state, height - 8))
        elif state.mode == ViewMode.DETAIL:
            layout["body"].update(self._render_detail(state))
        elif state.mode == ViewMode.POLICY:
            layout["body"].update(self._render_policy(state))
        elif state.mode == ViewMode.HELP:
            layout["body"].update(self._render_help())

        layout["footer"].update(self._render_footer(state))

        return layout

    def _render_header(self, state: TuiState) -> Panel:
        elapsed = timedelta(seconds=int(time.time() - self._start_time))
        sniffer = "[green]active[/green]" if state.sniffer_active else "[dim]off[/dim]"

        line1 = (
            f"[bold]TrustRun[/bold]  PID {state.pid}  "
            f"Policy: [cyan]{state.policy.name}[/cyan]   "
            f"Events: {state.event_count}  "
            f"Viols: {state.violation_count}"
        )
        line2 = f"Uptime: {elapsed}   DNS/SNI: {sniffer}"
        if state.command:
            line2 += f"   Cmd: [dim]{state.command}[/dim]"

        header_text = Text.from_markup(f"{line1}\n{line2}")
        return Panel(header_text, style="bold")

    def _render_table(self, state: TuiState, body_height: int) -> Panel:
        events, _violations, violation_ids = state.snapshot()

        if not events:
            return Panel(
                Text("Waiting for connections...", style="dim italic"),
                title="Connections",
                border_style="blue",
            )

        table = Table(
            show_header=True,
            header_style="bold",
            expand=True,
            box=None,
            padding=(0, 1),
        )
        table.add_column("#", width=4, justify="right")
        table.add_column("Time", width=19, no_wrap=True)
        table.add_column("Destination", ratio=1, no_wrap=True)
        table.add_column("Port", width=6, justify="right")
        table.add_column("Org", width=16, no_wrap=True)
        table.add_column("Proto", width=5)

        # Viewport calculation
        visible_rows = max(1, body_height - 3)  # account for header/border
        total = len(events)

        state.clamp_cursor(total)

        if state.follow:
            state.cursor = total - 1

        # Adjust scroll offset to keep cursor visible
        if state.cursor < state.scroll_offset:
            state.scroll_offset = state.cursor
        elif state.cursor >= state.scroll_offset + visible_rows:
            state.scroll_offset = state.cursor - visible_rows + 1
        state.scroll_offset = max(0, min(state.scroll_offset, total - visible_rows))

        start = state.scroll_offset
        end = min(start + visible_rows, total)

        for i in range(start, end):
            event = events[i]
            is_cursor = i == state.cursor
            is_violation = event.id in violation_ids
            row_num = i + 1

            dest = event.hostname or event.remote_ip
            org = _truncate(event.org, 16)
            ts = datetime.fromtimestamp(event.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            prefix = ">" if is_cursor else " "
            num_str = f"{prefix}{row_num}"

            if is_violation:
                style = "bold red" if is_cursor else "red"
            elif is_cursor:
                style = "bold reverse"
            else:
                style = ""

            table.add_row(
                num_str, ts, dest, str(event.remote_port), org, event.protocol,
                style=style,
            )

        scroll_info = ""
        if total > visible_rows:
            scroll_info = f" [{start + 1}-{end}/{total}]"

        return Panel(
            table,
            title=f"Connections{scroll_info}",
            border_style="blue",
        )

    def _render_detail(self, state: TuiState) -> Panel:
        events, violations, violation_ids = state.snapshot()
        total = len(events)

        if total == 0:
            return Panel(Text("No connection selected"), title="Detail")

        state.clamp_cursor(total)
        event = events[state.cursor]
        is_violation = event.id in violation_ids

        lines: list[str] = [
            f"[bold]Connection #{state.cursor + 1}[/bold]",
            "",
            f"  Process:      {event.process_name} (PID {event.pid})",
            f"  Remote IP:    {event.remote_ip}",
            f"  Hostname:     {event.hostname or '[dim]none[/dim]'}",
            f"  Remote Port:  {event.remote_port}",
            f"  Local:        {event.local_ip}:{event.local_port}",
            f"  Protocol:     {event.protocol}",
            f"  Status:       {event.status}",
            f"  Organization: {event.org or '[dim]unknown[/dim]'}",
            f"  Event ID:     {event.id}",
            "",
        ]

        if is_violation:
            viol = next(
                (v for v in violations if v.event.id == event.id), None
            )
            if viol:
                lines.append("  [red bold]VIOLATION[/red bold]")
                lines.append(f"  Action:       {viol.action.upper()}")
                lines.append(f"  Matched Rule: {viol.rule_match}")
                lines.append(f"  Reason:       {viol.reason}")
            lines.append("")
            lines.append(
                "  [dim]Press 'a' to allow, 'b' to block,"
                " Esc to go back[/dim]"
            )
        else:
            lines.append("  [green]No violation[/green]")
            lines.append("")
            lines.append("  [dim]Press 'b' to block, Esc to go back[/dim]")

        return Panel(
            Text.from_markup("\n".join(lines)),
            title="Connection Detail",
            border_style="yellow" if is_violation else "green",
        )

    def _render_policy(self, state: TuiState) -> Panel:
        policy = state.policy
        table = Table(
            show_header=True,
            header_style="bold",
            expand=True,
            box=None,
            padding=(0, 1),
        )
        table.add_column("#", width=4, justify="right")
        table.add_column("Pattern", ratio=1)
        table.add_column("Action", width=8)
        table.add_column("Reason", ratio=1)

        for i, rule in enumerate(policy.rules, 1):
            action_style = {
                "alert": "green",
                "block": "red",
                "kill": "red bold",
            }.get(rule.action.value, "")

            reason = rule.reason
            if "interactively via TUI" in reason:
                reason = f"{reason} [cyan][+NEW][/cyan]"

            table.add_row(
                str(i),
                rule.match,
                f"[{action_style}]{rule.action.value}[/{action_style}]",
                reason,
            )

        info = (
            f"Policy: [cyan]{policy.name}[/cyan]  "
            f"Rules: {len(policy.rules)}  "
            f"Default: {policy.defaults.action.value}"
        )
        if state.policy_dirty:
            info += "  [yellow](modified)[/yellow]"

        header = Text.from_markup(info)

        layout = Layout()
        layout.split_column(
            Layout(header, size=1),
            Layout(table),
        )

        return Panel(
            layout,
            title="Policy Rules",
            border_style="cyan",
        )

    def _render_help(self) -> Panel:
        help_text = Text.from_markup(
            "[bold]Key Bindings[/bold]\n"
            "\n"
            "  [cyan]j[/cyan] / [cyan]↓[/cyan]      Move cursor down\n"
            "  [cyan]k[/cyan] / [cyan]↑[/cyan]      Move cursor up\n"
            "  [cyan]g[/cyan]          Jump to top\n"
            "  [cyan]G[/cyan]          Jump to bottom (re-enable follow)\n"
            "  [cyan]Enter[/cyan]      Toggle detail view for selected connection\n"
            "  [cyan]a[/cyan]          Allow selected destination (add rule)\n"
            "  [cyan]b[/cyan]          Block selected destination (add rule)\n"
            "  [cyan]p[/cyan]          Toggle policy view\n"
            "  [cyan]e[/cyan]          Export current policy to YAML file\n"
            "  [cyan]Esc[/cyan]        Return to table view\n"
            "  [cyan]?[/cyan]          Toggle this help\n"
            "  [cyan]q[/cyan]          Quit monitoring\n"
        )
        return Panel(help_text, title="Help", border_style="green")

    def _render_footer(self, state: TuiState) -> Panel:
        if state.mode == ViewMode.TABLE:
            keys = (
                "[dim]q[/dim]:Quit  [dim]↑/↓[/dim]:Navigate  "
                "[dim]Enter[/dim]:Detail  [dim]a[/dim]:Allow  "
                "[dim]b[/dim]:Block  [dim]p[/dim]:Policy  [dim]?[/dim]:Help"
            )
        elif state.mode == ViewMode.DETAIL:
            keys = (
                "[dim]Esc[/dim]:Back  [dim]a[/dim]:Allow  "
                "[dim]b[/dim]:Block  [dim]↑/↓[/dim]:Prev/Next  [dim]q[/dim]:Quit"
            )
        elif state.mode == ViewMode.POLICY:
            keys = (
                "[dim]Esc[/dim]:Back  [dim]e[/dim]:Export  [dim]q[/dim]:Quit"
            )
        else:
            keys = "[dim]Esc[/dim]:Back  [dim]q[/dim]:Quit"

        lines = keys
        if state.status_message and time.time() < state._status_expiry:
            lines += f"\n[yellow]{state.status_message}[/yellow]"
        elif state.status_message:
            state.status_message = ""

        return Panel(Text.from_markup(lines), style="dim")


def _truncate(s: str, maxlen: int) -> str:
    if len(s) <= maxlen:
        return s
    return s[: maxlen - 1] + "…"
