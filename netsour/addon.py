"""The addon authoring API — the only module an addon needs to import.

    from netsour.addon import alert, key, on_packet, panel

    @on_packet
    def watch(pkt): ...

    @panel("My card")
    def card(ctx): ...

    @key("z", "do the thing")
    def go(ui): ...

Each decorator returns the function unchanged and files it against the addon
currently being loaded, so a file can also be imported normally (in a test, say)
without a registry present — the decorators just do nothing then.

Everything here is deliberately small. The contract is: packet hooks run on the
capture thread under the session lock, panels render under that same lock, key
handlers run on the UI thread, and none of them may raise into NetSour — the
registry catches what they throw and disables an addon that keeps throwing.
"""

from __future__ import annotations

from typing import Callable

from .addons import KeySpec, Line, PanelSpec, current_draft, current_registry

__all__ = ["on_packet", "panel", "key", "on_start", "on_clear", "alert",
           "Line", "notify"]


def on_packet(func: Callable) -> Callable:
    """Register `func(pkt)`, called for every dissected packet.

    This is the capture hot path — thousands of calls a second. Do arithmetic
    here and leave the formatting to a panel.
    """
    draft = current_draft()
    if draft is not None:
        draft.addon.packet_hooks.append(func)
    return func


def panel(title: str = "", key: str = "", order: int = 100) -> Callable:
    """Register `func(ctx)` as a Dashboard card.

    The function returns lines: plain strings, `(text, role)` pairs, or
    :class:`Line` objects. `role` is a theme colour name — base, dim, accent,
    ok, warn, danger or header.
    """
    def decorate(func: Callable) -> Callable:
        draft = current_draft()
        if draft is not None:
            name = title or func.__name__.replace("_", " ").title()
            draft.addon.panels.append(
                PanelSpec(key=key or f"{draft.name}.{func.__name__}",
                          title=name, render=func, source=draft.name,
                          order=order))
        return func
    return decorate


def key(char: str, help: str = "") -> Callable:
    """Bind a key to `func(ui)`. `ui` is the running App: notify, session, views.

    Addon bindings are tried after NetSour's own, so a key the application
    already uses cannot be stolen out from under the user.
    """
    def decorate(func: Callable) -> Callable:
        draft = current_draft()
        if draft is not None:
            draft.addon.keys.append(
                KeySpec(char=char[:1], help=help or func.__doc__ or "",
                        handler=func, source=draft.name))
        return func
    return decorate


def on_start(func: Callable) -> Callable:
    """Register `func(session)`, called once when the session is attached."""
    draft = current_draft()
    if draft is not None:
        draft.addon.start_hooks.append(func)
    return func


def on_clear(func: Callable) -> Callable:
    """Register `func()`, called when the user clears the capture buffer."""
    draft = current_draft()
    if draft is not None:
        draft.addon.clear_hooks.append(func)
    return func


def alert(title: str, detail: str = "", severity: str = "medium",
          pkt=None, key: str = "") -> None:
    """Raise a finding into the Alerts view.

    Repeats are collapsed the way the built-in detectors' are: alerts sharing a
    key inside the cooldown bump a counter instead of stacking up.
    """
    registry = current_registry()
    if registry is not None:
        registry.alert(title, detail=detail, severity=severity, rec=pkt,
                       key=key)


def notify(ui, text: str, role: str = "accent") -> None:
    """Put a message on NetSour's message line (from a key handler)."""
    ui.notify(text, role)
