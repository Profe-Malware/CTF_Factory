"""chumbucket.ui - split module (code verbatim from the monolith)."""




TOOL_NAME   = "ChumBucket"


SUBTITLE    = "Network-Forensics CTF Challenge Forge"


VERSION     = "v1.5"


AUTHOR      = "Profe Malware"


DESCRIPTION = (
    "Chums the water with realistic background traffic and decoy flags, then hides\n"
    "     the real catch for your players to fish out. Built for educators, red\n"
    "     teamers, and competition designers."
)


DEFAULT_FLAG_PREFIX = "CTF"


WORDMARK = r"""
 ██████╗██╗  ██╗██╗   ██╗███╗   ███╗██████╗ ██╗   ██╗ ██████╗██╗  ██╗███████╗████████╗
██╔════╝██║  ██║██║   ██║████╗ ████║██╔══██╗██║   ██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
██║     ███████║██║   ██║██╔████╔██║██████╔╝██║   ██║██║     █████╔╝ █████╗     ██║   
██║     ██╔══██║██║   ██║██║╚██╔╝██║██╔══██╗██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   
╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   
 ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
""".strip("\n")


def format_flag(wrapper: str, inner: str) -> str:
    """Insert the inner flag text into the wrapper at the first 'FLAG' token."""
    return wrapper.replace("FLAG", inner, 1)


def wrapper_parts(wrapper: str) -> tuple[str, str]:
    """Return the (open, close) text surrounding the 'FLAG' placeholder.
    Uses partition so a stray second 'FLAG' never causes an unpack error."""
    open_, _, close = wrapper.partition("FLAG")
    return open_, close


THEME = {
    "banner":      "bold cyan",
    "border":      "cyan",
    "author":      "bold bright_cyan",
    "subtitle":    "bold white",
    "description": "dim white",
    "meta":        "dim cyan",
    "menu_title":  "bold cyan",
    "menu_item":   "white",
    "menu_number": "bold cyan",
    "prompt":      "bold cyan",
    "success":     "bold green",
    "warning":     "bold yellow",
    "error":       "bold red",
    "highlight":   "bold bright_white",
    "coming_soon": "dim yellow",
}


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    _console = Console()
    _HAS_RICH = True
except ImportError:
    _console = None
    _HAS_RICH = False


def print_banner():
    """Render the tool signature with the big wordmark. rich + THEME if available."""
    if _HAS_RICH:
        from rich.align import Align
        from rich.console import Group
        art = Text(WORDMARK, style=THEME["banner"], no_wrap=True, overflow="ignore")
        sub = Text(SUBTITLE, style=THEME["subtitle"])
        desc = Text("\n" + DESCRIPTION + "\n", style=THEME["description"])
        foot = Text()
        foot.append(VERSION, style=THEME["meta"])
        foot.append("   •   ", style=THEME["border"])
        foot.append(f"by {AUTHOR}", style=THEME["author"])
        body = Group(art, Text(), sub, desc, foot)
        _console.print(Panel(body, border_style=THEME["border"], expand=False,
                             padding=(1, 3)))
    else:
        print(WORDMARK)
        print(f"  {SUBTITLE}")
        print(f"  {DESCRIPTION}")
        print(f"  {VERSION}  -  by {AUTHOR}")
        print("=" * 86)


def _style(text: str, key: str) -> str:
    """Wrap text in rich markup for THEME[key], or return plain if no rich."""
    return f"[{THEME[key]}]{text}[/]" if _HAS_RICH else text


def say(text: str, key: str = "menu_item"):
    if _HAS_RICH:
        _console.print(_style(text, key))
    else:
        print(text)


def ask(label: str, default: str = "") -> str:
    """Free-text prompt with a default shown in brackets."""
    suffix = f" [{default}]" if default else ""
    if _HAS_RICH:
        _console.print(_style(f"{label}{suffix}: ", "prompt"), end="")
    else:
        print(f"{label}{suffix}: ", end="")
    val = input().strip()
    return val if val else default


def ask_int(label: str, default: int) -> int:
    while True:
        raw = ask(label, str(default))
        try:
            return int(raw)
        except ValueError:
            say("  Please enter a whole number.", "error")


def ask_choice(title: str, options: list[tuple[str, str]], default_idx: int = 0) -> str:
    """Render a numbered menu. options is a list of (value, description).
    Returns the chosen value."""
    say(f"\n{title}", "menu_title")
    for i, (val, desc) in enumerate(options, 1):
        num = _style(f"  {i})", "menu_number")
        item = _style(f"{val}", "highlight")
        tail = _style(f" - {desc}", "menu_item")
        if _HAS_RICH:
            _console.print(f"{num} {item}{tail}")
        else:
            print(f"  {i}) {val} - {desc}")
    while True:
        raw = ask("Choose", str(default_idx + 1))
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        say("  Invalid choice, try again.", "error")


def ask_yesno(label: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    raw = ask(f"{label} ({d})", "").lower()
    if not raw:
        return default
    return raw.startswith("y")
