from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Optional, Sequence, TextIO

from descry.scoring import Result

PALETTE = {
    "accent": ((94, 234, 212), 121),
    "success": ((74, 222, 128), 114),
    "warning": ((251, 191, 36), 214),
    "error": ((248, 113, 113), 203),
    "muted": ((107, 114, 128), 243),
    "text": ((229, 231, 235), 252),
}


def color_mode(no_color: bool = False, stream: TextIO = sys.stdout) -> str:
    if no_color or "NO_COLOR" in os.environ or not stream.isatty():
        return "none"
    colorterm = os.environ.get("COLORTERM", "").lower()
    if colorterm in {"truecolor", "24bit"}:
        return "truecolor"
    if "256color" in os.environ.get("TERM", ""):
        return "256"
    if os.name == "nt" and os.environ.get("WT_SESSION"):
        return "truecolor"
    return "256"


def paint(
    text: str,
    name: str = "text",
    mode: str = "none",
    bold: bool = False,
    dim: bool = False,
) -> str:
    if mode == "none" or not text:
        return text
    (red, green, blue), fallback = PALETTE[name]
    codes = []
    if bold:
        codes.append("1")
    if dim:
        codes.append("2")
    if mode == "truecolor":
        codes.append(f"38;2;{red};{green};{blue}")
    else:
        codes.append(f"38;5;{fallback}")
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"


def confidence_style(value: float) -> str:
    if value < 40.0:
        return "error"
    if value < 70.0:
        return "warning"
    return "success"


def flatten(text: str) -> str:
    cleaned = "".join(
        character if character.isprintable() else " " for character in text
    )
    return " ".join(cleaned.split())


def preview(text: str, width: int) -> str:
    flattened = flatten(text)
    if width <= 3:
        return flattened[:width]
    if len(flattened) <= width:
        return flattened
    return flattened[: width - 3] + "..."


def supports_unicode(stream: TextIO = sys.stdout) -> bool:
    encoding = getattr(stream, "encoding", "") or ""
    try:
        "█░─".encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def bar(value: float, width: int, mode: str, unicode_ok: bool = True) -> str:
    filled = max(0, min(width, round(width * value / 100.0)))
    full = "█" if unicode_ok else "#"
    empty = "░" if unicode_ok else "."
    color = confidence_style(value)
    return paint(full * filled, color, mode) + paint(empty * (width - filled), "muted", mode)


def output_format(requested: Optional[str]) -> str:
    if requested is not None:
        return requested
    return "pretty" if sys.stdout.isatty() else "plain"


def write_line(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def write_json(payload: object) -> None:
    write_line(json.dumps(payload, indent=2))


def result_payload(results: Sequence[Result]) -> list[dict[str, object]]:
    return [
        {
            "rank": rank,
            "key": result.label,
            "confidence": result.confidence,
            "text": result.text,
        }
        for rank, result in enumerate(results, start=1)
    ]


def render_results(
    results: Sequence[Result],
    fmt: str,
    mode: str,
    label_header: str = "KEY",
    text_header: str = "PREVIEW",
    title: Optional[str] = None,
) -> None:
    if fmt == "json":
        write_json(result_payload(results))
        return
    if not results:
        write_line("no results")
        return
    if fmt == "plain":
        label_width = max(len(label_header.lower()), max(len(result.label) for result in results))
        rank_width = len(str(len(results)))
        for rank, result in enumerate(results, start=1):
            write_line(
                f"{rank:<{rank_width}}  {result.label:<{label_width}}  "
                f"{result.confidence:5.1f}  {preview(result.text, 80)}"
            )
        return
    render_pretty_results(results, mode, label_header, text_header, title)


def render_pretty_results(
    results: Sequence[Result],
    mode: str,
    label_header: str,
    text_header: str,
    title: Optional[str],
) -> None:
    rank_width = max(2, len(str(len(results))))
    label_width = max(
        len(label_header), max(len(result.label) for result in results)
    )
    bar_width = 12
    confidence_width = bar_width + 6
    terminal_width = shutil.get_terminal_size((100, 24)).columns
    unicode_ok = supports_unicode()
    preview_width = max(
        20,
        terminal_width - rank_width - label_width - confidence_width - 10,
    )
    if title:
        write_line(paint(f"  {title}", "accent", mode, bold=True))
    write_line(
        "  "
        + " " * rank_width
        + "  "
        + paint(label_header.ljust(label_width), "muted", mode)
        + "  "
        + paint("CONFIDENCE".ljust(confidence_width), "muted", mode)
        + "  "
        + paint(text_header, "muted", mode)
    )
    for rank, result in enumerate(results, start=1):
        best = rank == 1
        label_color = "accent" if best else "muted"
        text_color = "text" if best else "muted"
        rank_text = paint(
            f"{rank:>{rank_width}}",
            label_color,
            mode,
            bold=best,
            dim=not best,
        )
        label_text = paint(
            result.label.ljust(label_width),
            label_color,
            mode,
            bold=best,
            dim=not best,
        )
        confidence_text = paint(
            f"{result.confidence:5.1f}",
            confidence_style(result.confidence),
            mode,
            dim=not best,
        )
        plaintext = preview(result.text, preview_width)
        write_line(
            f"  {rank_text}  {label_text}  "
            f"{bar(result.confidence, bar_width, mode, unicode_ok)} {confidence_text}  "
            f"{paint(plaintext, text_color, mode, dim=not best)}"
        )


def render_single(
    value: str, fmt: str, mode: str, payload: dict[str, object]
) -> None:
    if fmt == "json":
        write_json(payload)
    elif fmt == "pretty":
        write_line(paint(value, "text", mode))
    else:
        write_line(value)


def render_decode(
    final: str,
    steps: Sequence[str],
    fmt: str,
    mode: str,
    original: str,
) -> None:
    if fmt == "json":
        write_json({"input": original, "steps": list(steps), "output": final})
        return
    if fmt == "plain":
        write_line(final)
        return
    if steps:
        write_line(paint(" -> ".join(steps), "muted", mode))
    write_line(paint(final, "accent", mode))


def render_frequency(
    rows: Sequence[dict[str, object]],
    summary: dict[str, object],
    fmt: str,
    mode: str,
) -> None:
    if fmt == "json":
        write_json({"letters": list(rows), "summary": summary})
        return
    if fmt == "plain":
        write_line("letter\tcount\tpercent\tenglish")
        for row in rows:
            write_line(
                f"{row['letter']}\t{row['count']}\t{row['percent']:.2f}\t{row['english']:.2f}"
            )
        write_line(f"index_of_coincidence\t{summary['index_of_coincidence']}")
        chi = summary["chi_squared"]
        write_line(f"chi_squared\t{'n/a' if chi is None else chi}")
        write_line(f"english\t{summary['english']}")
        return
    render_pretty_frequency(rows, summary, mode)


def render_pretty_frequency(
    rows: Sequence[dict[str, object]],
    summary: dict[str, object],
    mode: str,
) -> None:
    max_percent = max((float(row["percent"]) for row in rows), default=1.0)
    scale = max(1.0, max_percent)
    unicode_ok = supports_unicode()
    full = "█" if unicode_ok else "#"
    write_line(
        f"  {'LETTER':<8}{'COUNT':>5}  {'FREQ':>6}  {'ENGLISH':>7}"
    )
    for row in rows:
        count = int(row["count"])
        percent = float(row["percent"])
        english = float(row["english"])
        bars = max(0, round(20 * percent / scale))
        letter = paint(str(row["letter"]).ljust(8), "accent", mode, bold=True)
        write_line(
            f"  {letter}{count:>5}  {percent:>5.2f}%  {english:>6.2f}%  "
            f"{paint(full * bars, 'accent', mode)}"
        )
    write_line()
    write_line(
        f"  {paint('Index of coincidence', 'muted', mode)}  "
        f"{summary['index_of_coincidence']}"
    )
    chi = summary["chi_squared"]
    write_line(
        f"  {paint('Chi-squared', 'muted', mode)}           "
        f"{'n/a' if chi is None else chi}"
    )
    write_line(
        f"  {paint('English likeness', 'muted', mode)}      "
        f"{summary['english']} / 100"
    )


def render_home(mode: str) -> None:
    if sys.stdout.isatty():
        write_line()
        write_line(paint("  descry", "accent", mode, bold=True))
        write_line(paint("  cipher analysis and cracking", "muted", mode))
        rule = "─" if supports_unicode() else "-"
        write_line(paint("  " + rule * 27, "muted", mode, dim=True))
    groups = [
        (
            "CRACKING",
            [
                ("crack", "auto-detect and crack input"),
                ("id", "identify encoding or cipher"),
                ("decode", "peel layered encodings"),
            ],
        ),
        (
            "CIPHERS",
            [
                ("caesar", "encrypt, decrypt, brute force"),
                ("vigenere", "encrypt, decrypt, crack"),
                ("xor", "single-byte and repeating-key"),
            ],
        ),
        (
            "ANALYSIS",
            [
                ("freq", "letter frequency and coincidence"),
            ],
        ),
    ]
    for heading, entries in groups:
        write_line()
        write_line(paint(f"  {heading}", "muted", mode, bold=True))
        for command, description in entries:
            write_line(
                f"  {paint(command.ljust(10), 'accent', mode)} "
                f"{paint(description, 'text', mode)}"
            )
    write_line()
    write_line(
        paint("  descry -h for all commands and examples", "muted", mode)
    )
    write_line()
