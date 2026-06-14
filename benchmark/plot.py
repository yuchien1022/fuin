#!/usr/bin/env python3
"""Generate rotation benchmark SVG charts without third-party dependencies."""

from __future__ import annotations

import argparse
import csv
import html
import math
from pathlib import Path


DEFAULT_INPUT = Path("results/rotation_bench.csv")
DEFAULT_OUTPUT_DIR = Path("charts")


def svg_escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def read_rotation_csv(path: Path) -> list[dict[str, float]]:
    rows: list[dict[str, float]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "num_secrets",
            "secret_size_bytes",
            "envelope_ms",
            "naive_ms",
            "speedup",
        }
        if reader.fieldnames is None or set(reader.fieldnames) != required:
            raise ValueError(f"unexpected CSV header in {path}")
        for row in reader:
            rows.append(
                {
                    "num_secrets": float(row["num_secrets"]),
                    "secret_size_bytes": float(row["secret_size_bytes"]),
                    "envelope_ms": float(row["envelope_ms"]),
                    "naive_ms": float(row["naive_ms"]),
                    "speedup": float(row["speedup"]),
                }
            )
    if not rows:
        raise ValueError(f"no benchmark rows in {path}")
    return rows


def format_size(size_bytes: float) -> str:
    size = int(size_bytes)
    if size >= 1024 * 1024 and size % (1024 * 1024) == 0:
        return f"{size // (1024 * 1024)}MB"
    if size >= 1024 and size % 1024 == 0:
        return f"{size // 1024}KB"
    return f"{size}B"


def format_ms(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.2f}s"
    if value >= 10:
        return f"{value:.0f}ms"
    if value >= 1:
        return f"{value:.1f}ms"
    return f"{value:.2f}ms"


def polyline(points: list[tuple[float, float]], color: str) -> str:
    joined = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return (
        f'<polyline points="{joined}" fill="none" stroke="{color}" '
        'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>'
    )


def line_chart(rows: list[dict[str, float]], output: Path) -> None:
    width = 980
    height = 600
    left = 88
    right = 210
    top = 64
    bottom = 92
    plot_w = width - left - right
    plot_h = height - top - bottom
    counts = sorted({int(row["num_secrets"]) for row in rows})
    sizes = sorted({int(row["secret_size_bytes"]) for row in rows})
    by_count = {int(row["num_secrets"]): row for row in rows if int(row["secret_size_bytes"]) == sizes[0]}
    values = [row["envelope_ms"] for row in rows] + [row["naive_ms"] for row in rows]
    min_value = min(value for value in values if value > 0)
    max_value = max(values)
    log_min = math.floor(math.log10(min_value))
    log_max = math.ceil(math.log10(max_value))

    def x_scale(count: int) -> float:
        if len(counts) == 1:
            return left + plot_w / 2
        return left + ((count - counts[0]) / (counts[-1] - counts[0])) * plot_w

    def y_scale(value: float) -> float:
        normalized = (math.log10(value) - log_min) / (log_max - log_min)
        return top + (1.0 - normalized) * plot_h

    colors = {
        32: "#d95f02",
        1024: "#7570b3",
        65536: "#1b9e77",
        1048576: "#2171b5",
    }
    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Arial,Helvetica,sans-serif;fill:#1f2933}.title{font-size:22px;font-weight:700}.label{font-size:13px}.tick{font-size:12px;fill:#53606d}.legend{font-size:12px}</style>',
        f'<text x="{left}" y="34" class="title">Key Rotation Time: Envelope vs Naive</text>',
        f'<text x="{left}" y="54" class="label">Log scale; generated from results/rotation_bench.csv</text>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#415161" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#415161" stroke-width="1"/>',
    ]

    y_ticks = [10**exp for exp in range(log_min, log_max + 1)]
    for tick in y_ticks:
        y = y_scale(tick)
        parts.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + plot_w}" y2="{y:.2f}" stroke="#e5e9ef" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{left - 10}" y="{y + 4:.2f}" class="tick" text-anchor="end">{svg_escape(format_ms(float(tick)))}</text>'
        )
    for count in counts:
        x = x_scale(count)
        parts.append(
            f'<line x1="{x:.2f}" y1="{top + plot_h}" x2="{x:.2f}" y2="{top + plot_h + 6}" stroke="#415161" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{x:.2f}" y="{top + plot_h + 24}" class="tick" text-anchor="middle">{count}</text>'
        )
    parts.append(
        f'<text x="{left + plot_w / 2:.2f}" y="{height - 28}" class="label" text-anchor="middle">Number of secrets</text>'
    )
    parts.append(
        f'<text x="22" y="{top + plot_h / 2:.2f}" class="label" text-anchor="middle" transform="rotate(-90 22 {top + plot_h / 2:.2f})">Rotation time</text>'
    )

    envelope_points = [(x_scale(count), y_scale(by_count[count]["envelope_ms"])) for count in counts]
    parts.append(polyline(envelope_points, "#111827"))
    for x, y in envelope_points:
        parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3.5" fill="#111827"/>')

    for size in sizes:
        size_rows = {int(row["num_secrets"]): row for row in rows if int(row["secret_size_bytes"]) == size}
        points = [(x_scale(count), y_scale(size_rows[count]["naive_ms"])) for count in counts]
        color = colors.get(size, "#636363")
        parts.append(polyline(points, color))
        for x, y in points:
            parts.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="{color}"/>')

    legend_x = left + plot_w + 34
    legend_y = top + 16
    parts.append(f'<text x="{legend_x}" y="{legend_y}" class="label" font-weight="700">Series</text>')
    legend_items = [("Envelope", "#111827")] + [(f"Naive {format_size(size)}", colors.get(size, "#636363")) for size in sizes]
    for idx, (label, color) in enumerate(legend_items):
        y = legend_y + 24 + idx * 22
        parts.append(f'<line x1="{legend_x}" y1="{y - 4}" x2="{legend_x + 22}" y2="{y - 4}" stroke="{color}" stroke-width="3"/>')
        parts.append(f'<text x="{legend_x + 30}" y="{y}" class="legend">{svg_escape(label)}</text>')

    parts.append("</svg>")
    output.write_text("\n".join(parts) + "\n", encoding="utf-8")


def heat_color(speedup: float, max_log_speedup: float) -> str:
    if speedup < 1.0:
        return "#fdae61"
    level = math.log10(max(speedup, 1.0)) / max_log_speedup if max_log_speedup > 0 else 0.0
    level = max(0.0, min(level, 1.0))
    start = (222, 235, 247)
    end = (8, 81, 156)
    rgb = tuple(round(start[i] + (end[i] - start[i]) * level) for i in range(3))
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


def speedup_heatmap(rows: list[dict[str, float]], output: Path) -> None:
    width = 920
    height = 520
    left = 120
    top = 78
    cell_w = 150
    cell_h = 78
    counts = sorted({int(row["num_secrets"]) for row in rows})
    sizes = sorted({int(row["secret_size_bytes"]) for row in rows})
    data = {(int(row["num_secrets"]), int(row["secret_size_bytes"])): row for row in rows}
    max_log_speedup = max(math.log10(max(row["speedup"], 1.0)) for row in rows)

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<style>text{font-family:Arial,Helvetica,sans-serif;fill:#1f2933}.title{font-size:22px;font-weight:700}.label{font-size:13px}.tick{font-size:12px;fill:#53606d}.cell{font-size:16px;font-weight:700}.subcell{font-size:11px;fill:#334155}</style>',
        f'<text x="{left}" y="34" class="title">Rotation Speedup Heatmap</text>',
        f'<text x="{left}" y="54" class="label">Speedup = naive_ms / envelope_ms. Values below 1 mean naive is faster.</text>',
    ]

    for col, count in enumerate(counts):
        x = left + col * cell_w + cell_w / 2
        parts.append(f'<text x="{x:.2f}" y="{top - 18}" class="tick" text-anchor="middle">{count} secrets</text>')
    for row_idx, size in enumerate(sizes):
        y = top + row_idx * cell_h + cell_h / 2
        parts.append(f'<text x="{left - 16}" y="{y + 5:.2f}" class="tick" text-anchor="end">{svg_escape(format_size(size))}</text>')
        for col, count in enumerate(counts):
            item = data[(count, size)]
            speedup = item["speedup"]
            x0 = left + col * cell_w
            y0 = top + row_idx * cell_h
            fill = heat_color(speedup, max_log_speedup)
            text_color = "#ffffff" if speedup >= 50 else "#1f2933"
            parts.append(
                f'<rect x="{x0}" y="{y0}" width="{cell_w}" height="{cell_h}" fill="{fill}" stroke="#ffffff" stroke-width="2"/>'
            )
            parts.append(
                f'<text x="{x0 + cell_w / 2:.2f}" y="{y0 + 34:.2f}" class="cell" text-anchor="middle" style="fill:{text_color}">{speedup:.1f}x</text>'
            )
            parts.append(
                f'<text x="{x0 + cell_w / 2:.2f}" y="{y0 + 55:.2f}" class="subcell" text-anchor="middle">{format_ms(item["naive_ms"])} / {format_ms(item["envelope_ms"])}</text>'
            )

    parts.append(f'<text x="{left + len(counts) * cell_w / 2:.2f}" y="{height - 28}" class="label" text-anchor="middle">Number of secrets</text>')
    parts.append(f'<text x="34" y="{top + len(sizes) * cell_h / 2:.2f}" class="label" text-anchor="middle" transform="rotate(-90 34 {top + len(sizes) * cell_h / 2:.2f})">Secret size</text>')
    parts.append("</svg>")
    output.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate rotation benchmark charts.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    rows = read_rotation_csv(args.input)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    line_chart(rows, args.out_dir / "rotation_envelope_vs_naive.svg")
    speedup_heatmap(rows, args.out_dir / "rotation_speedup_heatmap.svg")
    print(f"Generated: {args.out_dir / 'rotation_envelope_vs_naive.svg'}")
    print(f"Generated: {args.out_dir / 'rotation_speedup_heatmap.svg'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
