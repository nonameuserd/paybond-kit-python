from __future__ import annotations

from paybond_kit.cli.command_spec import COMMAND_PATHS, GLOBAL_FLAG_NAMES


def _levenshtein(a: str, b: str) -> int:
    rows = len(a) + 1
    cols = len(b) + 1
    matrix = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        matrix[i][0] = i
    for j in range(cols):
        matrix[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost)
    return matrix[len(a)][len(b)]


def _best_suggestion(input_value: str, candidates: list[str]) -> str | None:
    needle = input_value.strip().lower()
    if not needle:
        return None
    best: tuple[str, int] | None = None
    for candidate in candidates:
        distance = _levenshtein(needle, candidate.lower())
        threshold = max(2, len(candidate) // 3)
        if distance > threshold:
            continue
        if best is None or distance < best[1]:
            best = (candidate, distance)
    return best[0] if best else None


def suggest_command_path(input_value: str) -> str | None:
    return _best_suggestion(input_value, COMMAND_PATHS)


def suggest_global_flag(input_value: str) -> str | None:
    normalized = input_value.split("=", 1)[0]
    return _best_suggestion(normalized, GLOBAL_FLAG_NAMES)


def format_unknown_command_message(input_value: str) -> str:
    suggestion = suggest_command_path(input_value)
    if suggestion:
        return f'unknown command: {input_value} (did you mean "{suggestion}"?)'
    return f"unknown command: {input_value}"


def format_unknown_global_flag_message(flag: str) -> str:
    suggestion = suggest_global_flag(flag)
    if suggestion:
        return f"unknown global flag: {flag} (did you mean {suggestion}?)"
    return f"unknown global flag: {flag}"
