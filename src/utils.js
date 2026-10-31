export const DEFAULT_REPLACEMENT = "[REDACTED]";

export function cloneRegExp(regex) {
  if (!(regex instanceof RegExp)) {
    throw new TypeError("Each pattern.regex must be a RegExp");
  }
  const flags = [...new Set(`${regex.flags.replace(/[gy]/g, "")}g`)].join("");
  return new RegExp(regex.source, flags);
}

export function getCaptureRange(match, groupIndex) {
  if (!groupIndex) {
    return { index: match.index, length: match[0].length };
  }

  const value = match[groupIndex];
  if (typeof value !== "string" || value.length === 0) return null;

  // Locate the capture inside the full match. This is deterministic for the
  // built-in patterns, whose secret capture is unique within the match.
  const offset = match[0].indexOf(value);
  if (offset < 0) return null;
  return { index: match.index + offset, length: value.length };
}

export function getIgnoredRanges(text, options = {}) {
  const ranges = [];

  if (options.ignoreCodeBlocks) {
    // Fenced Markdown blocks. The closing fence must use the same character
    // and be at least as long as the opening fence.
    const lines = text.split(/(?<=\n)/);
    let absolute = 0;
    let open = null;

    for (const line of lines) {
      const content = line.replace(/\r?\n$/, "");
      const fence = content.match(/^ {0,3}(`{3,}|~{3,})/);
      if (!open && fence) {
        open = { start: absolute, char: fence[1][0], length: fence[1].length };
      } else if (open) {
        const close = content.match(/^ {0,3}(`+|~+)/);
        if (close && close[1][0] === open.char && close[1].length >= open.length) {
          ranges.push({ start: open.start, end: absolute + line.length });
          open = null;
        }
      }
      absolute += line.length;
    }
    if (open) ranges.push({ start: open.start, end: text.length });

    // Inline code spans, excluding fenced ranges already found.
    const inline = /(`+)([^`\n]|\n)*?\1/g;
    let match;
    while ((match = inline.exec(text)) !== null) {
      ranges.push({ start: match.index, end: match.index + match[0].length });
    }
  }

  if (options.ignoreComments) {
    const comments = /<!--[\s\S]*?-->/g;
    let match;
    while ((match = comments.exec(text)) !== null) {
      ranges.push({ start: match.index, end: match.index + match[0].length });
    }
  }

  return ranges.sort((a, b) => a.start - b.start);
}

export function overlapsIgnoredRange(index, length, ranges) {
  const end = index + length;
  return ranges.some((range) => index < range.end && end > range.start);
}

/** Merge intersecting findings into deterministic redaction intervals. */
export function mergeOverlappingFindings(findings) {
  if (!findings.length) return [];
  const sorted = [...findings].sort((a, b) => a.index - b.index || b.length - a.length);
  const groups = [];

  for (const finding of sorted) {
    const current = groups[groups.length - 1];
    const end = finding.index + finding.length;
    if (!current || finding.index >= current.end) {
      groups.push({ start: finding.index, end, findings: [finding] });
    } else {
      current.end = Math.max(current.end, end);
      current.findings.push(finding);
    }
  }

  return groups;
}
