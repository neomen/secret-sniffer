import { DEFAULT_PATTERNS } from "./patterns.js";
import { cloneRegExp, getCaptureRange, getIgnoredRanges, overlapsIgnoredRange, mergeOverlappingFindings, DEFAULT_REPLACEMENT } from "./utils.js";

function validatePatterns(patterns) {
  if (!Array.isArray(patterns)) throw new TypeError("options.patterns must be an array");
  for (const pattern of patterns) {
    if (!pattern || typeof pattern.id !== "string" || typeof pattern.label !== "string") {
      throw new TypeError("Each pattern must have string id and label properties");
    }
    if (!(pattern.regex instanceof RegExp)) throw new TypeError(`Pattern ${pattern.id} must have a RegExp in regex`);
  }
}

/** Scan text and return metadata only. Secret values are never included. */
export function scan(text, options = {}) {
  if (typeof text !== "string") throw new TypeError("scan() expects a string");
  if (text.length === 0) return { found: false, findings: [] };

  const patterns = options.patterns ?? DEFAULT_PATTERNS;
  validatePatterns(patterns);
  const ignoredRanges = getIgnoredRanges(text, options);
  const findings = [];

  for (const pattern of patterns) {
    const regex = cloneRegExp(pattern.regex);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const range = getCaptureRange(match, pattern.secretGroup ?? 0);
      if (range && range.length > 0 && !overlapsIgnoredRange(range.index, range.length, ignoredRanges)) {
        findings.push(Object.freeze({
          patternId: pattern.id,
          label: pattern.label,
          index: range.index,
          length: range.length
        }));
      }
      if (match[0].length === 0) regex.lastIndex += 1;
    }
  }

  findings.sort((a, b) => a.index - b.index || b.length - a.length);
  return { found: findings.length > 0, findings };
}

/** Return true as soon as a finding exists, without collecting all findings. */
export function contains(text, options = {}) {
  if (typeof text !== "string") throw new TypeError("contains() expects a string");
  if (text.length === 0) return false;

  const patterns = options.patterns ?? DEFAULT_PATTERNS;
  validatePatterns(patterns);
  const ignoredRanges = getIgnoredRanges(text, options);

  for (const pattern of patterns) {
    const regex = cloneRegExp(pattern.regex);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const range = getCaptureRange(match, pattern.secretGroup ?? 0);
      if (range && range.length > 0 && !overlapsIgnoredRange(range.index, range.length, ignoredRanges)) {
        return true;
      }
      if (match[0].length === 0) regex.lastIndex += 1;
    }
  }
  return false;
}

/** Replace detected secrets. Intersecting findings are redacted as one span. */
export function redact(text, options = {}) {
  const result = scan(text, options);
  if (!result.found) return text;

  const replacement = options.replacement ?? DEFAULT_REPLACEMENT;
  const groups = mergeOverlappingFindings(result.findings);
  let output = text;

  for (let i = groups.length - 1; i >= 0; i -= 1) {
    const group = groups[i];
    const primary = [...group.findings].sort((a, b) => b.length - a.length || a.patternId.localeCompare(b.patternId))[0];
    const finding = Object.freeze({ ...primary, index: group.start, length: group.end - group.start });
    const value = typeof replacement === "function" ? replacement(finding) : replacement;
    if (typeof value !== "string") throw new TypeError("replacement function must return a string");
    output = output.slice(0, group.start) + value + output.slice(group.end);
  }

  return output;
}

export function sanitizeText(text, options = {}) {
  return redact(text, options);
}
