import { scan, redact } from "./scanner.js";
import { sanitizeStructured, isSensitiveKey } from "./structured.js";

function countFindings(value, options, seen = new WeakSet()) {
  if (typeof value === "string") return scan(value, options).findings.length;
  if (value === null || typeof value !== "object" || seen.has(value)) return 0;
  seen.add(value);

  let count = 0;
  if (Array.isArray(value)) {
    for (const item of value) count += countFindings(item, options, seen);
    return count;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return 0;

  for (const key of Object.keys(value)) {
    if (isSensitiveKey(key)) count += 1;
    else count += countFindings(value[key], options, seen);
  }
  return count;
}

/** Sanitize a string, array, or plain object without mutating the input. */
export function sanitize(value, options = {}) {
  return sanitizeStructured(value, options);
}

/** Sanitize and return a small report without exposing secret values. */
export function sanitizeWithReport(value, options = {}) {
  const findingsCount = countFindings(value, options);
  return {
    value: sanitize(value, options),
    report: {
      found: findingsCount > 0,
      findingsCount
    }
  };
}

export { redact };
