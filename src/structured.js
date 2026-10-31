import { redact } from "./scanner.js";

const SENSITIVE_KEY = /(?:^|[_-])(?:password|passwd|pwd|secret|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|credential|client[_-]?secret|cookie|session[_-]?id|token)(?:$|[_-])/i;
const SENSITIVE_COMPACT = /^(?:password|passwd|pwd|secret|apikey|privatekey|accesstoken|refreshtoken|authorization|auth|credential|credentials|clientsecret|cookie|setcookie|sessionid|token)$/i;

export function isSensitiveKey(key) {
  if (typeof key !== "string") return false;
  const normalized = key.replace(/[\s_-]/g, "").toLowerCase();
  return SENSITIVE_KEY.test(key) || SENSITIVE_COMPACT.test(normalized);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Recursively clone arrays and plain objects while sanitizing string values.
 * Non-plain objects (Date, Buffer, class instances, Map, Set, etc.) are returned
 * unchanged by design. Circular references are preserved in the cloned graph.
 */
export function sanitizeStructured(value, options = {}, seen = new WeakMap()) {
  if (typeof value === "string") return redact(value, options);
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value);

  if (Array.isArray(value)) {
    const output = [];
    seen.set(value, output);
    for (const item of value) output.push(sanitizeStructured(item, options, seen));
    return output;
  }

  if (!isPlainObject(value)) return value;

  const output = Object.create(Object.getPrototypeOf(value));
  seen.set(value, output);
  for (const key of Object.keys(value)) {
    const item = value[key];
    output[key] = isSensitiveKey(key)
      ? "[REDACTED]"
      : sanitizeStructured(item, options, seen);
  }
  return output;
}
