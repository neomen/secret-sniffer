export interface Pattern {
  readonly id: string;
  readonly label: string;
  readonly regex: RegExp;
  readonly secretGroup?: number;
}

export interface Finding {
  readonly patternId: string;
  readonly label: string;
  readonly index: number;
  readonly length: number;
}

export interface ScanResult {
  found: boolean;
  findings: Finding[];
}

export type RedactReplacement = string | ((finding: Finding) => string);

export interface ScanOptions {
  patterns?: readonly Pattern[];
  ignoreCodeBlocks?: boolean;
  ignoreComments?: boolean;
}

export interface RedactOptions extends ScanOptions {
  replacement?: RedactReplacement;
}

export declare const DEFAULT_PATTERNS: readonly Pattern[];
export declare function scan(text: string, options?: ScanOptions): ScanResult;
export declare function contains(text: string, options?: ScanOptions): boolean;
export declare function redact(text: string, options?: RedactOptions): string;
export declare function sanitizeText(text: string, options?: RedactOptions): string;
export declare function sanitize<T>(value: T, options?: RedactOptions): T;
export declare function sanitizeWithReport<T>(value: T, options?: RedactOptions): {
  value: T;
  report: { found: boolean; findingsCount: number };
};
export declare function isSensitiveKey(key: string): boolean;
