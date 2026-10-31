/**
 * Built-in secret patterns.
 * Patterns intentionally target recognizable credential formats and assignments.
 * This is a heuristic scanner, not a guarantee that every secret will be found.
 */

const define = (id, label, regex, secretGroup = 0) =>
  Object.freeze({ id, label, regex, secretGroup });

export const DEFAULT_PATTERNS = Object.freeze([
  // Generic credential assignments. Match the whole assignment so the key is
  // removed together with its value and cannot be accidentally left in logs.
  define(
    "generic.password",
    "Password or secret assignment",
    /(?:^|[^A-Za-z0-9_])(?:passphrase|password|passwd|пароль|pass|pwd|secret|auth|api[_-]?secret|client[_-]?secret|api[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|ключ)\s*[:=]\s*(?:"[^"\r\n]{4,}"|'[^'\r\n]{4,}'|[^\s,;"']{4,})/i
  ),
  define(
    "generic.email-password-pair",
    "Email and Password Pair",
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b(?:[ \t]*[:;|/ ][ \t]*|\r?\n[ \t]*)([^\s]{6,128})/i
  ),
  define(
    "generic.authorization",
    "Authorization header",
    /(?:\bAuthorization\s*:\s*)(?:Basic|Bearer)\s+[^\s,;]+/i
  ),
  define(
    "generic.bearer-token",
    "Bearer token",
    /\bBearer\s+([A-Za-z0-9_~+/.=-]{8,})/i,
    1
  ),
  define(
    "generic.basic-auth-url",
    "Credentials in URL",
    /\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s/@:]+:[^\s/@]+@[^\s]+/i
  ),
  define(
    "db.uri-password",
    "Database URI credentials",
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s/@:]+:[^\s/@]+@[^\s]+/i
  ),
  define(
    "generic.cookie-header",
    "Cookie or set-cookie header",
    /(?:\b(?:Cookie|Set-Cookie)\s*:\s*)[^\r\n]+/i
  ),

  // Cloud provider credentials.
  define("aws.access-key", "AWS access key ID", /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/),
  define(
    "aws.secret-key",
    "AWS secret access key",
    /\b(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i,
    1
  ),
  define("google.api-key", "Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/),
  define("google.oauth-token", "Google OAuth refresh token", /\b1\/\/0[0-9A-Za-z_-]{43,}\b/),
  define(
    "azure.storage-key",
    "Azure Storage account key",
    /\b(?:AccountKey|account_key)\s*=\s*["']?([A-Za-z0-9+/]{80,90}={0,2})["']?/i,
    1
  ),

  // AI and SaaS providers.
  define("openai.project-key", "OpenAI project key", /\bsk-proj-[A-Za-z0-9_-]{20,}\b/),
  define("openai.legacy-key", "OpenAI API key", /\bsk-[A-Za-z0-9]{40,64}\b/),
  define("anthropic.key", "Anthropic API key", /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b/),
  define("github.token", "GitHub token", /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/),
  define("github.fine-grained", "GitHub fine-grained token", /\bgithub_pat_[A-Za-z0-9_]{50,}\b/),
  define("gitlab.pat", "GitLab personal access token", /\bglpat-[A-Za-z0-9_-]{20,}\b/),
  define("stripe.live-secret", "Stripe live secret key", /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/),
  define("stripe.test-secret", "Stripe test secret key", /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b/),
  define("slack.token", "Slack token", /\bxox[abopsr]-[A-Za-z0-9-]{20,}\b/),
  define("slack.webhook", "Slack webhook URL", /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/),
  define("twilio.account-sid", "Twilio account SID", /\bAC[a-f0-9]{32}\b/),
  define("twilio.api-key", "Twilio API key", /\bSK[a-f0-9]{32}\b/),
  define("sendgrid.api-key", "SendGrid API key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/),
  define("mailgun.key", "Mailgun API key", /\bkey-[a-f0-9]{32}\b/i),
  define("npm.token", "npm token", /\bnpm_[A-Za-z0-9]{30,}\b/),
  define("pypi.token", "PyPI upload token", /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{30,}\b/),
  define("cloudflare.api-token", "Cloudflare API token", /\b(?:Cf|cf)-[A-Za-z0-9_-]{30,}\b/),
  define("square.token", "Square access token", /\bsq0i[ac]p-[0-9A-Za-z_-]{30,}\b/),
  define("newrelic.api-key", "New Relic API key", /\bNRAK-[A-Z0-9]{20,}\b/),
  define("shopify.token", "Shopify access token", /\bshp(?:ss|ca|at|pa)_[a-fA-F0-9]{32}\b/),

  // Cryptographic material and common token formats.
  define("jwt", "JSON Web Token", /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/),
  define(
    "pem.private-key",
    "PEM private key block",
    /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |)PRIVATE KEY-----/
  ),
  define("ssh.private-key-header", "SSH private key header", /-----BEGIN OPENSSH PRIVATE KEY-----/)
]);
