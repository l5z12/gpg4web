// Official-deployment detection.
//
// gpg4web is meant to be served from l5z12.dev (or a subdomain). Any other
// origin is flagged as potentially unofficial/modified so users don't enter
// secrets into a tampered copy. The allowed list can be overridden at build
// time with the VITE_OFFICIAL_DOMAINS env var (comma-separated).

const DEFAULT_OFFICIAL = 'l5z12.dev'

function parseDomains(): string[] {
  const raw = import.meta.env.VITE_OFFICIAL_DOMAINS || DEFAULT_OFFICIAL
  return raw
    .split(',')
    .map((d) => d.trim().toLowerCase().replace(/^\.+|\.+$/g, ''))
    .filter(Boolean)
}

/** The configured official domains (apex entries; subdomains are allowed). */
export const officialDomains = parseDomains()

/** True when the given hostname is an official domain or a subdomain of one. */
export function isOfficialDomain(hostname: string = window.location.hostname): boolean {
  const h = hostname.toLowerCase()
  return officialDomains.some((d) => h === d || h.endsWith(`.${d}`))
}
