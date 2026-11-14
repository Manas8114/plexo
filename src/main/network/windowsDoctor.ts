import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type {
  NetworkDoctorIssue,
  NetworkDoctorReport,
  NetworkInterfaceInfo
} from '../../shared/types'

const execFileAsync = promisify(execFile)
const POWERSHELL_TIMEOUT_MS = 5000

export function computeIpv4Subnet(address: string, netmask?: string): string | null {
  if (!netmask) return null
  const ipParts = address.split('.').map(Number)
  const maskParts = netmask.split('.').map(Number)
  if (ipParts.length !== 4 || maskParts.length !== 4) return null
  if (
    ipParts.some((p) => isNaN(p) || p < 0 || p > 255) ||
    maskParts.some((p) => isNaN(p) || p < 0 || p > 255)
  ) {
    return null
  }
  const subnetParts = ipParts.map((part, i) => part & maskParts[i])
  const maskBits =
    maskParts
      .map((b) => b.toString(2).padStart(8, '0'))
      .join('')
      .split('1').length - 1
  return `${subnetParts.join('.')}/${maskBits}`
}

export interface RawNetAdapter {
  Name?: string
  InterfaceDescription?: string
  InterfaceIndex?: number
  Status?: string
  LinkSpeed?: string
  Virtual?: boolean
  NdisPhysicalMedium?: number
}

export interface RawNetIPInterface {
  InterfaceAlias?: string
  InterfaceIndex?: number
  InterfaceMetric?: number
  AutomaticMetric?: number | boolean
  Dhcp?: number | boolean
  ConnectionState?: number | string
}

export interface RawNetRoute {
  InterfaceAlias?: string
  InterfaceIndex?: number
  NextHop?: string
  RouteMetric?: number
}

export interface RawNetConnectionProfile {
  InterfaceAlias?: string
  InterfaceIndex?: number
  Name?: string
  NetworkCategory?: number
  IPv4Connectivity?: number
}

export interface RawPowerShellDoctorData {
  adapters?: RawNetAdapter[]
  ipInterfaces?: RawNetIPInterface[]
  routes?: RawNetRoute[]
  profiles?: RawNetConnectionProfile[]
  domain?: boolean
}

export interface RegMinimizeConnectionsResult {
  exists: boolean
  value?: number
}

function toArray<T>(val: unknown): T[] {
  if (!val) return []
  return Array.isArray(val) ? val : [val as T]
}

/** Parses stdout of `reg.exe query ... /v fMinimizeConnections`. */
export function parseRegQueryMinimizeConnections(stdout: string): RegMinimizeConnectionsResult {
  const match = /\bfMinimizeConnections\s+REG_DWORD\s+(0x[0-9a-fA-F]+|\d+)/i.exec(stdout)
  if (!match) return { exists: false }
  const raw = match[1]
  const value = raw.toLowerCase().startsWith('0x') ? parseInt(raw, 16) : parseInt(raw, 10)
  return { exists: !Number.isNaN(value), value: Number.isNaN(value) ? undefined : value }
}

/** Parses JSON output of the combined PowerShell network query. */
export function parsePowerShellDoctorData(jsonString: string): RawPowerShellDoctorData {
  const clean = jsonString.trim().replace(/^\uFEFF/, '')
  if (!clean) return { adapters: [], ipInterfaces: [], routes: [], profiles: [], domain: false }
  try {
    const parsed = JSON.parse(clean) as Record<string, unknown>
    return {
      adapters: toArray<RawNetAdapter>(parsed.adapters),
      ipInterfaces: toArray<RawNetIPInterface>(parsed.ipInterfaces),
      routes: toArray<RawNetRoute>(parsed.routes),
      profiles: toArray<RawNetConnectionProfile>(parsed.profiles),
      domain: Boolean(parsed.domain)
    }
  } catch {
    return { adapters: [], ipInterfaces: [], routes: [], profiles: [], domain: false }
  }
}

const VIRTUAL_REGEX =
  /hyper-v|virtual|wsl|vethernet|tap|vpn|tailscale|wireguard|wintun|zerotier|openvpn/i

/** Pure, read-only evaluation of parsed Windows network state. */
export function diagnoseWindowsNetwork({
  psData,
  regData,
  interfaces
}: {
  psData: RawPowerShellDoctorData
  regData: RegMinimizeConnectionsResult
  interfaces: NetworkInterfaceInfo[]
}): NetworkDoctorReport {
  const issues: NetworkDoctorIssue[] = []
  const adapters = psData.adapters ?? []
  const ipInterfaces = psData.ipInterfaces ?? []
  const routes = psData.routes ?? []
  const isDomain = Boolean(psData.domain)

  // Read and report the connection policy without attempting to modify it.
  if (regData.exists && (regData.value ?? 0) !== 0) {
    const domainNote = isDomain
      ? ' Note: This computer is domain-joined and this policy may be managed by your organization.'
      : ''
    issues.push({
      id: 'fMinimizeConnections',
      severity: 'warning',
      title: 'Windows may disconnect Wi-Fi when tethering is connected',
      detail:
        `Windows policy "fMinimizeConnections" is active (value: ${regData.value}). ` +
        `This policy can cause Windows to minimize simultaneous connections when an Ethernet or USB phone tether is connected.${domainNote}`,
      recommendation:
        'To allow multiple simultaneous connections:\n' +
        '• Windows Pro/Enterprise: Open gpedit.msc → Computer Configuration → Administrative Templates → Network → Windows Connection Manager → disable "Minimize the number of simultaneous connections..."\n' +
        '• Windows Home: Run in an elevated prompt:\n' +
        '  reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 0 /f\n' +
        '  (Then restart your computer or reconnect network adapters).'
    })
  } else if (!regData.exists) {
    const domainNote = isDomain
      ? ' Note: This computer is domain-joined and settings may be managed by your organization.'
      : ''
    issues.push({
      id: 'fMinimizeConnections',
      severity: 'info',
      title: 'Simultaneous connection policy is unconfigured (default)',
      detail:
        `The "fMinimizeConnections" policy is not explicitly set in the registry. Windows Connection Manager may still manage simultaneous connections.${domainNote}`,
      recommendation:
        'If Wi-Fi drops when you plug in your phone tether, consult Windows Connection Manager policy settings. The Network Doctor does not change system settings.'
    })
  }

  // Identify the default route for information only. A lower metric on Ethernet than Wi-Fi
  // is a normal Windows configuration and is not diagnosed as a problem or remediation target.
  const ipInterfaceByAlias = new Map<string, RawNetIPInterface>()
  const ipInterfaceByIndex = new Map<number, RawNetIPInterface>()
  for (const ipIf of ipInterfaces) {
    if (ipIf.InterfaceAlias) ipInterfaceByAlias.set(ipIf.InterfaceAlias, ipIf)
    if (typeof ipIf.InterfaceIndex === 'number') ipInterfaceByIndex.set(ipIf.InterfaceIndex, ipIf)
  }

  const adapterByAlias = new Map<string, RawNetAdapter>()
  const adapterByIndex = new Map<number, RawNetAdapter>()
  for (const ad of adapters) {
    if (ad.Name) adapterByAlias.set(ad.Name, ad)
    if (typeof ad.InterfaceIndex === 'number') adapterByIndex.set(ad.InterfaceIndex, ad)
  }

  interface EvaluatedRoute {
    alias: string
    index?: number
    nextHop?: string
    totalMetric: number
  }

  const evaluatedRoutes: EvaluatedRoute[] = routes.map((route) => {
    const alias = route.InterfaceAlias || ''
    const index = route.InterfaceIndex
    const ipIf =
      (index !== undefined ? ipInterfaceByIndex.get(index) : undefined) ??
      ipInterfaceByAlias.get(alias)
    return {
      alias,
      index,
      nextHop: route.NextHop,
      totalMetric: (route.RouteMetric ?? 0) + (ipIf?.InterfaceMetric ?? 0)
    }
  })

  evaluatedRoutes.sort((a, b) => a.totalMetric - b.totalMetric)
  const defaultRoute = evaluatedRoutes[0]
  const defaultRouteOwner: NetworkDoctorReport['defaultRouteOwner'] = defaultRoute
    ? {
        interfaceName:
          defaultRoute.alias ||
          (defaultRoute.index !== undefined ? adapterByIndex.get(defaultRoute.index)?.Name : undefined) ||
          'Unknown',
        metric: defaultRoute.totalMetric,
        nextHop: defaultRoute.nextHop
      }
    : undefined

  // APIPA and interfaces without an IPv4 default route.
  for (const iface of interfaces) {
    const hasApipa = iface.addresses.some((addr) => addr.address.startsWith('169.254.'))
    if (hasApipa) {
      issues.push({
        id: 'apipa',
        severity: 'warning',
        title: `APIPA self-assigned IP on "${iface.displayName}"`,
        detail: `Adapter "${iface.displayName}" has an APIPA address (169.254.x.x), which usually indicates it did not receive an IPv4 address from DHCP.`,
        recommendation: 'Check the cable, phone tether, or DHCP configuration.',
        interfaceName: iface.displayName
      })
    }

    const hasDefaultRoute = evaluatedRoutes.some(
      (route) =>
        route.alias === iface.displayName ||
        route.alias === iface.device ||
        (typeof route.index === 'number' &&
          (adapterByIndex.get(route.index)?.Name === iface.displayName ||
            adapterByIndex.get(route.index)?.Name === iface.device))
    )

    if (!hasDefaultRoute && !hasApipa && iface.addresses.some((addr) => addr.family === 4)) {
      issues.push({
        id: 'noGateway',
        severity: 'warning',
        title: `No default gateway on "${iface.displayName}"`,
        detail:
          `Adapter "${iface.displayName}" has an IPv4 address but no default route (0.0.0.0/0). ` +
          'It may not be able to reach internet destinations on its own.',
        recommendation: 'Check that this network is connected to a router or tether with internet access.',
        interfaceName: iface.displayName
      })
    }
  }

  // Surface active virtual/VPN interfaces as informational notes only.
  for (const ad of adapters) {
    if (ad.Status && ad.Status.toLowerCase() !== 'up') continue
    const isVirtual =
      ad.Virtual === true ||
      VIRTUAL_REGEX.test((ad.InterfaceDescription || '') + ' ' + (ad.Name || ''))
    if (isVirtual && ad.Name) {
      issues.push({
        id: 'virtualAdapter',
        severity: 'info',
        title: `Virtual or VPN adapter: "${ad.Name}"`,
        detail:
          `Adapter "${ad.Name}" (${ad.InterfaceDescription || 'Virtual'}) appears to be a tunnel or virtual network. ` +
          'Check whether it is an independent internet connection before selecting it in Plexo.',
        recommendation: 'Review the adapter in Plexo and select it only if it provides an independent internet connection.',
        interfaceName: ad.Name
      })
    }
  }

  return {
    timestamp: Date.now(),
    supported: true,
    partOfDomain: isDomain,
    defaultRouteOwner,
    issues
  }
}

// Module-level cache: only re-runs PowerShell when interface list changes or a rescan is requested.
let cachedKey = ''
let cachedReport: NetworkDoctorReport | null = null
let inFlightScan: Promise<NetworkDoctorReport> | null = null

async function runWindowsDoctor(interfaces: NetworkInterfaceInfo[]): Promise<NetworkDoctorReport> {
  if (process.platform !== 'win32') {
    return { timestamp: Date.now(), supported: false, issues: [] }
  }

  let regData: RegMinimizeConnectionsResult = { exists: false }
  try {
    const { stdout } = await execFileAsync(
      'reg.exe',
      [
        'query',
        'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy',
        '/v',
        'fMinimizeConnections'
      ],
      { timeout: 3000, encoding: 'utf8' }
    )
    regData = parseRegQueryMinimizeConnections(stdout)
  } catch {
    regData = { exists: false }
  }

  let psData: RawPowerShellDoctorData = {}
  try {
    const psScript =
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ' +
      '@{ ' +
      'adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, InterfaceIndex, Status, LinkSpeed, Virtual, NdisPhysicalMedium); ' +
      'ipInterfaces = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, InterfaceMetric, AutomaticMetric, Dhcp, ConnectionState); ' +
      'routes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, NextHop, RouteMetric); ' +
      'profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, InterfaceIndex, Name, NetworkCategory, IPv4Connectivity); ' +
      'domain = [bool]((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain) ' +
      '} | ConvertTo-Json -Depth 3 -Compress'

    const { stdout } = await execFileAsync(
      'powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', psScript],
      { windowsHide: true, timeout: POWERSHELL_TIMEOUT_MS, encoding: 'utf8' }
    )
    psData = parsePowerShellDoctorData(stdout)
  } catch (error) {
    console.warn('[plexo] Network Doctor PowerShell query failed:', error)
  }

  return diagnoseWindowsNetwork({ psData, regData, interfaces })
}

/** Returns a read-only Network Doctor report; a forced scan is only user-triggered. */
export async function getWindowsDoctorReport(
  interfaces: NetworkInterfaceInfo[],
  force = false
): Promise<NetworkDoctorReport> {
  if (process.platform !== 'win32') {
    return { timestamp: Date.now(), supported: false, issues: [] }
  }

  const key = interfaces
    .map((i) => `${i.id}:${i.addresses.map((address) => address.address).sort().join(',')}`)
    .sort()
    .join('\n')

  if (!force && cachedReport && cachedKey === key) return cachedReport
  if (inFlightScan) return inFlightScan

  inFlightScan = runWindowsDoctor(interfaces)
    .then((report) => {
      cachedKey = key
      cachedReport = report
      inFlightScan = null
      return report
    })
    .catch((err) => {
      inFlightScan = null
      throw err
    })

  return inFlightScan
}
