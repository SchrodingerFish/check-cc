// CheckCC 的检测信号配置，用于声明各风险信号的启用状态、来源、权重和展示顺序。
import type { DetectionSignalConfig } from "./types";

export const signalConfig: Record<string, DetectionSignalConfig> = {
  // 1. 基础环境指纹 (10项)
  timezone: { enabled: true, labelKey: "timezone", source: "browser", weight: 26, order: 10 },
  language: { enabled: true, labelKey: "language", source: "browser", weight: 20, order: 20 },
  languageVariant: { enabled: true, labelKey: "languageVariant", source: "browser", weight: 12, order: 30 },
  chineseFonts: { enabled: true, labelKey: "chineseFonts", source: "browser", weight: 16, order: 40 },
  vendorFonts: { enabled: true, labelKey: "vendorFonts", source: "browser", weight: 10, order: 50 },
  domesticBrowser: { enabled: true, labelKey: "domesticBrowser", source: "browser", weight: 8, order: 60 },
  domesticDevice: { enabled: true, labelKey: "domesticDevice", source: "browser", weight: 6, order: 70 },
  locale: { enabled: true, labelKey: "locale", source: "browser", weight: 6, order: 80 },
  timezoneOffset: { enabled: true, labelKey: "timezoneOffset", source: "browser", weight: 4, order: 90 },
  emojiStyle: { enabled: true, labelKey: "emojiStyle", source: "browser", weight: 4, order: 100 },

  // 2. 浏览器环境与设备识别 (3项)
  browser: { enabled: true, labelKey: "browser", source: "browser", weight: 0, order: 110 },
  device: { enabled: true, labelKey: "device", source: "browser", weight: 0, order: 120 },
  os: { enabled: true, labelKey: "os", source: "browser", weight: 0, order: 130 },

  // 3. 客户端请求与协议头特征 (3项)
  requestHeaderIntegrity: { enabled: true, labelKey: "requestHeaderIntegrity", source: "browser", weight: 0, order: 140 },
  acceptLanguageHeader: { enabled: true, labelKey: "acceptLanguageHeader", source: "browser", weight: 4, order: 150 },
  secFetchProfile: { enabled: true, labelKey: "secFetchProfile", source: "browser", weight: 0, order: 160 },

  // 4. 网络出口与 IP 基础画像 (7项)
  country: { enabled: true, labelKey: "country", source: "server", weight: 20, order: 200 },
  proxyCountry: { enabled: true, labelKey: "proxyCountry", source: "server", weight: 0, order: 210 },
  ipAddress: { enabled: true, labelKey: "ipAddress", source: "server", weight: 0, order: 220 },
  browserIpLocation: { enabled: true, labelKey: "browserIpLocation", source: "server", weight: 0, order: 230 },
  browserIpAsn: { enabled: true, labelKey: "browserIpAsn", source: "server", weight: 0, order: 240 },
  browserIpOrg: { enabled: true, labelKey: "browserIpOrg", source: "server", weight: 0, order: 250 },
  ipCountryRisk: { enabled: true, labelKey: "ipCountryRisk", source: "server", weight: 15, order: 260 },

  // 5. Claude / Anthropic 节点连通性主动探测 (6项)
  claudeAiReachability: { enabled: true, labelKey: "claudeAiReachability", source: "browser", weight: 6, order: 300 },
  anthropicSiteReachability: { enabled: true, labelKey: "anthropicSiteReachability", source: "browser", weight: 6, order: 310 },
  anthropicApiReachability: { enabled: true, labelKey: "anthropicApiReachability", source: "browser", weight: 6, order: 320 },
  claudeServiceStatus: { enabled: true, labelKey: "claudeServiceStatus", source: "browser", weight: 8, order: 330 },
  claudeLatencyLevel: { enabled: true, labelKey: "claudeLatencyLevel", source: "browser", weight: 4, order: 340 },
  claudeAccessRisk: { enabled: true, labelKey: "claudeAccessRisk", source: "browser", weight: 10, order: 350 },

  // 6. WebRTC 真实 IP 泄漏探测 (7项)
  webrtcSupported: { enabled: true, labelKey: "webrtcSupported", source: "browser", weight: 0, order: 400 },
  webrtcCandidateStatus: { enabled: true, labelKey: "webrtcCandidateStatus", source: "browser", weight: 0, order: 410 },
  webrtcPublicIpLeak: { enabled: true, labelKey: "webrtcPublicIpLeak", source: "browser", weight: 14, order: 420 },
  webrtcLeakIpCount: { enabled: true, labelKey: "webrtcLeakIpCount", source: "browser", weight: 0, order: 430 },
  webrtcFirstLeakIp: { enabled: true, labelKey: "webrtcFirstLeakIp", source: "browser", weight: 0, order: 440 },
  webrtcLeakRegionRisk: { enabled: true, labelKey: "webrtcLeakRegionRisk", source: "browser", weight: 10, order: 450 },
  webrtcHttpExitMismatch: { enabled: true, labelKey: "webrtcHttpExitMismatch", source: "browser", weight: 8, order: 460 },

  // 7. DNS 检测与代理一致性 (3项)
  dnsCheckMode: { enabled: true, labelKey: "dnsCheckMode", source: "server", weight: 0, order: 500 },
  dnsExitRegionRisk: { enabled: true, labelKey: "dnsExitRegionRisk", source: "server", weight: 6, order: 510 },
  dnsProxyConsistencyHint: { enabled: true, labelKey: "dnsProxyConsistencyHint", source: "server", weight: 6, order: 520 },

  // 8. 多源 IP 情报与 Cloudflare 边缘特征 (9项)
  edgeCountry: { enabled: true, labelKey: "edgeCountry", source: "server", weight: 0, order: 600 },
  edgeColo: { enabled: true, labelKey: "edgeColo", source: "server", weight: 0, order: 610 },
  edgeCity: { enabled: true, labelKey: "edgeCity", source: "server", weight: 0, order: 620 },
  edgeAsn: { enabled: true, labelKey: "edgeAsn", source: "server", weight: 0, order: 630 },
  edgeAsOrganization: { enabled: true, labelKey: "edgeAsOrganization", source: "server", weight: 0, order: 640 },
  networkExitType: { enabled: true, labelKey: "networkExitType", source: "server", weight: 13, order: 650 },
  ipIntelConsistency: { enabled: true, labelKey: "ipIntelConsistency", source: "server", weight: 15, order: 660 },
  ipIntelSourceCount: { enabled: true, labelKey: "ipIntelSourceCount", source: "server", weight: 0, order: 670 },
  ipCountrySet: { enabled: true, labelKey: "ipCountrySet", source: "server", weight: 0, order: 680 },
};
