// CheckCC 的多源 IP 与网络出口威胁情报探测插件，通过多节点比对识别机房属性、ASN 与出口冲突。
import { isPublicIp, makeSignalScore } from "../client-engine";
import type { DetectionPlugin } from "../plugin";
import type { SignalResult } from "../types";

export type NetworkIntelData = {
  ip: string | null;
  country: string | null;
  city: string | null;
  location: string | null;
  asn: string | null;
  org: string | null;
  isp: string | null;
  colo: string | null;
  latitude: number | null;
  longitude: number | null;
  networkType: string | null;
  isDatacenter: boolean;
  consistencyStatus: string;
  sourceCount: string;
};

// 探测 ping0.cc JSONP 端点
export function queryPing0Intel(): Promise<{ ip: string; location: string; country: string; asn: string; org: string } | null> {
  if (typeof window === "undefined" || typeof document === "undefined") return Promise.resolve(null);
  return new Promise((resolve) => {
    const callbackName = `checkccPing0${Date.now()}${Math.random().toString(36).slice(2)}`;
    const script = document.createElement("script");
    const timer = window.setTimeout(() => cleanup(null), 2800);

    const cleanup = (res: any) => {
      window.clearTimeout(timer);
      script.remove();
      try {
        delete (window as any)[callbackName];
      } catch {}
      resolve(res);
    };

    (window as any)[callbackName] = (ip: string, location: string, asn: string, org: string) => {
      cleanup({
        ip,
        location,
        country: location?.split(/\s+/)[0] || location,
        asn,
        org,
      });
    };

    script.onerror = () => cleanup(null);
    script.src = `https://ping0.cc/geo/jsonp/${callbackName}`;
    document.body.appendChild(script);
  });
}

// 探测 Cloudflare cdn-cgi/trace
export async function queryCloudflareTrace(): Promise<{ ip: string | null; loc: string | null; colo: string | null } | null> {
  if (typeof window === "undefined" || typeof fetch === "undefined") return null;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 2600);

  try {
    const res = await fetch("https://cloudflare.com/cdn-cgi/trace", {
      signal: controller.signal,
      cache: "no-store",
    });
    if (res.ok) {
      const text = await res.text();
      const lines = text.split("\n");
      const kv: Record<string, string> = {};
      for (const line of lines) {
        const [k, v] = line.split("=");
        if (k && v) kv[k.trim()] = v.trim();
      }
      return {
        ip: kv["ip"] || null,
        loc: kv["loc"] || null,
        colo: kv["colo"] || null,
      };
    }
  } catch {
    // ignore
  } finally {
    window.clearTimeout(timer);
  }
  return null;
}

// 探测公共 IP 地址与归属 (ipwho.is 作为通用兜底)
export async function queryPublicIpwho(): Promise<{
  ip: string;
  country: string;
  city: string;
  asn: string;
  org: string;
  isp: string;
  latitude: number | null;
  longitude: number | null;
  isHosting: boolean;
} | null> {
  if (typeof window === "undefined" || typeof fetch === "undefined") return null;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 2600);

  try {
    const res = await fetch("https://ipwho.is/", {
      signal: controller.signal,
      cache: "no-store",
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.success !== false) {
        return {
          ip: data.ip,
          country: data.country || data.country_code,
          city: data.city,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : "",
          org: data.connection?.org || data.connection?.isp || "",
          isp: data.connection?.isp || data.connection?.org || "",
          latitude: typeof data.latitude === "number" ? data.latitude : null,
          longitude: typeof data.longitude === "number" ? data.longitude : null,
          isHosting: Boolean(data.connection?.hosting),
        };
      }
    }
  } catch {
    // ignore
  } finally {
    window.clearTimeout(timer);
  }
  return null;
}

export async function detectNetworkIntel(
  text: any,
  config: any
): Promise<{ data: NetworkIntelData; signals: SignalResult[] }> {
  const [ping0, cfTrace, ipwho] = await Promise.all([
    queryPing0Intel().catch(() => null),
    queryCloudflareTrace().catch(() => null),
    queryPublicIpwho().catch(() => null),
  ]);

  const detectedIp = ping0?.ip || ipwho?.ip || cfTrace?.ip || null;
  const country = ping0?.country || ipwho?.country || cfTrace?.loc || "未知";
  const city = ipwho?.city || ping0?.location?.split(/\s+/)[1] || null;
  const asn = ping0?.asn || ipwho?.asn || null;
  const org = ping0?.org || ipwho?.org || null;
  const isp = ipwho?.isp || org || null;
  const colo = cfTrace?.colo || null;
  const latitude = ipwho?.latitude ?? null;
  const longitude = ipwho?.longitude ?? null;

  // 判断机房 / 数据中心 / 云厂商
  const orgLower = (org || "").toLowerCase();
  const isDatacenter =
    Boolean(ipwho?.isHosting) ||
    /cloudflare|amazon|aws|google|microsoft|azure|digitalocean|oracle|linode|vultr|alibaba|tencent|ovh|hetzner|fastly|akamai/i.test(
      orgLower
    );

  const countries = [ping0?.country, ipwho?.country, cfTrace?.loc].filter(Boolean) as string[];
  const uniqueCountries = Array.from(new Set(countries.map((c) => c.toUpperCase())));
  const isConsistent = uniqueCountries.length <= 1;
  const consistencyText = isConsistent ? "多源 IP 画像一致" : "多源 IP 情报存在微弱冲突";

  const sourceCount = `${countries.length}/3`;
  const labels = text.signalLabels;

  const isHighRiskCountry = /china|中国|hong\s*kong|russia|iran/i.test(country);

  const signals: SignalResult[] = [
    makeSignalScore("country", labels.country, country, 20, isHighRiskCountry ? 1 : 0, text, config),
    makeSignalScore("proxyCountry", labels.proxyCountry, country, 0, 0, text, config),
    makeSignalScore("ipAddress", labels.ipAddress, detectedIp || "未知", 0, 0, text, config),
    makeSignalScore("browserIpLocation", labels.browserIpLocation, ping0?.location || city || country, 0, 0, text, config),
    makeSignalScore("browserIpAsn", labels.browserIpAsn, asn || "未提供", 0, 0, text, config),
    makeSignalScore("browserIpOrg", labels.browserIpOrg, org || "未知", 0, 0, text, config),
    makeSignalScore(
      "ipCountryRisk",
      labels.ipCountryRisk,
      isHighRiskCountry ? "高风险国家 / 存在风控拦截" : "未命中风险国家",
      15,
      isHighRiskCountry ? 1 : 0,
      text,
      config
    ),
    makeSignalScore("edgeCountry", labels.edgeCountry, cfTrace?.loc || country, 0, 0, text, config),
    makeSignalScore("edgeColo", labels.edgeColo, colo || "自动识别", 0, 0, text, config),
    makeSignalScore("edgeCity", labels.edgeCity, city || "未提供", 0, 0, text, config),
    makeSignalScore("edgeAsn", labels.edgeAsn, asn || "未提供", 0, 0, text, config),
    makeSignalScore("edgeAsOrganization", labels.edgeAsOrganization, org || "未提供", 0, 0, text, config),
    makeSignalScore(
      "networkExitType",
      labels.networkExitType,
      isDatacenter ? "数据中心 / 云厂商" : "住宅宽带 / 原生 ISP",
      13,
      isDatacenter ? 0.7 : 0,
      text,
      config
    ),
    makeSignalScore(
      "ipIntelConsistency",
      labels.ipIntelConsistency,
      consistencyText,
      15,
      isConsistent ? 0 : 0.4,
      text,
      config
    ),
    makeSignalScore("ipIntelSourceCount", labels.ipIntelSourceCount, sourceCount, 0, 0, text, config),
    makeSignalScore("ipCountrySet", labels.ipCountrySet, uniqueCountries.join(", ") || country, 0, 0, text, config),
    makeSignalScore("dnsCheckMode", labels.dnsCheckMode, "综合智能比对", 0, 0, text, config),
    makeSignalScore(
      "dnsExitRegionRisk",
      labels.dnsExitRegionRisk,
      isHighRiskCountry ? "网络出口位于目标风险地区，建议复核" : "出口地区正常",
      6,
      isHighRiskCountry ? 0.8 : 0,
      text,
      config
    ),
    makeSignalScore(
      "dnsProxyConsistencyHint",
      labels.dnsProxyConsistencyHint,
      isConsistent ? "网络画像未见明显冲突" : "网络画像存在潜在地区偏差",
      6,
      isConsistent ? 0 : 0.6,
      text,
      config
    ),
  ];

  const data: NetworkIntelData = {
    ip: detectedIp,
    country,
    city,
    location: ping0?.location || city || country,
    asn,
    org,
    isp,
    colo,
    latitude,
    longitude,
    networkType: isDatacenter ? "数据中心 / 云厂商" : "住宅宽带 / 原生 ISP",
    isDatacenter,
    consistencyStatus: consistencyText,
    sourceCount,
  };

  return { data, signals };
}

export const networkIntelPlugin: DetectionPlugin = {
  id: "networkIntel",
  titleKey: "country",
  source: "server",
  defaultWeight: 20,
  async run({ text, config }) {
    const { signals } = await detectNetworkIntel(text, config);
    return signals;
  },
};
