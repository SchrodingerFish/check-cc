// CheckCC 的 WebRTC 真实 IP 泄漏探测插件，用于检测 UDP 候选穿透、公网 IP 泄漏及出口一致性。
import { isPublicIp, makeSignalScore } from "../client-engine";
import type { DetectionPlugin } from "../plugin";
import type { SignalResult } from "../types";

async function queryIpCountry(ip: string): Promise<string | null> {
  if (typeof window === "undefined" || typeof fetch === "undefined") return null;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 2500);

  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
      cache: "no-store",
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.success !== false) {
        return data.country || data.country_code || null;
      }
    }
  } catch {
    // try fallback to ipapi.co
  } finally {
    window.clearTimeout(timer);
  }

  try {
    const fallbackRes = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      cache: "no-store",
    });
    if (fallbackRes.ok) {
      const data = await fallbackRes.json();
      return data.country_name || data.country || null;
    }
  } catch {
    // ignore
  }

  return null;
}

export async function detectWebRtcLeak(
  httpExitCountry: string | null,
  text: any,
  config: any
): Promise<{ publicIps: string[]; country: string | null; signals: SignalResult[] }> {
  const labels = text.signalLabels;

  if (typeof window === "undefined" || !("RTCPeerConnection" in window)) {
    return {
      publicIps: [],
      country: null,
      signals: [
        makeSignalScore("webrtcSupported", labels.webrtcSupported, "浏览器不支持", 0, 0, text, config),
        makeSignalScore("webrtcCandidateStatus", labels.webrtcCandidateStatus, "无法检测", 0, 0, text, config),
        makeSignalScore("webrtcPublicIpLeak", labels.webrtcPublicIpLeak, "未发现公网 IP", 14, 0, text, config),
        makeSignalScore("webrtcLeakIpCount", labels.webrtcLeakIpCount, "0", 0, 0, text, config),
        makeSignalScore("webrtcFirstLeakIp", labels.webrtcFirstLeakIp, "未发现", 0, 0, text, config),
        makeSignalScore("webrtcLeakRegionRisk", labels.webrtcLeakRegionRisk, "无法判断", 10, 0, text, config),
        makeSignalScore("webrtcHttpExitMismatch", labels.webrtcHttpExitMismatch, "无法判断", 8, 0, text, config),
      ],
    };
  }

  const publicIps = new Set<string>();
  let peer: RTCPeerConnection | null = null;

  try {
    peer = new RTCPeerConnection({
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
    });

    await new Promise<void>((resolve) => {
      const timer = window.setTimeout(resolve, 2200);

      peer!.onicecandidate = (event) => {
        const cand = event.candidate?.candidate;
        if (!cand) return;
        const matches = cand.match(/(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9:]{2,}/gi) ?? [];
        for (const candidateIp of matches) {
          if (isPublicIp(candidateIp)) {
            publicIps.add(candidateIp);
          }
        }
      };

      try {
        peer!.createDataChannel("checkcc");
        peer!
          .createOffer()
          .then((offer) => peer!.setLocalDescription(offer))
          .catch(() => resolve());
      } catch {
        resolve();
      }

      window.setTimeout(() => {
        window.clearTimeout(timer);
        resolve();
      }, 2400);
    });
  } catch {
    // WebRTC disabled or blocked by extension
  } finally {
    try {
      peer?.close();
    } catch {}
  }

  const ipList = Array.from(publicIps);
  const firstIp = ipList[0] ?? null;
  const leakedCountry = firstIp ? await queryIpCountry(firstIp) : null;
  const isHighRiskRegion = Boolean(
    leakedCountry && /china|中国|hong\s*kong|russia|iran/i.test(leakedCountry)
  );
  const isExitMismatch = Boolean(
    leakedCountry &&
      httpExitCountry &&
      !leakedCountry.toLowerCase().includes(httpExitCountry.toLowerCase()) &&
      !httpExitCountry.toLowerCase().includes(leakedCountry.toLowerCase())
  );

  const leakValue = ipList.length ? `发现 ${ipList.length} 个公网 IP` : "未发现公网 IP";
  const regionRiskValue = leakedCountry
    ? isHighRiskRegion
      ? `${leakedCountry} · 高风险地区`
      : `${leakedCountry} · 未命中高风险地区`
    : "地区未知";
  const mismatchValue = isExitMismatch ? "不一致" : leakedCountry && httpExitCountry ? "一致" : "无法判断";

  const signals: SignalResult[] = [
    makeSignalScore("webrtcSupported", labels.webrtcSupported, "浏览器支持", 0, 0, text, config),
    makeSignalScore(
      "webrtcCandidateStatus",
      labels.webrtcCandidateStatus,
      ipList.length ? "发现候选地址" : "未发现候选地址",
      0,
      0,
      text,
      config
    ),
    makeSignalScore("webrtcPublicIpLeak", labels.webrtcPublicIpLeak, leakValue, 14, ipList.length > 0 ? 1 : 0, text, config),
    makeSignalScore("webrtcLeakIpCount", labels.webrtcLeakIpCount, String(ipList.length), 0, 0, text, config),
    makeSignalScore("webrtcFirstLeakIp", labels.webrtcFirstLeakIp, firstIp || "未发现", 0, 0, text, config),
    makeSignalScore(
      "webrtcLeakRegionRisk",
      labels.webrtcLeakRegionRisk,
      regionRiskValue,
      10,
      isHighRiskRegion ? 1 : 0,
      text,
      config
    ),
    makeSignalScore(
      "webrtcHttpExitMismatch",
      labels.webrtcHttpExitMismatch,
      mismatchValue,
      8,
      isExitMismatch ? 1 : 0,
      text,
      config
    ),
  ];

  return { publicIps: ipList, country: leakedCountry, signals };
}

export const webrtcPlugin: DetectionPlugin = {
  id: "webrtc",
  titleKey: "webrtc",
  source: "browser",
  defaultWeight: 14,
  async run({ text, config }) {
    const { signals } = await detectWebRtcLeak(null, text, config);
    return signals;
  },
};
