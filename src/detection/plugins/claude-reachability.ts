// CheckCC 的 Claude 节点连通性与延迟探测插件，用于主动测试主流端点可达性与访问延迟。
import { makeSignalScore } from "../client-engine";
import type { DetectionPlugin } from "../plugin";
import type { SignalResult } from "../types";

async function probeEndpoint(url: string, timeoutMs = 3500): Promise<{ ok: boolean; latencyMs: number | null }> {
  if (typeof window === "undefined" || typeof fetch === "undefined") {
    return { ok: true, latencyMs: 120 };
  }
  const startTime = performance.now();
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    await fetch(url, {
      mode: "no-cors",
      cache: "no-store",
      signal: controller.signal,
    });
    const latency = Math.round(performance.now() - startTime);
    return { ok: true, latencyMs: latency };
  } catch {
    return { ok: false, latencyMs: null };
  } finally {
    window.clearTimeout(timer);
  }
}

export async function detectClaudeReachability(text: any, config: any): Promise<{ signals: SignalResult[]; availableCount: number }> {
  const results = await Promise.all([
    probeEndpoint("https://claude.ai/"),
    probeEndpoint("https://www.anthropic.com/"),
    probeEndpoint("https://api.anthropic.com/"),
  ]);

  const okCount = results.filter((item) => item.ok).length;
  const latencies = results.map((item) => item.latencyMs).filter((val): val is number => typeof val === "number");
  const maxLatency = latencies.length ? Math.max(...latencies) : null;

  const formatEndpointValue = (index: number) => {
    const res = results[index];
    if (!res.ok) return "超时或异常";
    return res.latencyMs != null ? `正常 · ${res.latencyMs}ms` : "正常";
  };

  const statusValue = okCount >= 2 ? "可正常访问" : okCount === 1 ? "部分端点异常" : "主要端点不可达";
  const statusScore = okCount >= 2 ? 0 : okCount === 1 ? 0.5 : 1;

  const latencyValue =
    maxLatency == null
      ? "全部超时"
      : maxLatency < 800
        ? "低延迟"
        : maxLatency < 2200
          ? "中等延迟"
          : "高延迟";
  const latencyScore = maxLatency != null && maxLatency >= 2200 ? 0.5 : maxLatency == null ? 1 : 0;

  const accessRiskValue = okCount >= 2 ? "可正常连接" : okCount === 1 ? "部分端点阻断" : "访问全面受阻";
  const accessRiskScore = okCount >= 2 ? 0 : okCount === 1 ? 0.5 : 1;
  const labels = text.signalLabels;

  const signals: SignalResult[] = [
    makeSignalScore("claudeAiReachability", labels.claudeAiReachability, formatEndpointValue(0), 6, results[0].ok ? 0 : 1, text, config),
    makeSignalScore("anthropicSiteReachability", labels.anthropicSiteReachability, formatEndpointValue(1), 6, results[1].ok ? 0 : 1, text, config),
    makeSignalScore("anthropicApiReachability", labels.anthropicApiReachability, formatEndpointValue(2), 6, results[2].ok ? 0 : 1, text, config),
    makeSignalScore("claudeServiceStatus", labels.claudeServiceStatus, statusValue, 8, statusScore, text, config),
    makeSignalScore("claudeLatencyLevel", labels.claudeLatencyLevel, latencyValue, 4, latencyScore, text, config),
    makeSignalScore("claudeAccessRisk", labels.claudeAccessRisk, accessRiskValue, 10, accessRiskScore, text, config),
  ];

  return { signals, availableCount: okCount };
}

export const claudeReachabilityPlugin: DetectionPlugin = {
  id: "claudeReachability",
  titleKey: "claudeReachability",
  source: "browser",
  defaultWeight: 6,
  async run({ text, config }) {
    const { signals } = await detectClaudeReachability(text, config);
    return signals;
  },
};
