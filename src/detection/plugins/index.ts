// CheckCC 的检测插件注册入口，用于汇总浏览器环境、语言、时区、字体、WebRTC、网络连通与 IP 情报等检测插件。
import type { DetectionPlugin } from "../plugin";
import { browserEnvironmentPlugin } from "./browser-environment";
import { claudeReachabilityPlugin } from "./claude-reachability";
import { emojiStylePlugin } from "./emoji-style";
import { languagePlugin } from "./language";
import { languageVariantPlugin } from "./language-variant";
import { localePlugin } from "./locale";
import { networkIntelPlugin } from "./network-intel";
import { timezonePlugin } from "./timezone";
import { timezoneOffsetPlugin } from "./timezone-offset";
import { webrtcPlugin } from "./webrtc";

export const detectionPlugins: DetectionPlugin[] = [
  timezonePlugin,
  languagePlugin,
  languageVariantPlugin,
  localePlugin,
  timezoneOffsetPlugin,
  emojiStylePlugin,
  browserEnvironmentPlugin,
  claudeReachabilityPlugin,
  webrtcPlugin,
  networkIntelPlugin,
];

export { claudeReachabilityPlugin, webrtcPlugin, networkIntelPlugin };
