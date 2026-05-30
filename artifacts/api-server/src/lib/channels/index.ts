export type { ChannelAdapter, ChannelEnvelope, DispatchResult } from "./types";
export {
  buildChannelsFromEnv,
  selectChannels,
  severityRank,
  type ChannelConfig,
} from "./router";
export {
  initChannels,
  dispatchAlertFromLedger,
  __setChannelsForTest,
  __resetChannelsForTest,
  __drainChannelsForTest,
} from "./dispatch";
export {
  buildSignatureBase,
  signWebhookBody,
  verifyWebhookSignature,
} from "./adapters/webhook";
