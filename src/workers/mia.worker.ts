// 成员推断评估 Worker：在后台线程执行主体切分、镜像生成器与攻击指标计算。

import { evaluateMembership, type MiaEvalInput, type MiaConfig } from '../domain/mia';

self.onmessage = async (e: MessageEvent) => {
  const msg = e.data;
  if (msg?.type !== 'mia') return;
  try {
    const payload = msg.payload as MiaEvalInput & { config?: Partial<MiaConfig> };
    const result = await evaluateMembership(payload);
    (self as unknown as Worker).postMessage({ type: 'done', result });
  } catch (err) {
    (self as unknown as Worker).postMessage({ type: 'error', error: err instanceof Error ? err.message : String(err) });
  }
};
