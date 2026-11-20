// 成员推断评估编排：WebWorker 中执行主体切分、镜像生成器与攻击评估，报告落库。
// 报告绑定被评估合成包的实算哈希；包更新（新运行输出）后哈希不同，旧报告不覆盖、不复用。

import { db, nextSeq } from '../db/db';
import type { TableRows } from '../domain/types';
import type { MiaConfig, MiaReport } from '../domain/mia';
import { hashObject } from '../domain/hash';
import { getRunOutput } from './runService';
export interface MiaStartInput {
  runId: string;
  configOverrides?: Partial<MiaConfig>;
}

export async function startMiaEvaluation(input: MiaStartInput): Promise<{ ok: true; report: MiaReport } | { ok: false; error: string }> {
  const run = await db.runs.get(input.runId);
  if (!run) return { ok: false, error: '运行不存在' };
  if (run.status !== 'done') return { ok: false, error: '运行尚未完成' };
  const syn = await getRunOutput(input.runId);
  const src = (await db.batchRows.get(run.batchKey))?.tables;
  if (!syn || !src) return { ok: false, error: '缺少合成输出或来源批次数据' };

  try {
    const body = await runMiaWorker(run.id, syn, src, run.planSnapshot, run.ruleSetSnapshot, input.configOverrides);
    // 哈希绑定校验：报告内包哈希必须与当前输出实算一致
    const currentHash = await hashObject(syn);
    if (body.packageHash !== currentHash) {
      return { ok: false, error: '合成包哈希与报告绑定值不一致，评估结果作废' };
    }
    const seq = await nextSeq('miaSeq');
    const report: MiaReport = {
      ...body,
      id: `MIA-${String(seq).padStart(4, '0')}`,
      createdAt: new Date().toISOString()
    };
    await db.miaReports.put(report);
    return { ok: true, report };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function runMiaWorker(
  runId: string,
  syn: TableRows,
  src: TableRows,
  plan: Parameters<typeof import('../domain/mia')['evaluateMembership']>[0]['plan'],
  ruleSet: Parameters<typeof import('../domain/mia')['evaluateMembership']>[0]['ruleSet'],
  configOverrides?: Partial<MiaConfig>
): Promise<Omit<MiaReport, 'id' | 'createdAt'>> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/mia.worker.ts', import.meta.url), { type: 'module' });
    // 影子路线含多台生成器训练，给更宽的超时
    const timer = setTimeout(() => { worker.terminate(); reject(new Error('成员推断评估超时（180s）')); }, 180_000);
    worker.onmessage = (e) => {
      const msg = e.data;
      if (msg.type === 'done') { clearTimeout(timer); worker.terminate(); resolve(msg.result); }
      else if (msg.type === 'error') { clearTimeout(timer); worker.terminate(); reject(new Error(msg.error)); }
    };
    worker.onerror = (e) => { clearTimeout(timer); worker.terminate(); reject(new Error(e.message)); };
    worker.postMessage({ type: 'mia', payload: { runId, syn, src, plan, ruleSet, config: configOverrides } });
  });
}
