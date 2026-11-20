import { useEffect, useMemo, useState } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { db } from '../db/db';
import { startMiaEvaluation } from '../services/miaService';
import { hashObject } from '../domain/hash';
import { HashChip, Empty } from '../ui/widgets';
import { useToast } from '../ui/toast';
import { DEFAULT_MIA_CONFIG, type MiaConfig, type MiaReport, type MiaAttackMethod } from '../domain/mia';

const FPR_OPTIONS = [0.01, 0.05, 0.1];

export default function Membership() {
  const toast = useToast();
  const runs = useLiveQuery(() => db.runs.orderBy('seq').reverse().toArray(), []);
  const reports = useLiveQuery(() => db.miaReports.toArray(), []);
  const [method, setMethod] = useState<MiaAttackMethod>('nn-likelihood');
  const [fprs, setFprs] = useState<number[]>(DEFAULT_MIA_CONFIG.fprTargets);
  const [memberRatio, setMemberRatio] = useState(DEFAULT_MIA_CONFIG.memberRatio);
  const [running, setRunning] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const doneRuns = (runs ?? []).filter((r) => r.status === 'done');
  const currentHashes = useMemo(() => new Map<string, string>(), []);
  const [hashVersion, setHashVersion] = useState(0);

  const toggleFpr = (v: number) => setFprs((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v].sort((a, b) => a - b)));

  const run = async (runId: string) => {
    if (fprs.length === 0) { toast('至少选择一个固定误报率工作点', 'bad'); return; }
    setRunning(runId);
    const overrides: Partial<MiaConfig> = { method, fprTargets: fprs, memberRatio };
    const res = await startMiaEvaluation({ runId, configOverrides: overrides });
    setRunning(null);
    if (res.ok) {
      const anyDetected = res.report.attacks.some((a) => !a.noDetection);
      toast(`成员推断评估完成：${anyDetected ? '检出可区分信号' : '本次未检出统计可区分信号（非零风险结论）'}`, anyDetected ? 'bad' : 'ok');
      setSelected(res.report.id);
      setHashVersion((v) => v + 1);
    } else toast(res.error, 'bad');
  };

  return (
    <div>
      <h1 className="page-title">成员推断风险评估</h1>
      <p className="page-sub">
        按人员/家庭主体（同一来电或同址事件聚合）切分源成员集与未参与生成的对照集，将合成包交给模拟攻击器，
        报告固定误报率下的识别能力、推断优势与置信区间。同一家庭的多起事件整体归属一侧，不跨成员/对照。
      </p>

      <div className="card">
        <h3>攻击配置</h3>
        <table className="data">
          <tbody>
            <tr>
              <td className="small">攻击路线</td>
              <td className="small">
                <label style={{ marginRight: 16 }}>
                  <input type="radio" checked={method === 'nn-likelihood'} onChange={() => setMethod('nn-likelihood')} />
                  {' '}最近邻距离 + 属性似然（轻量、易复现、对近复制敏感）
                </label>
                <label>
                  <input type="radio" checked={method === 'shadow'} onChange={() => setMethod('shadow')} />
                  {' '}影子生成器分类器（{DEFAULT_MIA_CONFIG.shadowGroups} 组影子训练，更强但成本更高）
                </label>
              </td>
            </tr>
            <tr>
              <td className="small">固定误报率工作点</td>
              <td className="small">
                {FPR_OPTIONS.map((v) => (
                  <label key={v} style={{ marginRight: 14 }}>
                    <input type="checkbox" checked={fprs.includes(v)} onChange={() => toggleFpr(v)} /> FPR≤{(v * 100).toFixed(0)}%
                  </label>
                ))}
              </td>
            </tr>
            <tr>
              <td className="small">成员侧占比</td>
              <td className="small">
                <input type="range" min={0.3} max={0.7} step={0.1} value={memberRatio} onChange={(e) => setMemberRatio(Number(e.target.value))} />
                {' '}{(memberRatio * 100).toFixed(0)}% 成员 / {((1 - memberRatio) * 100).toFixed(0)}% 对照（按主体整分）
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>对已完成运行执行评估</h3>
        {doneRuns.length === 0 ? <Empty text="尚无已完成运行" /> : (
          <table className="data">
            <thead><tr><th>运行</th><th>路线</th><th>规模</th><th>批次快照</th><th></th></tr></thead>
            <tbody>
              {doneRuns.map((r) => (
                <tr key={r.id}>
                  <td>{r.id}</td>
                  <td>{r.method === 'constraint' ? '约束驱动' : '分布+筛选'}</td>
                  <td>{r.targetEvents}</td>
                  <td>{r.batchKey}</td>
                  <td>
                    <button className="primary" disabled={running !== null} onClick={() => void run(r.id)}>
                      {running === r.id ? '评估中…' : '执行成员推断评估'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {!reports?.length ? <div className="card"><Empty text="尚无成员推断评估报告" /></div> : reports
        .slice()
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .map((r) => (
          <ReportCard key={r.id} report={r} selected={selected === r.id} onToggle={() => setSelected(selected === r.id ? null : r.id)} hashVersion={hashVersion} currentHashes={currentHashes} />
        ))}
    </div>
  );
}

function ReportCard({ report, selected, onToggle, hashVersion, currentHashes }: {
  report: MiaReport;
  selected: boolean;
  onToggle: () => void;
  hashVersion: number;
  currentHashes: Map<string, string>;
}) {
  const runs = useLiveQuery(() => db.runs.get(report.runId), [report.runId]);
  const outputs = useLiveQuery(() => db.runOutputs.get(report.runId), [report.runId]);
  const [currentHash, setCurrentHash] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!outputs) { setCurrentHash(null); return; }
      const cached = currentHashes.get(report.runId);
      if (cached) { if (!cancelled) setCurrentHash(cached); return; }
      const h = await hashObject(outputs.tables);
      currentHashes.set(report.runId, h);
      if (!cancelled) setCurrentHash(h);
    })();
    return () => { cancelled = true; };
    // hashVersion 变化时允许重新计算（运行输出不可变，正常情况下哈希恒定）
  }, [outputs, report.runId, currentHashes, hashVersion]);

  const stale = currentHash != null && currentHash !== report.packageHash;

  return (
    <div className="card">
      <div className="btn-row" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>{report.id} <span className="muted">（{report.runId}）</span></h3>
        <div className="btn-row">
          {stale
            ? <span className="badge bad">包已更新·报告失效</span>
            : <span className="badge ok">哈希绑定有效</span>}
          <button onClick={onToggle}>{selected ? '收起' : '查看报告'}</button>
        </div>
      </div>
      <div className="small muted" style={{ marginTop: 6 }}>
        {new Date(report.createdAt).toLocaleString()} · 合成包哈希 <HashChip text={report.packageHash} len={16} />
        {stale && <> · 当前包哈希 <HashChip text={currentHash ?? ''} len={16} />（请对新包重新评估）</>}
        {runs && <> · {runs.method === 'constraint' ? '约束驱动' : '分布+筛选'}路线</>}
      </div>
      {selected && <MiaReportView report={report} />}
    </div>
  );
}

function MiaReportView({ report }: { report: MiaReport }) {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="card" style={{ background: '#fafbfe' }}>
        <h4>主体切分（按人员/家庭，不跨侧）</h4>
        <table className="data">
          <tbody>
            <tr><td className="small">成员侧主体</td><td className="small">{report.split.memberCount}</td>
              <td className="small">对照侧主体</td><td className="small">{report.split.controlCount}</td></tr>
            <tr><td className="small">实际成员占比</td><td className="small">{(report.split.memberRatio * 100).toFixed(1)}%</td>
              <td className="small">链接构成</td>
              <td className="small">{Object.entries(report.split.linkKinds).map(([k, n]) => `${linkLabel(k)} ${n}`).join(' / ')}</td></tr>
          </tbody>
        </table>
        <p className="small muted" style={{ marginBottom: 0 }}>
          镜像审计包：{report.mirror.method === 'constraint' ? '约束驱动' : '分布+筛选'}路线，
          仅用成员侧 {report.mirror.memberSourceEvents} 起事件训练（种子 {report.mirror.seed}，目标 {report.mirror.targetEvents}），
          镜像包哈希 <HashChip text={report.mirror.packageHash} len={16} />。
          成员/对照标签在镜像包上具有真值；真实发布包无真值非成员，只做描述性近复制扫描。
        </p>
      </div>

      {report.attacks.map((a) => (
        <div key={a.method} className="card" style={{ background: '#fafbfe' }}>
          <div className="btn-row" style={{ justifyContent: 'space-between' }}>
            <h4 style={{ margin: 0 }}>{a.method === 'nn-likelihood' ? '攻击①最近邻距离 + 属性似然' : '攻击②影子生成器分类器'}</h4>
            {a.noDetection
              ? <span className="badge warn">本次未检出（非零风险结论）</span>
              : <span className="badge bad">检出可区分信号</span>}
          </div>
          {a.note && <p className="small muted">{a.note}</p>}
          <p className="small">
            AUC = <b>{a.auc.toFixed(3)}</b>（95% CI {a.aucCi.low.toFixed(3)} ~ {a.aucCi.high.toFixed(3)}）
            · 成员 {a.memberCount} / 对照 {a.controlCount}
          </p>
          <table className="data">
            <thead>
              <tr><th>目标 FPR</th><th>实际 FPR (CI)</th><th>TPR (95% CI)</th><th>推断优势 TPR−FPR</th><th>阈值</th><th>功效</th></tr>
            </thead>
            <tbody>
              {a.points.map((p) => (
                <tr key={p.fprTarget}>
                  <td className="small">≤{(p.fprTarget * 100).toFixed(0)}%</td>
                  <td className="small">{p.fpr.toFixed(3)}（{p.fprCi.low.toFixed(3)}~{p.fprCi.high.toFixed(3)}）</td>
                  <td className="small">{p.tpr.toFixed(3)}（{p.tprCi.low.toFixed(3)}~{p.tprCi.high.toFixed(3)}）</td>
                  <td className="small">
                    <span className={`badge ${p.advantage > 0 ? 'bad' : ''}`}>{p.advantage.toFixed(3)}</span>
                  </td>
                  <td className="small mono">{p.threshold}</td>
                  <td className="small">{p.underpowered ? <span className="badge warn">样本不足</span> : '正常'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h4 style={{ marginTop: 12 }}>高风险人群分层</h4>
          <table className="data">
            <thead><tr><th>分层</th><th>成员/对照</th><th>结论</th></tr></thead>
            <tbody>
              {a.strata.map((s) => (
                <tr key={s.stratum}>
                  <td className="small">{s.label}</td>
                  <td className="small">{s.memberCount} / {s.controlCount}</td>
                  <td className="small">
                    {s.points === null
                      ? <span className="muted">{s.note}</span>
                      : s.points.map((p) => `FPR≤${(p.fprTarget * 100).toFixed(0)}%: TPR ${p.tpr.toFixed(2)} / 优势 ${p.advantage.toFixed(2)}`).join('；')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      <div className="card" style={{ background: '#fafbfe' }}>
        <h4>真实发布包近复制扫描（描述性，不作识别能力指标）</h4>
        <table className="data">
          <thead><tr><th>主体</th><th>源事件</th><th>最近合成事件</th><th>距离</th></tr></thead>
          <tbody>
            {report.releasedPackageScan.nearReplicationEvidence.slice(0, 5).map((e, i) => (
              <tr key={i}>
                <td className="small mono">{e.subjectId}</td>
                <td className="small mono">{e.eventId}</td>
                <td className="small mono">{e.nearestSyntheticEventId}</td>
                <td className="small">{e.distance.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small muted" style={{ marginBottom: 0 }}>{report.releasedPackageScan.note}</p>
      </div>

      {report.notes.length > 0 && (
        <div className="notice info small"><b>执行备注：</b>{report.notes.join('；')}</div>
      )}
      <div className="notice info small"><b>评估范围声明：</b>{report.disclaimer}</div>
    </div>
  );
}

function linkLabel(kind: string): string {
  if (kind === 'caller_phone') return '来电链接';
  if (kind === 'address_text') return '同址链接';
  return '单事件主体';
}
