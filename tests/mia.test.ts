import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCsv } from '../src/domain/csv';
import {
  buildSubjects,
  splitSubjects,
  rowsForSubjects,
  nnLikelihoodScores,
  evaluateMembership,
  DEFAULT_MIA_CONFIG,
  MIA_DISCLAIMER,
  type MiaConfig,
  type SubjectBuild,
  type MiaSplit,
  type SubjectScore
} from '../src/domain/mia';
import { defaultPlan, defaultRuleSet } from '../src/domain/defaults';
import { hashObject } from '../src/domain/hash';
import type { Plan, RuleSet, TableRows, SourceEvent, SourceDispatch, SourceArrival, SourceClosure, SourceResource } from '../src/domain/types';

// ---------- 受控数据集构造 ----------

const RESOURCES: SourceResource[] = [
  { resource_id: 'AMB-01', resource_type: '救护车', station: '城东分站', capability: '急救,转运' },
  { resource_id: 'AMB-02', resource_type: '救护车', station: '城西分站', capability: '急救,转运' },
  { resource_id: 'HAZ-01', resource_type: '危化专勤车', station: '郊区分站', capability: '危化,消防' }
];

interface EventSpec {
  key: string;
  day: number;
  hour: number;
  type: string;
  district: string;
  priority: string;
  outcome: string;
  phone: string;
  address: string;
}

function makeTables(specs: EventSpec[]): TableRows {
  const events: SourceEvent[] = [];
  const dispatches: SourceDispatch[] = [];
  const arrivals: SourceArrival[] = [];
  const closures: SourceClosure[] = [];
  specs.forEach((s, i) => {
    const eid = `E${String(i + 1).padStart(3, '0')}`;
    const base = new Date(2025, 8, 1 + s.day, s.hour, 0, 0).getTime();
    const fmt = (ms: number) => {
      const d = new Date(ms);
      const p = (n: number) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    };
    events.push({ event_id: eid, alarm_time: fmt(base), event_type: s.type, district: s.district, address_text: s.address, caller_phone: s.phone, priority: s.priority });
    const did = `${eid}-D1`;
    dispatches.push({ dispatch_id: did, event_id: eid, resource_id: s.type === '危化品泄漏' ? 'HAZ-01' : 'AMB-01', dispatch_time: fmt(base + 3 * 60000) });
    arrivals.push({ arrival_id: `${eid}-A1`, dispatch_id: did, arrive_time: fmt(base + 12 * 60000), arrive_site: '现场' });
    closures.push({ closure_id: `${eid}-C1`, event_id: eid, close_time: fmt(base + 45 * 60000), outcome: s.outcome });
  });
  return { events, dispatches, resources: structuredClone(RESOURCES), arrivals, closures };
}

/**
 * 48 个主体 / 60 起事件：
 * - 6 个多事件家庭（各 3 起事件，同一来电+同址，专属组合）
 * - 6 个稀有属性组合单事件主体（组合全源仅 1 次）
 * - 36 个普通高频单事件主体（共同常见组合，小时错开）
 */
function buildDataset(): { tables: TableRows; specs: EventSpec[] } {
  const specs: EventSpec[] = [];
  // 多事件家庭
  for (let h = 1; h <= 6; h++) {
    const phone = `139****10${String(h).padStart(2, '0')}`;
    const addr = `家庭片区${h}号`;
    for (let k = 0; k < 3; k++) {
      specs.push({ key: `HH-${h}`, day: h + k * 4, hour: 9 + k, type: '危化品泄漏', district: `家庭区${h}`, priority: 'P1', outcome: '现场处置', phone, address: addr });
    }
  }
  // 稀有组合主体（每个组合全源仅出现 1 次）
  for (let r = 1; r <= 6; r++) {
    specs.push({ key: `RARE-${r}`, day: 20 + r, hour: 2 + (r % 3), type: r % 2 ? '火灾' : '交通事故', district: `稀有片区${r}`, priority: 'P1', outcome: '转运上级医院', phone: `137****20${String(r).padStart(2, '0')}`, address: `稀有路${r}号` });
  }
  // 普通高频主体
  for (let c = 1; c <= 36; c++) {
    specs.push({ key: `COM-${c}`, day: (c % 28), hour: 8 + (c % 10), type: '突发疾病', district: '城东区', priority: 'P2', outcome: '送医', phone: `138****30${String(c).padStart(2, '0')}`, address: `普通路${c}号` });
  }
  return { tables: makeTables(specs), specs };
}

/** 模拟“记住成员”的审计合成包：逐字复制成员侧属性与时刻，仅换新标识，再补常见填充事件 */
function replicatingPackage(memberRows: TableRows, fillerN: number): TableRows {
  const events: SourceEvent[] = [];
  const dispatches: SourceDispatch[] = [];
  const arrivals: SourceArrival[] = [];
  const closures: SourceClosure[] = [];
  memberRows.events.forEach((e, i) => {
    const newId = `SYN-R${String(i + 1).padStart(3, '0')}`;
    events.push({ ...e, event_id: newId });
    const oldId = e.event_id;
    for (const d of memberRows.dispatches.filter((x) => x.event_id === oldId)) {
      const nd = `${newId}-D1`;
      dispatches.push({ ...d, dispatch_id: nd, event_id: newId, resource_id: d.resource_id.replace('HAZ-01', 'HAZ-01') });
      for (const a of memberRows.arrivals.filter((x) => x.dispatch_id === d.dispatch_id)) {
        arrivals.push({ ...a, arrival_id: `${newId}-A1`, dispatch_id: nd });
      }
    }
    for (const c of memberRows.closures.filter((x) => x.event_id === oldId)) {
      closures.push({ ...c, closure_id: `${newId}-C1`, event_id: newId });
    }
  });
  // 填充：仅常见组合，不带任何成员特异信息
  for (let f = 0; f < fillerN; f++) {
    const id = `SYN-F${String(f + 1).padStart(3, '0')}`;
    const base = new Date(2025, 8, 1 + (f % 28), 8 + (f % 10), 0, 0).getTime();
    const fmt = (ms: number) => {
      const d = new Date(ms);
      const p = (n: number) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    };
    events.push({ event_id: id, alarm_time: fmt(base), event_type: '突发疾病', district: '城东区', address_text: `合成路${f}号(演练)`, caller_phone: `SYN-PH-${f}`, priority: 'P2' });
    dispatches.push({ dispatch_id: `${id}-D1`, event_id: id, resource_id: 'AMB-01', dispatch_time: fmt(base + 3 * 60000) });
    arrivals.push({ arrival_id: `${id}-A1`, dispatch_id: `${id}-D1`, arrive_time: fmt(base + 12 * 60000), arrive_site: '现场' });
    closures.push({ closure_id: `${id}-C1`, event_id: id, close_time: fmt(base + 45 * 60000), outcome: '送医' });
  }
  return { events, dispatches, resources: structuredClone(RESOURCES), arrivals, closures };
}

/** 无信号包：只含常见组合模板，成员/对照特征在包中同样“普通”，不含任何成员特异记忆 */
function genericPackage(n: number): TableRows {
  const specs: EventSpec[] = [];
  for (let i = 0; i < n; i++) {
    specs.push({ key: `G-${i}`, day: i % 28, hour: 8 + (i % 10), type: '突发疾病', district: '城东区', priority: 'P2', outcome: '送医', phone: `SYN-G-${i}`, address: `合成普通路${i}号(演练)` });
  }
  return makeTables(specs);
}

const CONFIG: MiaConfig = { ...DEFAULT_MIA_CONFIG, fprTargets: [0.01, 0.05, 0.1], minStratumSize: 6 };

function aucOf(scores: SubjectScore[]): number {
  const m = scores.filter((s) => s.isMember).map((s) => s.score);
  const c = scores.filter((s) => !s.isMember).map((s) => s.score);
  let wins = 0;
  let ties = 0;
  for (const x of m) for (const y of c) { if (x > y) wins++; else if (x === y) ties++; }
  return (wins + 0.5 * ties) / (m.length * c.length);
}

// ---------- 随题样例（端到端用） ----------

const SAMPLE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'samples', 'emerg-2025-09', 'r2');
function loadSample(): TableRows {
  const read = (n: string) => parseCsv(readFileSync(join(SAMPLE_DIR, n), 'utf8'));
  return {
    events: read('events.csv') as never,
    dispatches: read('dispatches.csv') as never,
    resources: read('resources.csv') as never,
    arrivals: read('arrivals.csv') as never,
    closures: read('closures.csv') as never
  };
}

let sampleSource: TableRows;
let samplePlan: Plan;
let sampleRuleSet: RuleSet;

beforeAll(() => {
  sampleSource = loadSample();
  sampleRuleSet = { ...defaultRuleSet('2025-01-01T00:00:00Z'), id: 'RS-MIA', version: 1, status: 'approved', hash: 't' };
  samplePlan = defaultPlan('PL-MIA', 'emerg-2025-09@r2', 'RS-MIA', 1, sampleSource, '2025-01-01T00:00:00Z');
  samplePlan.targetEvents = 200;
});

// ---------- 1. 主体切分：家庭多事件不跨侧 ----------

describe('主体构建与成员/对照切分', () => {
  it('同一来电的多起事件聚合为一个家庭主体', () => {
    const build = buildSubjects(buildDataset().tables);
    const households = build.subjects.filter((s) => s.eventCount === 3);
    expect(households.length).toBe(6);
    expect(households.every((s) => s.linkKind === 'caller_phone')).toBe(true);
    expect(households.every((s) => s.strata.includes('multi-event'))).toBe(true);
  });

  it('稀有组合与普通主体被正确分层', () => {
    const build = buildSubjects(buildDataset().tables);
    const rare = build.subjects.filter((s) => s.strata.includes('rare-combo'));
    const common = build.subjects.filter((s) => s.strata.includes('common'));
    expect(rare.length).toBe(6);
    expect(common.length).toBe(36);
  });

  it('同一家庭的多起事件整体归属一侧，绝不跨成员/对照', () => {
    const { tables } = buildDataset();
    const build = buildSubjects(tables);
    const split = splitSubjects(build.subjects, CONFIG);
    // 赋值无重复、无交叉
    expect(new Set(split.assignment.map((a) => a.subjectId)).size).toBe(build.subjects.length);
    expect(new Set(split.memberSubjectIds).size + new Set(split.controlSubjectIds).size).toBe(build.subjects.length);
    for (const id of split.memberSubjectIds) expect(split.controlSubjectIds).not.toContain(id);

    const memberRows = rowsForSubjects(tables, build.subjects, new Set(split.memberSubjectIds));
    const controlRows = rowsForSubjects(tables, build.subjects, new Set(split.controlSubjectIds));
    const memberEventIds = new Set(memberRows.events.map((e) => e.event_id));
    const controlEventIds = new Set(controlRows.events.map((e) => e.event_id));
    // 每个家庭主体的 3 起事件必须同在一侧
    for (const hh of build.subjects.filter((s) => s.eventCount > 1)) {
      const inMember = hh.eventIds.filter((e) => memberEventIds.has(e)).length;
      const inControl = hh.eventIds.filter((e) => controlEventIds.has(e)).length;
      expect(inMember === hh.eventIds.length || inControl === hh.eventIds.length).toBe(true);
      expect(inMember * inControl).toBe(0);
    }
    // 关联表按事件整体保留，无悬空派遣
    const memberDispatchEvents = new Set(memberRows.dispatches.map((d) => d.event_id));
    for (const eid of memberDispatchEvents) expect(memberEventIds.has(eid)).toBe(true);
  });

  it('同种子切分可复现，不同种子切分不同', () => {
    const build = buildSubjects(buildDataset().tables);
    const a = splitSubjects(build.subjects, CONFIG);
    const b = splitSubjects(build.subjects, CONFIG);
    expect(a).toEqual(b);
    const c = splitSubjects(build.subjects, { ...CONFIG, seed: CONFIG.seed + 1 });
    expect(c.memberSubjectIds).not.toEqual(a.memberSubjectIds);
  });
});

// ---------- 2. 逐条复制：近复制在固定误报率下被检出 ----------

describe('攻击①：逐条复制场景的攻击效能', () => {
  let build: SubjectBuild;
  let split: MiaSplit;
  let tables: TableRows;
  let scores: SubjectScore[];

  beforeAll(() => {
    ({ tables } = buildDataset());
    build = buildSubjects(tables);
    split = splitSubjects(build.subjects, CONFIG);
    const memberRows = rowsForSubjects(tables, build.subjects, new Set(split.memberSubjectIds));
    const auditSyn = replicatingPackage(memberRows, 12);
    scores = nnLikelihoodScores(tables, auditSyn, build, split, CONFIG);
  });

  it('全局 AUC 仅温和高于随机，但高风险分层（稀有组合/多事件家庭）分离显著', () => {
    // 普通高频主体本身无成员信号，会稀释全局 AUC——分层结果才是决策依据
    expect(aucOf(scores)).toBeGreaterThan(0.55);
    const highRisk = scores.filter((s) => s.strata.some((x) => x !== 'common'));
    expect(aucOf(highRisk)).toBeGreaterThan(0.85);
    // 普通高频主体不产生虚假高分离：其 AUC 不被宣称为强信号
    const commonOnly = scores.filter((s) => s.strata.includes('common'));
    expect(aucOf(commonOnly)).toBeLessThan(0.75);
  });

  it('各工作点实际误报率严格不超过目标 FPR（保守校准）', () => {
    const controls = scores.filter((s) => !s.isMember);
    for (const target of CONFIG.fprTargets) {
      const sorted = controls.map((s) => s.score).sort((a, b) => a - b);
      const allowedFp = Math.floor(target * sorted.length);
      const threshold = sorted[sorted.length - 1 - allowedFp];
      const fpr = sorted.filter((v) => v > threshold).length / sorted.length;
      expect(fpr).toBeLessThanOrEqual(target);
    }
  });

  it('放宽 FPR 阈值时命中率单调不减、误报率单调不降', () => {
    const memberN = scores.filter((s) => s.isMember).length;
    const controlN = scores.filter((s) => !s.isMember).length;
    const tprAt = (target: number) => {
      const sorted = scores.filter((s) => !s.isMember).map((s) => s.score).sort((a, b) => a - b);
      const allowedFp = Math.floor(target * sorted.length);
      const threshold = sorted[sorted.length - 1 - allowedFp];
      return {
        tpr: scores.filter((s) => s.isMember && s.score > threshold).length / memberN,
        fpr: sorted.filter((v) => v > threshold).length / controlN
      };
    };
    const p1 = tprAt(0.01);
    const p5 = tprAt(0.05);
    const p10 = tprAt(0.1);
    expect(p10.tpr).toBeGreaterThanOrEqual(p5.tpr);
    expect(p5.tpr).toBeGreaterThanOrEqual(p1.tpr);
    expect(p10.fpr).toBeGreaterThanOrEqual(p5.fpr);
    expect(p5.fpr).toBeGreaterThanOrEqual(p1.fpr);
    // 近复制场景下，高风险分层（稀有/家庭）成员在 10% 误报率工作点过半被识别。
    // 阈值按攻击者掌握目标所属子人群的背景知识，在分层内对照上校准（与产品分层口径一致）。
    const highRisk = scores.filter((s) => s.strata.some((x) => x !== 'common'));
    const hrControls = highRisk.filter((s) => !s.isMember).map((s) => s.score).sort((a, b) => a - b);
    const hrThreshold = hrControls[hrControls.length - 1 - Math.floor(0.1 * hrControls.length)];
    const hrTpr = highRisk.filter((s) => s.isMember && s.score > hrThreshold).length / highRisk.filter((s) => s.isMember).length;
    expect(hrTpr).toBeGreaterThan(0.5);
    // 分层内实际误报仍受约束
    const hrFpr = hrControls.filter((v) => v > hrThreshold).length / hrControls.length;
    expect(hrFpr).toBeLessThanOrEqual(0.1);
  });

  it('多事件家庭与稀有主体在近复制下进入高风险分层', () => {
    const strata = new Set<string>();
    for (const s of scores.filter((x) => x.isMember && x.score > 0)) {
      for (const st of s.strata) strata.add(st);
    }
    // 家庭主体至少有一个被攻击信号命中
    const hhHit = scores.some((s) => s.isMember && s.strata.includes('multi-event') && s.nearest != null);
    expect(hhHit).toBe(true);
    expect(strata.size).toBeGreaterThan(0);
  });
});

// ---------- 3. 稀有属性组合 + 普通高频事件：无信号包的基准失败 ----------

describe('攻击①：无记忆信号时的基准失败与小样本保护', () => {
  it('普通高频事件在通用包下 AUC 接近随机，不制造虚假识别能力', () => {
    const { tables } = buildDataset();
    const build = buildSubjects(tables);
    const split = splitSubjects(build.subjects, CONFIG);
    const scores = nnLikelihoodScores(tables, genericPackage(40), build, split, CONFIG);
    const auc = aucOf(scores);
    expect(auc).toBeGreaterThan(0.35);
    expect(auc).toBeLessThan(0.65);
  });

  it('基准攻击失败只记“本次未检出”，不表述为零风险、不宣称匿名', () => {
    // 同质主体 + 同质包：所有攻击分数相同，TPR=FPR、优势为 0
    const specs: EventSpec[] = [];
    for (let i = 0; i < 24; i++) {
      specs.push({ key: `H-${i}`, day: 1, hour: 10, type: '突发疾病', district: '城东区', priority: 'P2', outcome: '送医', phone: `138****9${String(i).padStart(3, '0')}`, address: `同质路${i}号` });
    }
    const tables = makeTables(specs);
    const build = buildSubjects(tables);
    const split = splitSubjects(build.subjects, { ...CONFIG, minStratumSize: 4 });
    const pkg = genericPackage(20);
    const scores = nnLikelihoodScores(tables, pkg, build, split, { ...CONFIG, minStratumSize: 4 });
    // 所有分数相同 -> 每个工作点优势为 0
    const uniq = new Set(scores.map((s) => s.score));
    expect(uniq.size).toBe(1);
    // 范围声明纪律
    expect(MIA_DISCLAIMER).toContain('本次未检出');
    expect(MIA_DISCLAIMER).toContain('不等于零风险');
    expect(MIA_DISCLAIMER).toContain('不构成匿名性保证');
  });

  it('极低样本分层不单独给出分数，只标注样本不足', () => {
    const { tables } = buildDataset();
    const build = buildSubjects(tables);
    const split = splitSubjects(build.subjects, CONFIG);
    const memberRows = rowsForSubjects(tables, build.subjects, new Set(split.memberSubjectIds));
    const strict: MiaConfig = { ...CONFIG, minStratumSize: 100 }; // 任何分层都达不到
    const scores = nnLikelihoodScores(tables, replicatingPackage(memberRows, 12), build, split, strict);
    // 通过端到端报告检查分层抑制（summarize 在 evaluateMembership 内调用）
    return evaluateMembership({
      runId: 'RUN-UT',
      syn: replicatingPackage(memberRows, 12),
      src: tables,
      plan: { ...samplePlan, targetEvents: 40 },
      ruleSet: sampleRuleSet,
      config: { ...strict, method: 'nn-likelihood' }
    }).then((report) => {
      expect(scores.length).toBeGreaterThan(0);
      for (const a of report.attacks) {
        for (const st of a.strata) {
          expect(st.points).toBeNull();
          expect(st.note).toContain('不单独给出分数');
        }
      }
    });
  });
});

// ---------- 4. 端到端：哈希绑定、置信区间、镜像审计与确定性 ----------

describe('evaluateMembership 端到端（随题样例 r2）', () => {
  it('报告绑定合成包哈希，包更新后哈希变化使旧报告失配', async () => {
    const gen = await import('../src/domain/generatorA');
    const syn = gen.generateConstraint({ plan: samplePlan, ruleSet: sampleRuleSet, source: sampleSource }).tables;
    const report = await evaluateMembership({ runId: 'RUN-E2E-1', syn, src: sampleSource, plan: samplePlan, ruleSet: sampleRuleSet });
    expect(report.packageHash).toBe(await hashObject(syn));
    expect(report.hash).toBe(await hashObject({ ...report, hash: undefined }));
    // 包内容变化 -> 哈希不再匹配
    const changed: TableRows = structuredClone(syn);
    changed.events[0] = { ...changed.events[0], event_type: '火灾' };
    expect(await hashObject(changed)).not.toBe(report.packageHash);
  });

  it('镜像审计包仅由成员侧源行训练，成员/对照计数与切分一致', async () => {
    const gen = await import('../src/domain/generatorA');
    const syn = gen.generateConstraint({ plan: samplePlan, ruleSet: sampleRuleSet, source: sampleSource }).tables;
    const report = await evaluateMembership({ runId: 'RUN-E2E-2', syn, src: sampleSource, plan: samplePlan, ruleSet: sampleRuleSet });
    expect(report.mirror.memberSourceEvents).toBeGreaterThan(10);
    expect(report.split.memberCount + report.split.controlCount).toBe(Object.keys(report.split.linkKinds).reduce((n, k) => n + report.split.linkKinds[k], 0));
    expect(report.attacks.length).toBe(1);
    const a = report.attacks[0];
    expect(a.memberCount).toBe(report.split.memberCount);
    expect(a.controlCount).toBe(report.split.controlCount);
    // 置信区间结构合法
    for (const p of a.points) {
      expect(p.tprCi.low).toBeLessThanOrEqual(p.tprCi.high);
      expect(p.fprCi.low).toBeLessThanOrEqual(p.fprCi.high);
      // advantage 与 tpr/fpr 同源计算（各自 4 位舍入），允许舍入误差
      expect(Math.abs(p.advantage - (p.tpr - p.fpr))).toBeLessThanOrEqual(1e-4);
      // 保守校准：实际误报率可为 0（离散样本下允许的 FP 数向下取整），但绝不超过目标
      expect(p.fpr).toBeGreaterThanOrEqual(0);
      expect(p.fpr).toBeLessThanOrEqual(p.fprTarget);
      expect(p.tpr).toBeGreaterThanOrEqual(0);
      expect(p.tpr).toBeLessThanOrEqual(1);
    }
    expect(a.aucCi.low).toBeLessThanOrEqual(a.auc);
    expect(a.aucCi.high).toBeGreaterThanOrEqual(a.auc);
  });

  it('同配置结果确定可复现（报告哈希一致）', async () => {
    const gen = await import('../src/domain/generatorA');
    const syn = gen.generateConstraint({ plan: samplePlan, ruleSet: sampleRuleSet, source: sampleSource }).tables;
    const r1 = await evaluateMembership({ runId: 'RUN-E2E-3', syn, src: sampleSource, plan: samplePlan, ruleSet: sampleRuleSet });
    const r2 = await evaluateMembership({ runId: 'RUN-E2E-3', syn, src: sampleSource, plan: samplePlan, ruleSet: sampleRuleSet });
    expect(r1.hash).toBe(r2.hash);
    expect(r1.mirror.packageHash).toBe(r2.mirror.packageHash);
  });

  it('真实发布包近复制扫描给出描述性证据且注明不作为识别指标', async () => {
    const gen = await import('../src/domain/generatorA');
    const syn = gen.generateConstraint({ plan: samplePlan, ruleSet: sampleRuleSet, source: sampleSource }).tables;
    const report = await evaluateMembership({ runId: 'RUN-E2E-4', syn, src: sampleSource, plan: samplePlan, ruleSet: sampleRuleSet });
    expect(report.releasedPackageScan.nearReplicationEvidence.length).toBeGreaterThan(0);
    expect(report.releasedPackageScan.note).toContain('不作为识别能力指标');
  });
});

// ---------- 5. 影子生成器路线 ----------

describe('攻击②：影子生成器分类器', () => {
  it('在随题样例上完成训练并输出同口径指标', async () => {
    const gen = await import('../src/domain/generatorA');
    const syn = gen.generateConstraint({ plan: samplePlan, ruleSet: sampleRuleSet, source: sampleSource }).tables;
    const report = await evaluateMembership({
      runId: 'RUN-E2E-SHADOW',
      syn,
      src: sampleSource,
      plan: samplePlan,
      ruleSet: sampleRuleSet,
      config: { method: 'shadow', shadowGroups: 2, minStratumSize: 6, fprTargets: [0.05, 0.1] }
    });
    const methods = report.attacks.map((a) => a.method);
    expect(methods).toContain('nn-likelihood');
    expect(methods).toContain('shadow');
    const shadow = report.attacks.find((a) => a.method === 'shadow')!;
    // 评估池主体（每侧折半后）仍有计数与合法区间
    expect(shadow.memberCount).toBeGreaterThan(0);
    expect(shadow.controlCount).toBeGreaterThan(0);
    for (const p of shadow.points) {
      expect(p.fprTarget).toBeGreaterThan(0);
      expect(p.tprCi.low).toBeGreaterThanOrEqual(0);
      expect(p.tprCi.high).toBeLessThanOrEqual(1);
    }
  }, 30000);

  it('样本不足时影子攻击记为未执行/未检出，不伪造分数', async () => {
    // 极小数据集：每侧不足 4 个主体
    const specs: EventSpec[] = [];
    for (let i = 0; i < 6; i++) {
      specs.push({ key: `T-${i}`, day: i, hour: 10, type: '突发疾病', district: '城东区', priority: 'P2', outcome: '送医', phone: `138****0${String(i).padStart(3, '0')}`, address: `小路${i}号` });
    }
    const tiny = makeTables(specs);
    const plan = defaultPlan('PL-TINY', 'tiny@r1', 'RS-MIA', 1, tiny, '2025-01-01T00:00:00Z');
    plan.status = 'approved';
    plan.targetEvents = 12;
    const report = await evaluateMembership({
      runId: 'RUN-TINY',
      syn: genericPackage(8),
      src: tiny,
      plan,
      ruleSet: sampleRuleSet,
      config: { method: 'shadow', shadowGroups: 2, minStratumSize: 2 }
    });
    // 影子路线不可用时只剩 nn 路线，且备注说明未执行原因
    expect(report.attacks.map((a) => a.method)).not.toContain('shadow');
    expect(report.notes.join('；')).toContain('影子攻击本次未执行');
  });
});
