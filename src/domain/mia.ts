// 成员推断风险评估（Membership Inference Attack, MIA）。
//
// 威胁模型：攻击者拿到合成演练包，并掌握一批候选主体（人员/家庭）的背景知识，
// 试图判断这些主体是否出现在生成器的训练样本（来源批次）中。这不同于在输出里
// 找一条对应记录——即使没有直接身份字段，生成器对成员与非成员的“拟合差异”仍可能泄漏。
//
// 评估纪律：
// - 评估单元是“主体”（同一来电/地址聚合的家庭或人员），同一主体的多起事件整体进入
//   成员侧或对照侧，绝不允许跨两侧造成泄漏；
// - 真实发布包由全量源批次训练，不存在真值非成员。因此指标在“镜像审计包”上测量：
//   仅用成员侧源行训练一台与发布同路线的镜像生成器，成员/对照标签由此具有真值；
//   对真实发布包只做描述性的近复制距离扫描，不据此宣称识别能力；
// - 攻击指标只在固定误报率（FPR）工作点报告，并给出 Wilson 置信区间；
// - 成员推断优势 = TPR - FPR，基准攻击失败只记“本次未检出”，不表述为零风险；
// - 极低样本分层不单独给出高精度分数，只标注样本不足；
// - 报告绑定被评估合成包的哈希，包更新后哈希变化，旧报告自动失效。
//
// 提供两条攻击路线，估计的是同一量（攻击者区分成员与非成员的能力）：
// ① nn-likelihood：最近邻距离 + 属性似然，轻量、可复现、对近复制敏感；
// ② shadow：多组影子生成器训练攻击分类器，可捕捉更复杂的成员特征，
//    代价是更多训练运行，且对影子数据代表性敏感。

import type { GenMethod, Plan, RuleSet, TableRows } from './types';
import { buildChains, type ChainEvent } from './stats';
import { mulberry32, type Rng } from './prng';
import { generateConstraint } from './generatorA';
import { generateJointFilter } from './generatorB';
import { hashObject } from './hash';

// ---------- 公共类型 ----------

export type MiaAttackMethod = 'nn-likelihood' | 'shadow';

/** 分层键：稀有属性组合 / 多事件家庭 / 高频普通主体 */
export type MiaStratum = 'rare-combo' | 'multi-event' | 'common';

export interface MiaConfig {
  method: MiaAttackMethod;
  /** 固定误报率工作点（如 0.05、0.01），可同时评估多个阈值 */
  fprTargets: number[];
  /** 成员侧占比；其余主体构成未参与生成的对照集 */
  memberRatio: number;
  seed: number;
  /** 分层与置信区间所要求的最小主体数，低于该数不单独给出分数 */
  minStratumSize: number;
  /** 最近邻路线：每个主体参与攻击的背景事件抽样上限 */
  maxEventsPerSubject: number;
  /** 影子路线：影子生成器组数（每组一进一出） */
  shadowGroups: number;
}

export const DEFAULT_MIA_CONFIG: MiaConfig = {
  method: 'nn-likelihood',
  fprTargets: [0.01, 0.05, 0.1],
  memberRatio: 0.5,
  seed: 20251120,
  minStratumSize: 8,
  maxEventsPerSubject: 8,
  shadowGroups: 4
};

export interface MiaSubject {
  id: string;
  /** 链接键来源：来电号码或地址（去标识化值仍可作家庭链接信号） */
  linkKey: string;
  linkKind: 'caller_phone' | 'address_text' | 'singleton';
  eventIds: string[];
  strata: MiaStratum[];
  eventCount: number;
}

export interface MiaSplit {
  memberSubjectIds: string[];
  controlSubjectIds: string[];
  /** 供审计的整分信息：每个主体归属哪一侧 */
  assignment: { subjectId: string; side: 'member' | 'control' }[];
}

export interface BinomialCI {
  level: number;
  low: number;
  high: number;
}

export interface MiaOperatingPoint {
  fprTarget: number;
  /** 在对照集上实际达到的误报率（阈值来自对照分位数，故贴近目标） */
  fpr: number;
  /** 该工作点下成员侧命中率 */
  tpr: number;
  /** 成员推断优势 = TPR - FPR */
  advantage: number;
  tprCi: BinomialCI;
  fprCi: BinomialCI;
  /** 判定阈值（攻击分数严格大于阈值即预测为成员；并列分数不报警） */
  threshold: number;
  /** 该工作点是否因样本不足而检验功效不足 */
  underpowered: boolean;
}

export interface MiaStratumResult {
  stratum: MiaStratum;
  label: string;
  memberCount: number;
  controlCount: number;
  /** 样本不足时为 null，不给出虚假的高精度分数 */
  points: MiaOperatingPoint[] | null;
  note?: string;
}

export interface MiaAttackSummary {
  method: MiaAttackMethod;
  /** ROC AUC（含 Hanley-McNeil 近似区间） */
  auc: number;
  aucCi: BinomialCI;
  points: MiaOperatingPoint[];
  strata: MiaStratumResult[];
  memberCount: number;
  controlCount: number;
  /** 基准攻击是否未检出：所有工作点优势的置信上界 <= 0 */
  noDetection: boolean;
  note?: string;
}

export interface MiaNearReplication {
  subjectId: string;
  eventId: string;
  nearestSyntheticEventId: string;
  distance: number;
}

export interface MiaMirrorInfo {
  method: GenMethod;
  seed: number;
  targetEvents: number;
  memberSourceEvents: number;
  packageHash: string;
}

export interface MiaReport {
  id: string;
  runId: string;
  createdAt: string;
  /** 绑定的真实发布包哈希（由运行输出表实算）；包更新后哈希变化，旧报告失效 */
  packageHash: string;
  sourceBatchKey: string;
  config: MiaConfig;
  split: { memberCount: number; controlCount: number; memberRatio: number; linkKinds: Record<string, number> };
  /** 镜像审计包信息：指标全部在该包上测量，标签才有真值 */
  mirror: MiaMirrorInfo;
  attacks: MiaAttackSummary[];
  /** 对真实发布包的描述性近复制扫描（不作为识别能力指标） */
  releasedPackageScan: { nearReplicationEvidence: MiaNearReplication[]; note: string };
  notes: string[];
  /** 只描述所测攻击风险的范围声明，绝不宣称绝对匿名 */
  disclaimer: string;
  hash: string;
}

export const MIA_DISCLAIMER =
  '成员推断评估仅刻画本次所实现攻击（最近邻距离+属性似然 / 影子生成器分类器）在固定误报率下区分训练成员与对照主体的能力。' +
  '“本次未检出”只表示该攻击在当前样本与阈值下未获得统计上可区分的信号，不等于零风险，更不构成匿名性保证；' +
  '掌握更强背景知识、更多辅助数据或定制模型的攻击者可能获得更高识别能力。演练包应按内部受控资料管理。';

export const STRATUM_LABELS: Record<MiaStratum, string> = {
  'rare-combo': '稀有属性组合主体',
  'multi-event': '多事件家庭/人员',
  common: '普通高频事件主体'
};

// ---------- 主体构建与切分 ----------

export interface SubjectBuild {
  subjects: MiaSubject[];
  chainsById: Map<string, ChainEvent>;
  rareComboKeys: Set<string>;
}

/**
 * 从来源批次构建评估主体：
 * - 同一 caller_phone（真实来电，含脱敏值）的多起事件聚合为一个人员/家庭主体；
 * - 无重复来电时，用 address_text 聚合同址事件（家庭链接的弱信号）；
 * - 其余事件各自成为单事件主体。
 */
export function buildSubjects(src: TableRows): SubjectBuild {
  const chains = buildChains(src);
  const chainsById = new Map(chains.map((c) => [c.eventId, c]));

  // 稀有属性组合：(事件类型, 行政区, 优先级, 链型, 结局) 在源中仅出现 <=2 次
  const comboCount = new Map<string, number>();
  for (const c of chains) {
    const key = rareKeyOf(c);
    comboCount.set(key, (comboCount.get(key) ?? 0) + 1);
  }
  const rareComboKeys = new Set<string>();
  for (const [key, n] of comboCount) if (n <= 2) rareComboKeys.add(key);

  const phoneOwners = new Map<string, string>(); // 来电值 -> 主体链接键
  const addrOwners = new Map<string, string>();
  const subjects: MiaSubject[] = [];
  const byKey = new Map<string, MiaSubject>();

  const ensure = (linkKey: string, linkKind: MiaSubject['linkKind']): MiaSubject => {
    let s = byKey.get(linkKey);
    if (!s) {
      s = { id: `SUB-${String(subjects.length + 1).padStart(4, '0')}`, linkKey, linkKind, eventIds: [], strata: [], eventCount: 0 };
      subjects.push(s);
      byKey.set(linkKey, s);
    }
    return s;
  };

  for (const e of src.events) {
    const phone = e.caller_phone?.trim();
    const addr = e.address_text?.trim();
    let owner: MiaSubject | undefined;
    if (phone && phoneOwners.has(phone)) owner = byKey.get(phoneOwners.get(phone)!);
    else if (addr && addrOwners.has(addr)) owner = byKey.get(addrOwners.get(addr)!);

    if (!owner) {
      const linkKind: MiaSubject['linkKind'] = phone ? 'caller_phone' : addr ? 'address_text' : 'singleton';
      const linkKey = phone ? `phone:${phone}` : addr ? `addr:${addr}` : `event:${e.event_id}`;
      owner = ensure(linkKey, linkKind);
      if (phone) phoneOwners.set(phone, linkKey);
      if (addr) addrOwners.set(addr, linkKey);
    }
    owner.eventIds.push(e.event_id);
  }

  for (const s of subjects) {
    s.eventCount = s.eventIds.length;
    const strata = new Set<MiaStratum>();
    for (const eid of s.eventIds) {
      const c = chainsById.get(eid);
      if (c && rareComboKeys.has(rareKeyOf(c))) strata.add('rare-combo');
    }
    if (s.eventCount > 1) strata.add('multi-event');
    if (strata.size === 0) strata.add('common');
    s.strata = [...strata];
  }
  return { subjects, chainsById, rareComboKeys };
}

function rareKeyOf(c: ChainEvent): string {
  return [c.event_type, c.district, c.priority, c.pattern, c.outcome || '未知'].join('|');
}

/**
 * 主体级切分：按主体整分成员集与对照集，同一主体的全部事件只出现在一侧。
 * 使用确定性洗牌（mulberry32），同种子可复现。
 */
export function splitSubjects(subjects: MiaSubject[], config: MiaConfig): MiaSplit {
  const rng = mulberry32(config.seed);
  const idx = subjects.map((_, i) => i);
  for (let i = idx.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  const memberN = Math.max(1, Math.round(subjects.length * clamp(config.memberRatio, 0.1, 0.9)));
  const memberSet = new Set(idx.slice(0, memberN));
  const memberSubjectIds: string[] = [];
  const controlSubjectIds: string[] = [];
  const assignment: MiaSplit['assignment'] = [];
  subjects.forEach((s, i) => {
    const side = memberSet.has(i) ? 'member' : 'control';
    (side === 'member' ? memberSubjectIds : controlSubjectIds).push(s.id);
    assignment.push({ subjectId: s.id, side });
  });
  return { memberSubjectIds, controlSubjectIds, assignment };
}

/** 从源表中按主体侧抽取行（整主体事件不跨侧） */
export function rowsForSubjects(src: TableRows, subjects: MiaSubject[], ids: Set<string>): TableRows {
  const keepEvents = new Set<string>();
  for (const s of subjects) if (ids.has(s.id)) for (const eid of s.eventIds) keepEvents.add(eid);
  const events = src.events.filter((e) => keepEvents.has(e.event_id));
  const eventIds = new Set(events.map((e) => e.event_id));
  const dispatches = src.dispatches.filter((d) => eventIds.has(d.event_id));
  const dispatchIds = new Set(dispatches.map((d) => d.dispatch_id));
  const arrivals = src.arrivals.filter((a) => dispatchIds.has(a.dispatch_id));
  const closures = src.closures.filter((c) => eventIds.has(c.event_id));
  return { events, dispatches, resources: structuredClone(src.resources), arrivals, closures };
}

// ---------- 特征与攻击分数 ----------

interface Feat {
  type: string;
  district: string;
  priority: string;
  pattern: string;
  outcome: string;
  hour: number;
  logResponse: number;
  logTravel: number;
  logOnScene: number;
}

const CAT_KEYS: (keyof Feat)[] = ['type', 'district', 'priority', 'pattern', 'outcome'];
const NUM_KEYS: (keyof Feat)[] = ['logResponse', 'logTravel', 'logOnScene', 'hour'];

function featurize(chains: ChainEvent[]): Feat[] {
  return chains.map((c) => {
    const response = c.legs.length ? (c.legs[0].dispatchMs - c.alarmMs) / 60000 : 5;
    const travels = c.legs.filter((l) => l.arriveMs != null).map((l) => (l.arriveMs! - l.dispatchMs) / 60000);
    const travel = travels.length ? travels.reduce((a, b) => a + b, 0) / travels.length : 10;
    const onScene = c.closeMs != null && c.legs.length
      ? (c.closeMs - Math.max(...c.legs.map((l) => l.arriveMs ?? l.dispatchMs))) / 60000
      : 20;
    return {
      type: c.event_type,
      district: c.district,
      priority: c.priority,
      pattern: c.pattern,
      outcome: c.outcome || '未知',
      hour: new Date(c.alarmMs).getHours(),
      logResponse: Math.log1p(Math.max(0, response)),
      logTravel: Math.log1p(Math.max(0, travel)),
      logOnScene: Math.log1p(Math.max(0, onScene))
    };
  });
}

/** 类别频率表（加一平滑）与数值均值/标准差，供似然与归一化距离共用 */
interface FeatureModel {
  catFreq: Record<string, Map<string, number>>;
  catAlpha: number;
  numMean: Record<string, number>;
  numSd: Record<string, number>;
  n: number;
}

function fitModel(feats: Feat[]): FeatureModel {
  const catFreq: Record<string, Map<string, number>> = {};
  for (const k of CAT_KEYS) {
    const m = new Map<string, number>();
    for (const f of feats) m.set(f[k] as string, (m.get(f[k] as string) ?? 0) + 1);
    catFreq[k] = m;
  }
  const numMean: Record<string, number> = {};
  const numSd: Record<string, number> = {};
  for (const k of NUM_KEYS) {
    const vals = feats.map((f) => f[k] as number);
    const m = mean(vals);
    numMean[k] = m;
    numSd[k] = sd(vals, m) || 1;
  }
  return { catFreq, catAlpha: 1, numMean, numSd, n: feats.length };
}

function catProb(m: FeatureModel, key: keyof Feat, value: string): number {
  const freq = m.catFreq[key as string];
  const seen = freq?.get(value) ?? 0;
  const cardinality = Math.max(1, freq?.size ?? 1);
  return (seen + m.catAlpha) / (m.n + m.catAlpha * (cardinality + 1));
}

function zScore(m: FeatureModel, key: keyof Feat, value: number): number {
  return (value - m.numMean[key as string]) / m.numSd[key as string];
}

/** 单事件到合成包记录的距离：类别汉明距离（归一化）+ 数值标准化欧氏距离（归一化） */
function eventDistance(a: Feat, b: Feat, model: FeatureModel): number {
  let catDiff = 0;
  for (const k of CAT_KEYS) if (a[k] !== b[k]) catDiff++;
  const catPart = catDiff / CAT_KEYS.length;
  let numSq = 0;
  for (const k of NUM_KEYS) {
    const d = (a[k] as number) - (b[k] as number);
    numSq += (d / model.numSd[k as string]) ** 2;
  }
  const numPart = Math.sqrt(numSq / NUM_KEYS.length);
  return (catPart + numPart) / 2;
}

/** 事件在某特征模型下的属性对数似然（类别多项 + 数值高斯） */
function eventLogLikelihood(f: Feat, model: FeatureModel): number {
  let ll = 0;
  for (const k of CAT_KEYS) ll += Math.log(catProb(model, k, f[k] as string));
  for (const k of NUM_KEYS) {
    const z = zScore(model, k, f[k] as number);
    ll += -0.5 * (Math.log(2 * Math.PI) + 2 * Math.log(model.numSd[k as string]) + z * z);
  }
  return ll;
}

export interface SubjectScore {
  subjectId: string;
  /** 标准化后的攻击分数，越大越可能是成员 */
  score: number;
  isMember: boolean;
  strata: MiaStratum[];
  nearest: { eventId: string; syntheticEventId: string; distance: number } | null;
  /** 原始信号：平均最近邻距离（越小越可疑） */
  rawDist: number;
  /** 原始信号：平均属性对数似然（越大越可疑） */
  rawLl: number;
}

/**
 * 攻击路线①：最近邻距离 + 属性似然。
 * 攻击者观察：主体背景事件在合成包中的最小距离（越小越像被记住），
 * 以及这些事件相对合成包属性模型的平均似然（越像模型内样本越可能是成员）。
 * 两个信号用对照集分布标准化后等权合成攻击分数——攻击者阈值校准只能依据非成员分布。
 */
export function nnLikelihoodScores(
  src: TableRows,
  syn: TableRows,
  build: SubjectBuild,
  split: MiaSplit,
  config: MiaConfig
): SubjectScore[] {
  const synChains = buildChains(syn);
  const synFeats = featurize(synChains);
  const synModel = fitModel(synFeats);
  const synFeatById = new Map(synChains.map((c, i) => [c.eventId, synFeats[i]]));

  const memberSet = new Set(split.memberSubjectIds);
  const allIds = new Set([...split.memberSubjectIds, ...split.controlSubjectIds]);
  const rng = mulberry32(config.seed ^ 0x9e3779b9);
  const raw: SubjectScore[] = [];

  for (const s of build.subjects) {
    if (!allIds.has(s.id)) continue;
    let eventIds = s.eventIds;
    // 背景事件抽样上限：防止多事件主体仅凭事件数量占优
    if (eventIds.length > config.maxEventsPerSubject) {
      eventIds = shuffle([...eventIds], rng).slice(0, config.maxEventsPerSubject);
    }
    let distSum = 0;
    let llSum = 0;
    let nearest: SubjectScore['nearest'] = null;
    let used = 0;
    for (const eid of eventIds) {
      const chain = build.chainsById.get(eid);
      if (!chain) continue;
      used++;
      const f = featurize([chain])[0];
      let bestD = Infinity;
      let bestSynId = '';
      for (const sc of synChains) {
        const sf = synFeatById.get(sc.eventId)!;
        const d = eventDistance(f, sf, synModel);
        if (d < bestD) { bestD = d; bestSynId = sc.eventId; }
      }
      distSum += bestD;
      if (!nearest || bestD < nearest.distance) nearest = { eventId: eid, syntheticEventId: bestSynId, distance: round4(bestD) };
      llSum += eventLogLikelihood(f, synModel);
    }
    const n = Math.max(1, used);
    raw.push({
      subjectId: s.id,
      score: 0,
      isMember: memberSet.has(s.id),
      strata: s.strata,
      nearest,
      rawDist: distSum / n,
      rawLl: llSum / n
    });
  }

  // 标准化参数只从对照集估计；无对照时（影子 in 侧打分）保留 0 分，原始信号仍可用
  const controls = raw.filter((x) => !x.isMember);
  const dMean = mean(controls.map((x) => x.rawDist));
  const dSd = sd(controls.map((x) => x.rawDist), dMean);
  const lMean = mean(controls.map((x) => x.rawLl));
  const lSd = sd(controls.map((x) => x.rawLl), lMean);
  for (const x of raw) {
    const zDist = dSd > 0 ? (dMean - x.rawDist) / dSd : 0; // 距离低于对照均值 -> 正分
    const zLl = lSd > 0 ? (x.rawLl - lMean) / lSd : 0;
    x.score = round4((zDist + zLl) / 2);
  }
  return raw;
}

// ---------- 影子生成器攻击 ----------

/**
 * 攻击路线②：影子生成器。
 * 将成员/对照主体再各折半为影子训练池与攻击评估池：
 * - 每个影子组用影子成员池的随机子集训练一台影子生成器（复用本工程两条生成路线），
 *   对“影子内（in）”与“影子外（out）”主体分别计算路线①的原始信号；
 * - 用 (in/out) 标注训练一个轻量逻辑回归攻击分类器（仅两个标准化特征），
 *   再在未参与任何影子训练的评估池主体上测试。
 * 对影子数据代表性敏感，且训练成本随 shadowGroups 线性增长。
 */
export function shadowScores(
  src: TableRows,
  auditSyn: TableRows,
  build: SubjectBuild,
  split: MiaSplit,
  plan: Plan,
  ruleSet: RuleSet,
  config: MiaConfig
): { scores: SubjectScore[]; trainedGroups: number; note?: string } {
  const rng = mulberry32(config.seed ^ 0x5bd1e995);
  const members = shuffle([...split.memberSubjectIds], rng);
  const controls = shuffle([...split.controlSubjectIds], rng);

  // 每侧至少 4 个主体才能折半并保留评估池；否则本路线不可用
  if (members.length < 4 || controls.length < 4) {
    return { scores: [], trainedGroups: 0, note: '成员或对照主体不足 4 个，无法构建影子训练/评估折，影子攻击本次未执行' };
  }
  const mHalf = Math.floor(members.length / 2);
  const cHalf = Math.floor(controls.length / 2);
  const shadowMemberPool = members.slice(0, mHalf);
  const shadowControlPool = controls.slice(0, cHalf);
  const evalMembers = members.slice(mHalf);
  const evalControls = controls.slice(cHalf);

  interface TrainRow { x1: number; x2: number; y: 0 | 1 }
  const trainRows: TrainRow[] = [];
  const groups = Math.max(1, config.shadowGroups);
  let trained = 0;

  for (let g = 0; g < groups; g++) {
    // 影子“成员”样本：从影子成员池中抽 70% 主体重组训练表
    const inIds = new Set(sampleSubset(shadowMemberPool, 0.7, rng));
    const shadowRows = rowsForSubjects(src, build.subjects, inIds);
    if (shadowRows.events.length < 20) continue; // 样本太小训练无意义
    const shadowPlan: Plan = {
      ...structuredClone(plan),
      seed: (config.seed + 101 * (g + 1)) >>> 0,
      targetEvents: Math.max(20, Math.round(shadowRows.events.length * 1.2)),
      dateRange: { ...plan.dateRange }
    };
    let shadowSyn: TableRows;
    try {
      shadowSyn = (plan.method === 'joint-filter' ? generateJointFilter : generateConstraint)({ plan: shadowPlan, ruleSet, source: shadowRows }).tables;
    } catch {
      continue;
    }
    const shadowBuild = buildSubjects(shadowRows);
    const inSplit: MiaSplit = {
      memberSubjectIds: shadowBuild.subjects.map((s) => s.id),
      controlSubjectIds: [],
      assignment: shadowBuild.subjects.map((s) => ({ subjectId: s.id, side: 'member' as const }))
    };
    // in 主体（参与影子训练）与 out 主体（影子对照池，未参与）分别取原始信号
    const inScores = nnLikelihoodScores(shadowRows, shadowSyn, shadowBuild, inSplit, { ...config, seed: config.seed + g });
    const outRows = rowsForSubjects(src, build.subjects, new Set(shadowControlPool));
    const outBuild = buildSubjects(outRows);
    const outSplit: MiaSplit = {
      memberSubjectIds: [],
      controlSubjectIds: outBuild.subjects.map((s) => s.id),
      assignment: outBuild.subjects.map((s) => ({ subjectId: s.id, side: 'control' as const }))
    };
    const outScores = nnLikelihoodScores(outRows, shadowSyn, outBuild, outSplit, { ...config, seed: config.seed + g });
    for (const x of inScores) trainRows.push({ x1: x.rawDist, x2: x.rawLl, y: 1 });
    for (const x of outScores) trainRows.push({ x1: x.rawDist, x2: x.rawLl, y: 0 });
    trained++;
  }

  if (trained === 0 || trainRows.filter((r) => r.y === 1).length < 5 || trainRows.filter((r) => r.y === 0).length < 5) {
    return { scores: [], trainedGroups: trained, note: '影子训练样本不足，攻击分类器未训练，影子攻击本次未检出有效信号' };
  }

  // 逻辑回归（两特征，带 L2），梯度下降；特征方向：距离小、似大者为成员
  const x1Mean = mean(trainRows.map((r) => r.x1));
  const x1Sd = sd(trainRows.map((r) => r.x1), x1Mean) || 1;
  const x2Mean = mean(trainRows.map((r) => r.x2));
  const x2Sd = sd(trainRows.map((r) => r.x2), x2Mean) || 1;
  const features = (r: TrainRow) => [(x1Mean - r.x1) / x1Sd, (r.x2 - x2Mean) / x2Sd];
  let w1 = 0;
  let w2 = 0;
  let bias = 0;
  const lr = 0.1;
  const l2 = 0.02;
  for (let iter = 0; iter < 400; iter++) {
    let g1 = 0;
    let g2 = 0;
    let gb = 0;
    for (const r of trainRows) {
      const [z1, z2] = features(r);
      const p = 1 / (1 + Math.exp(-(w1 * z1 + w2 * z2 + bias)));
      const err = p - r.y;
      g1 += err * z1 + l2 * w1;
      g2 += err * z2 + l2 * w2;
      gb += err;
    }
    w1 -= (lr * g1) / trainRows.length;
    w2 -= (lr * g2) / trainRows.length;
    bias -= (lr * gb) / trainRows.length;
  }

  // 在评估池主体上应用分类器：特征基于镜像审计包计算，标签具有真值
  const evalSplit: MiaSplit = {
    memberSubjectIds: evalMembers,
    controlSubjectIds: evalControls,
    assignment: [
      ...evalMembers.map((id) => ({ subjectId: id, side: 'member' as const })),
      ...evalControls.map((id) => ({ subjectId: id, side: 'control' as const }))
    ]
  };
  const base = nnLikelihoodScores(src, auditSyn, build, evalSplit, config);
  for (const x of base) {
    const z1 = (x1Mean - x.rawDist) / x1Sd;
    const z2 = (x.rawLl - x2Mean) / x2Sd;
    x.score = round4(1 / (1 + Math.exp(-(w1 * z1 + w2 * z2 + bias))));
  }
  return { scores: base, trainedGroups: trained };
}

// ---------- 指标：固定误报率工作点、AUC、置信区间、分层 ----------

/**
 * 保守阈值校准：选择使对照集实际误报率不超过目标 FPR 的最高阈值。
 * 离散样本下可实现的 FPR 是网格值（1/n、2/n…），因此实际 FPR 可能低于目标；
 * 预测规则为“分数严格大于阈值”，并列分数判为非成员，绝不放宽误报约束。
 */
export function thresholdAtFpr(controlScores: number[], target: number): { threshold: number; fprRaw: number } {
  if (controlScores.length === 0) return { threshold: Infinity, fprRaw: 0 };
  const sorted = [...controlScores].sort((a, b) => a - b);
  const allowedFp = Math.floor(target * sorted.length);
  // 允许 allowedFp 个对照越界：阈值取升序第 (n-1-allowedFp) 个值，严格大于才报警
  const threshold = sorted[sorted.length - 1 - allowedFp];
  const fprRaw = sorted.filter((v) => v > threshold).length / sorted.length;
  return { threshold, fprRaw };
}

function wilsonCi(k: number, n: number, level = 0.95): BinomialCI {
  if (n === 0) return { level, low: 0, high: 0 };
  const z = level === 0.95 ? 1.96 : 1.645;
  const phat = k / n;
  const denom = 1 + (z * z) / n;
  const center = (phat + (z * z) / (2 * n)) / denom;
  const half = (z * Math.sqrt((phat * (1 - phat) + (z * z) / (4 * n)) / n)) / denom;
  return { level, low: clamp(center - half, 0, 1), high: clamp(center + half, 0, 1) };
}

function aucWithCi(memberScores: number[], controlScores: number[]): { auc: number; ci: BinomialCI } {
  let wins = 0;
  let ties = 0;
  for (const m of memberScores) {
    for (const c of controlScores) {
      if (m > c) wins++;
      else if (m === c) ties++;
    }
  }
  const pairs = memberScores.length * controlScores.length;
  if (pairs === 0) return { auc: 0.5, ci: { level: 0.95, low: 0.5, high: 0.5 } };
  const auc = (wins + 0.5 * ties) / pairs;
  // Hanley-McNeil 近似方差
  const n1 = memberScores.length;
  const n0 = controlScores.length;
  const q1 = auc / (2 - auc);
  const q2 = (2 * auc * auc) / (1 + auc);
  const varAuc = (auc * (1 - auc) + (n1 - 1) * (q1 - auc * auc) + (n0 - 1) * (q2 - auc * auc)) / (n1 * n0);
  const se = Math.sqrt(Math.max(0, varAuc));
  return {
    auc: round4(auc),
    ci: { level: 0.95, low: clamp(auc - 1.96 * se, 0, 1), high: clamp(auc + 1.96 * se, 0, 1) }
  };
}

function operatingPoints(scores: SubjectScore[], config: MiaConfig): MiaOperatingPoint[] {
  const controls = scores.filter((x) => !x.isMember);
  const members = scores.filter((x) => x.isMember);
  const controlScores = controls.map((x) => x.score);
  return config.fprTargets.map((target) => {
    const { threshold, fprRaw } = thresholdAtFpr(controlScores, target);
    const tp = members.filter((x) => x.score > threshold).length;
    const fp = controls.filter((x) => x.score > threshold).length;
    const tprRaw = members.length ? tp / members.length : 0;
    const tpr = round4(tprRaw);
    const fpr = round4(fprRaw);
    const underpowered = members.length < config.minStratumSize || controls.length < config.minStratumSize;
    return {
      fprTarget: target,
      fpr,
      tpr,
      advantage: round4(tpr - fpr),
      tprCi: wilsonCi(tp, members.length),
      fprCi: wilsonCi(fp, controls.length),
      threshold: round4(threshold),
      underpowered
    };
  });
}function summarizeAttack(
  method: MiaAttackMethod,
  scores: SubjectScore[],
  config: MiaConfig,
  build: SubjectBuild,
  note?: string
): MiaAttackSummary | null {
  if (scores.length === 0) return null;
  const members = scores.filter((x) => x.isMember);
  const controls = scores.filter((x) => !x.isMember);
  const { auc, ci } = aucWithCi(members.map((x) => x.score), controls.map((x) => x.score));
  const points = operatingPoints(scores, config);
  // 基准攻击失败：所有工作点的优势置信上界 <= 0（含 0 视为未检出）
  const noDetection = points.every((p) => p.tprCi.high - p.fpr <= 0);

  const strata = (['rare-combo', 'multi-event', 'common'] as MiaStratum[]).map((stratum): MiaStratumResult => {
    const inStratum = new Set(build.subjects.filter((s) => s.strata.includes(stratum)).map((s) => s.id));
    const sub = scores.filter((x) => inStratum.has(x.subjectId));
    const mCount = sub.filter((x) => x.isMember).length;
    const cCount = sub.filter((x) => !x.isMember).length;
    if (mCount < config.minStratumSize || cCount < config.minStratumSize) {
      return {
        stratum,
        label: STRATUM_LABELS[stratum],
        memberCount: mCount,
        controlCount: cCount,
        points: null,
        note: `成员 ${mCount} / 对照 ${cCount}，低于最小样本 ${config.minStratumSize}，不单独给出分数以免虚假高精度`
      };
    }
    return { stratum, label: STRATUM_LABELS[stratum], memberCount: mCount, controlCount: cCount, points: operatingPoints(sub, config) };
  });

  return {
    method,
    auc,
    aucCi: ci,
    points,
    strata,
    memberCount: members.length,
    controlCount: controls.length,
    noDetection,
    note
  };
}

/** 对真实发布包的描述性近复制扫描：取全体主体最近邻距离最低的若干对 */
function scanReleasedPackage(syn: TableRows, build: SubjectBuild, config: MiaConfig): MiaNearReplication[] {
  const synChains = buildChains(syn);
  const synFeats = featurize(synChains);
  const model = fitModel(synFeats);
  const synFeatById = new Map(synChains.map((c, i) => [c.eventId, synFeats[i]]));
  const all: MiaNearReplication[] = [];
  for (const s of build.subjects) {
    for (const eid of s.eventIds.slice(0, config.maxEventsPerSubject)) {
      const chain = build.chainsById.get(eid);
      if (!chain) continue;
      const f = featurize([chain])[0];
      let bestD = Infinity;
      let bestSynId = '';
      for (const sc of synChains) {
        const d = eventDistance(f, synFeatById.get(sc.eventId)!, model);
        if (d < bestD) { bestD = d; bestSynId = sc.eventId; }
      }
      all.push({ subjectId: s.id, eventId: eid, nearestSyntheticEventId: bestSynId, distance: round4(bestD) });
    }
  }
  return all.sort((a, b) => a.distance - b.distance).slice(0, 10);
}

// ---------- 顶层评估入口 ----------

export interface MiaEvalInput {
  runId: string;
  /** 真实发布包（运行输出）；仅用于哈希绑定与描述性扫描 */
  syn: TableRows;
  src: TableRows;
  plan: Plan;
  ruleSet: RuleSet;
  config?: Partial<MiaConfig>;
}

export async function evaluateMembership(input: MiaEvalInput): Promise<Omit<MiaReport, 'id' | 'createdAt'>> {
  const config: MiaConfig = { ...DEFAULT_MIA_CONFIG, ...input.config };
  config.fprTargets = [...new Set(config.fprTargets.map((x) => clamp(x, 0.001, 0.5)))].sort((a, b) => a - b);

  const build = buildSubjects(input.src);
  const split = splitSubjects(build.subjects, config);

  // 泄漏自检：同一主体不得同时出现在成员与对照两侧
  const memberSet = new Set(split.memberSubjectIds);
  for (const id of split.controlSubjectIds) {
    if (memberSet.has(id)) throw new Error('成员/对照切分泄漏：同一主体跨两侧');
  }

  // 镜像审计包：仅用成员侧源行训练，成员（参与训练）/对照（未参与）标签由此具有真值
  const memberRows = rowsForSubjects(input.src, build.subjects, memberSet);
  const mirrorSeed = (config.seed ^ 0x7f4a7c15) >>> 0;
  const mirrorPlan: Plan = {
    ...structuredClone(input.plan),
    seed: mirrorSeed,
    targetEvents: Math.max(20, Math.min(input.plan.targetEvents, Math.round(memberRows.events.length * 1.2))),
    dateRange: { ...input.plan.dateRange }
  };
  const mirrorSyn = (input.plan.method === 'joint-filter' ? generateJointFilter : generateConstraint)({
    plan: mirrorPlan,
    ruleSet: input.ruleSet,
    source: memberRows
  }).tables;
  const mirrorPackageHash = await hashObject(mirrorSyn);

  const attacks: MiaAttackSummary[] = [];
  const notes: string[] = [];

  const nnScores = nnLikelihoodScores(input.src, mirrorSyn, build, split, config);
  const nnSummary = summarizeAttack('nn-likelihood', nnScores, config, build);
  if (nnSummary) attacks.push(nnSummary);

  if (config.method === 'shadow') {
    const shadow = shadowScores(input.src, mirrorSyn, build, split, input.plan, input.ruleSet, config);
    if (shadow.note) notes.push(shadow.note);
    const shadowSummary = summarizeAttack('shadow', shadow.scores, config, build, shadow.note);
    if (shadowSummary) attacks.push(shadowSummary);
    else if (!shadow.note) notes.push('影子攻击本次未检出可用信号');
  }

  const linkKinds: Record<string, number> = {};
  for (const s of build.subjects) linkKinds[s.linkKind] = (linkKinds[s.linkKind] ?? 0) + 1;

  const evidence = scanReleasedPackage(input.syn, build, config);
  const packageHash = await hashObject(input.syn);
  const body = {
    runId: input.runId,
    packageHash,
    sourceBatchKey: input.plan.batchKey,
    config,
    split: {
      memberCount: split.memberSubjectIds.length,
      controlCount: split.controlSubjectIds.length,
      memberRatio: round4(split.memberSubjectIds.length / build.subjects.length),
      linkKinds
    },
    mirror: {
      method: input.plan.method,
      seed: mirrorSeed,
      targetEvents: mirrorPlan.targetEvents,
      memberSourceEvents: memberRows.events.length,
      packageHash: mirrorPackageHash
    },
    attacks,
    releasedPackageScan: {
      nearReplicationEvidence: evidence,
      note: '基于真实发布包的最近邻距离描述性扫描；发布包由全量源批次训练，无真值非成员，不作为识别能力指标'
    },
    notes,
    disclaimer: MIA_DISCLAIMER
  };
  const hash = await hashObject(body);
  return { ...body, hash };
}

// ---------- 小工具 ----------

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, v));
}
function mean(xs: number[]): number {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
}
function sd(xs: number[], m: number): number {
  return xs.length ? Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / xs.length) : 0;
}
function round4(v: number): number {
  return Math.round(v * 10000) / 10000;
}
function shuffle<T>(arr: T[], rng: Rng): T[] {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
function sampleSubset<T>(arr: T[], ratio: number, rng: Rng): T[] {
  return shuffle(arr, rng).slice(0, Math.max(1, Math.round(arr.length * ratio)));
}
