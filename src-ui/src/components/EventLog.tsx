import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { makeRealtimeEvent, type EventEvidence, type SecurityEvent } from "../lib/api";
import { tr, verdictLabel, type Locale } from "../lib/locale";
import "./data-panels.css";

interface EventLogProps {
  events: SecurityEvent[];
  onEvent: (event: SecurityEvent) => void;
  locale: Locale;
}

type EventFilter = "all" | "blocked" | "warnings";
const PAGE_SIZE = 5;

function eventVerdict(event: SecurityEvent): string { return (event.decision.verdict || "pass").toLowerCase(); }
function evidenceText(evidence: EventEvidence): string { return evidence.message || evidence.snippet || evidence.rule_id || evidence.type; }
function eventMessage(event: SecurityEvent): string {
  const evidence = event.evidence.find((item) => item.message || item.snippet);
  return evidence?.message || evidence?.snippet || event.recommendation || event.action.resource || event.risk.category;
}
function eventGuardName(event: SecurityEvent): string { return event.evidence.find((item) => item.guard)?.guard || event.action.name || event.risk.category || event.source; }

export default function EventLog({ events, onEvent, locale }: EventLogProps) {
  const [filter, setFilter] = useState<EventFilter>("all");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const filterLabels: Record<EventFilter, string> = { all: tr(locale, "All events", "全部事件"), blocked: tr(locale, "Blocked", "已拦截"), warnings: tr(locale, "Warnings", "告警") };

  useEffect(() => {
    const unlisten = listen<Record<string, unknown>>("guard-event", (event) => { makeRealtimeEvent(event.payload).forEach(onEvent); });
    return () => { unlisten.then((fn) => fn()); };
  }, [onEvent]);
  useEffect(() => { if (selected && dialog.current && !dialog.current.open) dialog.current.showModal(); }, [selected]);

  const filtered = events.filter((event) => (filter === "all" || eventVerdict(event) === (filter === "blocked" ? "block" : "warn")) && `${eventGuardName(event)} ${eventMessage(event)} ${event.agent.name}`.toLowerCase().includes(query.toLowerCase()));
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount - 1);
  const visibleEvents = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  function closeDetail() { dialog.current?.close(); setSelected(null); }

  return (
    <section className="qise-card event-panel">
      <div className="event-toolbar"><div className="qise-tabs" aria-label={tr(locale, "Filter events", "筛选事件")}>
        {(["all", "blocked", "warnings"] as EventFilter[]).map((key) => <button key={key} aria-pressed={filter === key} className={`qise-tab ${filter === key ? "is-active" : ""}`} onClick={() => { setFilter(key); setPage(0); }}>{filterLabels[key]}<span className="event-tab-count">{events.filter((event) => key === "all" || eventVerdict(event) === (key === "blocked" ? "block" : "warn")).length}</span></button>)}
      </div><input className="qise-input event-search" aria-label={tr(locale, "Search events", "搜索事件")} placeholder={tr(locale, "Search events…", "搜索事件…")} value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} /></div>
      <div className="event-columns" aria-hidden="true"><span>{tr(locale, "Time", "时间")}</span><span>{tr(locale, "Application / Guard", "应用 / 守卫")}</span><span>{tr(locale, "Decision", "处置")}</span><span>{tr(locale, "Activity", "事件内容")}</span><span /></div>
      <div className="event-list">
        {visibleEvents.map((event, index) => <button key={`${event.id}-${index}`} className="event-row" onClick={() => setSelected(event)} aria-label={`${tr(locale, "View event", "查看事件")} ${eventMessage(event)}`}>
          <span className="event-time"><strong>{event.timestamp.replace("T", " ").slice(11, 19)}</strong><small>{event.timestamp.slice(0, 10)}</small></span>
          <span className="event-source"><strong>{event.agent.name || eventGuardName(event)}</strong><small>{eventGuardName(event)}</small></span>
          <span className={`event-verdict event-verdict-${eventVerdict(event)}`}><i />{verdictLabel(locale, eventVerdict(event))}</span>
          <span className="event-message">{eventMessage(event)}</span><span className="event-row-arrow" aria-hidden="true">›</span>
        </button>)}
        {visibleEvents.length === 0 && <div className="event-empty"><strong>{tr(locale, "No events to show", "暂无事件")}</strong><p>{events.length === 0 ? tr(locale, "Events appear here when protection is enabled.", "开启保护后，安全事件会显示在这里。") : tr(locale, "Try another filter or search term.", "请尝试其他筛选条件或关键词。")}</p></div>}
      </div>
      <footer className="event-pagination"><span>{tr(locale, `${filtered.length} events · Select a row for details`, `共 ${filtered.length} 条事件 · 点击查看详情`)}</span><div><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} aria-label={tr(locale, "Previous page", "上一页")}>‹</button><span>{currentPage + 1} / {pageCount}</span><button disabled={currentPage + 1 >= pageCount} onClick={() => setPage(currentPage + 1)} aria-label={tr(locale, "Next page", "下一页")}>›</button></div></footer>
      {selected && <dialog ref={dialog} className="event-dialog" onCancel={closeDetail} aria-labelledby="event-detail-title">
        <div className="event-dialog-header"><div><span className="event-detail-kicker">{tr(locale, "SECURITY EVENT", "安全事件")}</span><h3 id="event-detail-title">{eventGuardName(selected)}</h3></div><button className="event-close" aria-label={tr(locale, "Close", "关闭")} onClick={closeDetail}>×</button></div>
        <div className="event-dialog-content"><div className="event-detail-summary"><span className={`event-verdict event-verdict-${eventVerdict(selected)}`}><i />{verdictLabel(locale, eventVerdict(selected))}</span><time>{selected.timestamp.replace("T", " ").slice(0, 19)}</time></div><p className="event-detail-message">{eventMessage(selected)}</p>
          <dl className="event-metadata"><dt>{tr(locale, "Application", "应用")}</dt><dd>{selected.agent.name || "—"}</dd><dt>{tr(locale, "Resource", "关联资源")}</dt><dd>{selected.action.resource || "—"}</dd><dt>{tr(locale, "Source", "来源")}</dt><dd>{selected.source || "—"}</dd><dt>{tr(locale, "Event ID", "事件编号")}</dt><dd>{selected.id || "—"}</dd></dl>
          {!!selected.evidence.length && <div className="event-evidence"><h4>{tr(locale, "Evidence", "检测依据")}</h4>{selected.evidence.map((evidence, index) => <p key={index}>{evidenceText(evidence)}</p>)}</div>}
          {selected.recommendation && <div className="event-recommendation"><h4>{tr(locale, "Recommendation", "建议")}</h4><p>{selected.recommendation}</p></div>}
        </div><div className="event-dialog-actions"><button className="qise-action qise-action-secondary" onClick={closeDetail}>{tr(locale, "Close details", "关闭详情")}</button></div>
      </dialog>}
    </section>
  );
}
