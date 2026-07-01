pub mod widgets;

use argus_common::{AggregatedMetrics, Alert, HealthState};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Sparkline},
};
use std::io::stdout;
use std::time::Duration;

/// Snapshot of the agent state for TUI rendering.
#[derive(Debug, Clone)]
pub struct DashboardState {
    pub health: HealthState,
    pub metrics: AggregatedMetrics,
    pub recent_alerts: Vec<Alert>,
    pub event_count: u64,
    pub uptime_secs: f64,
    pub source_name: String,
    pub ib_error_history: Vec<f64>,
    pub irq_rate_history: Vec<f64>,
    pub slab_rate_history: Vec<f64>,
    pub rdma_throughput_history: Vec<f64>,
    pub cq_latency_history: Vec<f64>,
    /// True when standard IB byte counters are available (mlx5), false for packet-only (rxe).
    pub rdma_has_byte_counters: bool,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            health: HealthState::Healthy,
            metrics: AggregatedMetrics::default(),
            recent_alerts: Vec::new(),
            event_count: 0,
            uptime_secs: 0.0,
            source_name: String::from("none"),
            ib_error_history: Vec::new(),
            irq_rate_history: Vec::new(),
            slab_rate_history: Vec::new(),
            rdma_throughput_history: Vec::new(),
            cq_latency_history: Vec::new(),
            rdma_has_byte_counters: false,
        }
    }
}

impl DashboardState {
    pub fn push_metrics_snapshot(&mut self) {
        let ib_errors = self.metrics.ib_counter_deltas.total_all_errors_delta() as f64;
        self.ib_error_history.push(ib_errors);
        if self.ib_error_history.len() > 60 {
            self.ib_error_history.remove(0);
        }

        let slab_rate = self.metrics.slab_metrics.alloc_count as f64;
        self.slab_rate_history.push(slab_rate);
        if self.slab_rate_history.len() > 60 {
            self.slab_rate_history.remove(0);
        }

        let irq_total = self.metrics.interrupt_distribution.total_count as f64;
        self.irq_rate_history.push(irq_total);
        if self.irq_rate_history.len() > 60 {
            self.irq_rate_history.remove(0);
        }

        let cq_p99_us = self.metrics.cq_jitter.estimated_p99_ns() / 1000.0;
        self.cq_latency_history.push(cq_p99_us);
        if self.cq_latency_history.len() > 60 {
            self.cq_latency_history.remove(0);
        }

        let d = &self.metrics.ib_counter_deltas;
        if d.throughput_bytes() > 0 {
            self.rdma_has_byte_counters = true;
        }
        let throughput_val = if self.rdma_has_byte_counters {
            d.throughput_bytes() as f64 / 1024.0
        } else {
            d.throughput_pkts() as f64
        };
        self.rdma_throughput_history.push(throughput_val);
        if self.rdma_throughput_history.len() > 60 {
            self.rdma_throughput_history.remove(0);
        }
    }
}

pub struct Dashboard {
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
}

impl Dashboard {
    pub fn new() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        stdout().execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn draw(&mut self, state: &DashboardState) -> anyhow::Result<()> {
        self.terminal.draw(|frame| {
            render_dashboard(frame, state);
        })?;
        Ok(())
    }

    /// Returns true if the user pressed 'q' or Esc.
    pub fn poll_quit(&self) -> anyhow::Result<bool> {
        if event::poll(Duration::from_millis(0))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn shutdown(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }
}

impl Drop for Dashboard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = stdout().execute(LeaveAlternateScreen);
    }
}

fn render_dashboard(frame: &mut Frame, state: &DashboardState) {
    let area = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(6),    // IRQ distribution
            Constraint::Min(8),    // sparklines / metrics
            Constraint::Length(8), // event log
        ])
        .split(area);

    render_header(frame, outer[0], state);
    render_irq_distribution(frame, outer[1], state);
    render_metrics_panel(frame, outer[2], state);
    render_event_log(frame, outer[3], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let (style, label) = match state.health {
        HealthState::Healthy => (Style::default().fg(Color::Green).bold(), "HEALTHY"),
        HealthState::Degraded => (Style::default().fg(Color::Yellow).bold(), "DEGRADED"),
        HealthState::Recovering => (Style::default().fg(Color::Yellow).bold(), "RECOVERING"),
        HealthState::Critical => (
            Style::default()
                .fg(Color::Red)
                .bold()
                .add_modifier(Modifier::SLOW_BLINK),
            "CRITICAL",
        ),
    };

    let rdma_active = state
        .rdma_throughput_history
        .last()
        .is_some_and(|&v| v > 0.0);
    let (rdma_indicator, rdma_style) = if rdma_active {
        ("▲ active", Style::default().fg(Color::Green).bold())
    } else {
        ("— idle", Style::default().fg(Color::DarkGray))
    };

    // When the fabric is idle, surface it next to RDMA so operators can
    // tell "passive monitoring" apart from "monitoring offline." Hardware
    // error counters keep firing regardless.
    let fabric_idle = state.metrics.ib_fabric_idle();
    let max_idle = state.metrics.ib_max_idle_seconds();
    let (idle_indicator, idle_style) = if !state.metrics.ib_port_idle.is_empty() && fabric_idle {
        (
            format!(" | IB: passive ({max_idle}s idle)"),
            Style::default().fg(Color::Yellow),
        )
    } else if !state.metrics.ib_port_idle.is_empty() {
        (
            " | IB: traffic".to_string(),
            Style::default().fg(Color::Green),
        )
    } else {
        (String::new(), Style::default())
    };

    let header_text = Line::from(vec![
        Span::styled(" ARGUS ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("| State: "),
        Span::styled(format!("██ {label}"), style),
        Span::raw(format!(
            " | Source: {} | Events: {} | Uptime: {:.1}s | RDMA: ",
            state.source_name, state.event_count, state.uptime_secs
        )),
        Span::styled(rdma_indicator, rdma_style),
        Span::styled(idle_indicator, idle_style),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Adaptive RDMA Guard & Utilization Sentinel ")
        .title_style(Style::default().fg(Color::Cyan).bold());

    let para = Paragraph::new(header_text).block(block);
    frame.render_widget(para, area);
}

fn render_irq_distribution(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let dist = &state.metrics.interrupt_distribution;
    let total_cpus = dist.per_cpu_counts.len();
    let title = format!(" IRQ Distribution ({total_cpus} CPUs) ");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(title)
        .title_style(Style::default().fg(Color::White).bold());

    if dist.per_cpu_counts.is_empty() || dist.total_count == 0 {
        let para = Paragraph::new("  Waiting for interrupt data...")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(para, area);
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Sort CPUs by descending IRQ count so the hottest are always visible
    // even on 80-core nodes where a per-index list would hide them. We
    // keep the original CPU index alongside the count so the label
    // remains meaningful ("CPU 47" not "row 3").
    let mut indexed: Vec<(usize, u64)> = dist.per_cpu_counts.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| b.1.cmp(&a.1));

    let max_count = indexed.first().map_or(1, |(_, c)| *c).max(1);
    let active_count = indexed.iter().filter(|(_, c)| *c > 0).count();

    // Reserve the bottom row for a summary line. Show as many CPU bars
    // as fit above it. On a 13-row panel that's 12 CPUs; on a 30-row
    // panel that's 29. Always shows the hottest CPUs first.
    let summary_rows: u16 = 1;
    let bars_rows = inner.height.saturating_sub(summary_rows);
    let cpus_shown = (bars_rows as usize).min(indexed.len());

    let bar_area_width = inner.width.saturating_sub(20);

    for (row, (cpu, count)) in indexed.iter().take(cpus_shown).enumerate() {
        let pct = if dist.total_count > 0 {
            *count as f64 / dist.total_count as f64 * 100.0
        } else {
            0.0
        };
        let bar_len = ((*count as f64 / max_count as f64) * f64::from(bar_area_width)) as u16;
        let color = if pct >= 70.0 {
            Color::Red
        } else if pct >= 40.0 {
            Color::Yellow
        } else if *count > 0 {
            Color::Green
        } else {
            Color::DarkGray
        };

        let label = format!("  CPU{cpu:>3}");
        let bar = "█".repeat(bar_len as usize);
        let pct_str = format!(" {pct:>4.1}%");

        let line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(color)),
            Span::styled(pct_str, Style::default().fg(Color::DarkGray)),
        ]);

        let y = inner.y + row as u16;
        if y < inner.y + inner.height.saturating_sub(summary_rows) {
            frame.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));
        }
    }

    // Summary line at the bottom — always rendered, regardless of panel
    // size, so operators always see fleet-relevant stats: which CPU
    // dominates, how skewed, how many CPUs are active, and how many
    // are off-screen.
    let dominant_cpu = indexed.first().map_or(0, |(c, _)| *c);
    let dominant_pct = indexed.first().map_or(0.0, |(_, c)| {
        if dist.total_count > 0 {
            *c as f64 / dist.total_count as f64 * 100.0
        } else {
            0.0
        }
    });
    let perfect_share = 100.0 / total_cpus.max(1) as f64;
    let skew = if total_cpus > 1 && dominant_pct > perfect_share {
        ((dominant_pct - perfect_share) / (100.0 - perfect_share) * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let hidden = total_cpus.saturating_sub(cpus_shown);
    let summary_color = if skew >= 70.0 {
        Color::Red
    } else if skew >= 40.0 {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let summary = format!(
        "  Active: {active_count}/{total_cpus}  Hottest: CPU{dominant_cpu} ({dominant_pct:.1}%)  Skew: {skew:.0}%  Hidden: {hidden}"
    );
    let y = inner.y + inner.height.saturating_sub(summary_rows);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            summary,
            Style::default().fg(summary_color),
        ))),
        Rect::new(inner.x, y, inner.width, 1),
    );
}

fn render_metrics_panel(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    let rdma_active = state
        .rdma_throughput_history
        .last()
        .is_some_and(|&v| v > 0.0);
    let rdma_color = if rdma_active {
        Color::Green
    } else {
        Color::DarkGray
    };
    let rdma_label = if !rdma_active {
        " RDMA Traffic (idle) "
    } else if state.rdma_has_byte_counters {
        " RDMA Throughput (KB/w) "
    } else {
        " RDMA Traffic (pkts/w) "
    };
    render_sparkline_panel(
        frame,
        chunks[0],
        rdma_label,
        &state.rdma_throughput_history,
        rdma_color,
    );

    // CQ p99 latency is fed by eBPF CQ kprobes. If those didn't attach,
    // every value is 0 and the sparkline renders as an invisible flat
    // line — which looks identical to "broken" to an operator. Detect
    // the all-zero case and tag the title so the operator knows the
    // data path isn't producing data, not just that nothing's happened.
    let cq_has_any_data = state.cq_latency_history.iter().any(|&v| v > 0.0);
    let cq_color = if cq_has_any_data {
        Color::LightRed
    } else {
        Color::DarkGray
    };
    let cq_title = if !state.cq_latency_history.is_empty() && !cq_has_any_data {
        " CQ Latency p99 (us) — no data (kprobes off?) "
    } else {
        " CQ Latency p99 (us) "
    };
    render_sparkline_panel(
        frame,
        chunks[1],
        cq_title,
        &state.cq_latency_history,
        cq_color,
    );

    render_sparkline_panel(
        frame,
        chunks[2],
        " IB Errors (/window) ",
        &state.ib_error_history,
        Color::Magenta,
    );
    render_sparkline_panel(
        frame,
        chunks[3],
        " Slab Allocs (/window) ",
        &state.slab_rate_history,
        Color::Yellow,
    );
    render_sparkline_panel(
        frame,
        chunks[4],
        " IRQ Rate (/window) ",
        &state.irq_rate_history,
        Color::Cyan,
    );
}

fn render_sparkline_panel(frame: &mut Frame, area: Rect, title: &str, data: &[f64], color: Color) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(title)
        .title_style(Style::default().fg(color).bold());

    if data.is_empty() {
        let para = Paragraph::new("  Waiting for data...")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(para, area);
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let max_val = data
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max)
        .max(1.0);
    let u64_data: Vec<u64> = data.iter().map(|&v| (v / max_val * 100.0) as u64).collect();

    let sparkline = Sparkline::default()
        .data(&u64_data)
        .style(Style::default().fg(color));

    let current = data.last().copied().unwrap_or(0.0);
    let avg: f64 = data.iter().sum::<f64>() / data.len() as f64;
    let summary = Paragraph::new(format!(" cur: {current:.1}  avg: {avg:.1}"))
        .style(Style::default().fg(Color::DarkGray));

    if inner.height >= 2 {
        let spark_area = Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(1),
        );
        let summary_area = Rect::new(
            inner.x,
            inner.y + inner.height.saturating_sub(1),
            inner.width,
            1,
        );
        frame.render_widget(sparkline, spark_area);
        frame.render_widget(summary, summary_area);
    } else {
        frame.render_widget(sparkline, inner);
    }
}

fn render_event_log(frame: &mut Frame, area: Rect, state: &DashboardState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Recent Alerts ")
        .title_style(Style::default().fg(Color::White).bold());

    if state.recent_alerts.is_empty() {
        let para = Paragraph::new("  No alerts - system nominal")
            .style(Style::default().fg(Color::Green))
            .block(block);
        frame.render_widget(para, area);
        return;
    }

    let inner_height = block.inner(area).height as usize;
    let visible_alerts = state
        .recent_alerts
        .iter()
        .rev()
        .take(inner_height)
        .collect::<Vec<_>>();

    let lines: Vec<Line> = visible_alerts
        .iter()
        .rev()
        .map(|alert| {
            let ts_display = {
                let secs = (alert.timestamp_ns / 1_000_000_000) as i64;
                chrono::DateTime::from_timestamp(secs, 0).map_or_else(
                    || "??:??:??".to_string(),
                    |utc| {
                        utc.with_timezone(&chrono::Local)
                            .format("%H:%M:%S")
                            .to_string()
                    },
                )
            };
            let severity_style = match alert.severity {
                HealthState::Healthy => Style::default().fg(Color::Green),
                HealthState::Degraded | HealthState::Recovering => {
                    Style::default().fg(Color::Yellow)
                }
                HealthState::Critical => Style::default().fg(Color::Red).bold(),
            };

            Line::from(vec![
                Span::styled(
                    format!("  {ts_display:>8} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{:<24} ", alert.kind_name()),
                    Style::default().fg(Color::White),
                ),
                Span::styled(format!("[{}] ", alert.severity), severity_style),
                Span::styled(&alert.message, Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

/// Render a single frame to a string buffer (for snapshot testing).
#[must_use]
pub fn render_to_string(state: &DashboardState, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| render_dashboard(frame, state))
        .expect("draw");
    let buf = terminal.backend().buffer().clone();

    let mut output =
        String::with_capacity(usize::from(width) * usize::from(height) + usize::from(height));
    let mut line = String::with_capacity(usize::from(width));
    for y in 0..height {
        line.clear();
        for x in 0..width {
            let cell = &buf[(x, y)];
            line.push_str(cell.symbol());
        }
        // Trim only this row's trailing whitespace — trimming the whole
        // accumulated buffer is O(N²) and silently eats blank rows whose
        // preceding '\n' gets stripped along with the trailing spaces.
        let end = line.trim_end().len();
        output.push_str(&line[..end]);
        output.push('\n');
    }
    output
}
