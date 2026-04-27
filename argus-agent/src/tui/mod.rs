pub mod widgets;

use argus_common::{AggregatedMetrics, Alert, HealthState};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{prelude::*, widgets::*};
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
        .map_or(false, |&v| v > 0.0);
    let (rdma_indicator, rdma_style) = if rdma_active {
        ("▲ active", Style::default().fg(Color::Green).bold())
    } else {
        ("— idle", Style::default().fg(Color::DarkGray))
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
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" IRQ Distribution ")
        .title_style(Style::default().fg(Color::White).bold());

    if dist.per_cpu_counts.is_empty() || dist.total_count == 0 {
        let para = Paragraph::new("  Waiting for interrupt data...")
            .style(Style::default().fg(Color::DarkGray))
            .block(block);
        frame.render_widget(para, area);
        return;
    }

    let max_count = dist
        .per_cpu_counts
        .iter()
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let bar_area_width = inner.width.saturating_sub(16);
    let num_cpus = dist.per_cpu_counts.len().min(inner.height as usize);

    for (i, &count) in dist.per_cpu_counts.iter().take(num_cpus).enumerate() {
        let pct = if dist.total_count > 0 {
            count as f64 / dist.total_count as f64 * 100.0
        } else {
            0.0
        };
        let bar_len = ((count as f64 / max_count as f64) * bar_area_width as f64) as u16;
        let color = if pct >= 70.0 {
            Color::Red
        } else if pct >= 40.0 {
            Color::Yellow
        } else {
            Color::Green
        };

        let label = format!("  CPU{i:<2}");
        let bar = "█".repeat(bar_len as usize);
        let pct_str = format!(" {pct:.0}%");

        let line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::White)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(color)),
            Span::styled(pct_str, Style::default().fg(Color::DarkGray)),
        ]);

        let y = inner.y + i as u16;
        if y < inner.y + inner.height {
            frame.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));
        }
    }
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
        .map_or(false, |&v| v > 0.0);
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

    let cq_has_data = state.cq_latency_history.last().map_or(false, |&v| v > 0.0);
    let cq_color = if cq_has_data {
        Color::LightRed
    } else {
        Color::DarkGray
    };
    render_sparkline_panel(
        frame,
        chunks[1],
        " CQ Latency p99 (us) ",
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
            let ts_secs = alert.timestamp_ns as f64 / 1_000_000_000.0;
            let severity_style = match alert.severity {
                HealthState::Healthy => Style::default().fg(Color::Green),
                HealthState::Degraded | HealthState::Recovering => Style::default().fg(Color::Yellow),
                HealthState::Critical => Style::default().fg(Color::Red).bold(),
            };

            Line::from(vec![
                Span::styled(
                    format!("  {ts_secs:>10.3}s "),
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
pub fn render_to_string(state: &DashboardState, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| render_dashboard(frame, state))
        .expect("draw");
    let buf = terminal.backend().buffer().clone();

    let mut output = String::with_capacity(usize::from(width) * usize::from(height) + usize::from(height));
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
