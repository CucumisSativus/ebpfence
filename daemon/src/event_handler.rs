use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use globset::{Glob, GlobSet, GlobSetBuilder};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::BlockStrategy;
use crate::ebpf_provider::{EBPFProvider, Event};

pub struct EventHandlerConfig {
    pub disallowed_patterns: Vec<String>,
    pub threshold: u32,
    pub target_pid: u32,
    pub strategy: BlockStrategy,
}

struct HandlerState {
    violation_counts: HashMap<u32, u32>,
    blocked_pids: HashSet<u32>,
}

pub struct EventHandler {
    provider: Arc<dyn EBPFProvider>,
    config: EventHandlerConfig,
    globs: GlobSet,
    state: RwLock<HandlerState>,
}

impl EventHandler {
    pub fn new(
        provider: Arc<dyn EBPFProvider>,
        config: EventHandlerConfig,
    ) -> anyhow::Result<Self> {
        let globs = build_glob_set(&config.disallowed_patterns)?;
        Ok(EventHandler {
            provider,
            config,
            globs,
            state: RwLock::new(HandlerState {
                violation_counts: HashMap::new(),
                blocked_pids: HashSet::new(),
            }),
        })
    }

    pub async fn run(self: Arc<Self>, token: CancellationToken) -> anyhow::Result<()> {
        if self.config.disallowed_patterns.is_empty() {
            anyhow::bail!("no disallowed patterns configured");
        }
        if self.config.threshold == 0 {
            anyhow::bail!("threshold must be greater than 0");
        }

        info!(
            patterns = ?self.config.disallowed_patterns,
            threshold = self.config.threshold,
            strategy = %self.config.strategy,
            "Starting event handler",
        );
        if self.config.target_pid != 0 {
            info!(target_pid = self.config.target_pid, "Monitoring specific PID");
        }

        // When cancelled, close the provider so read_event() unblocks.
        {
            let provider = self.provider.clone();
            let t = token.clone();
            tokio::spawn(async move {
                t.cancelled().await;
                provider.close();
            });
        }

        loop {
            let provider = self.provider.clone();
            let result =
                tokio::task::spawn_blocking(move || provider.read_event()).await?;

            match result {
                Ok(event) => {
                    if let Err(e) = self.process_event(&event) {
                        error!("processing event: {}", e);
                    }
                }
                Err(_) if token.is_cancelled() => return Ok(()),
                Err(e) => {
                    error!("reading event: {}", e);
                    continue;
                }
            }
        }
    }

    fn process_event(&self, event: &Event) -> anyhow::Result<()> {
        // Filter by PID if configured
        if self.config.target_pid != 0 && event.pid != self.config.target_pid {
            return Ok(());
        }

        let comm = null_term_str(&event.comm);
        let filename = null_term_str(&event.filename);

        if !self.matches_pattern(&filename) {
            return Ok(());
        }

        let mut state = self.state.write().unwrap();
        let count = state.violation_counts.entry(event.pid).or_insert(0);
        *count += 1;
        let violations = *count;

        println!(
            "[VIOLATION {}/{}] PID {} ({}) opened disallowed file: {}",
            violations, self.config.threshold, event.pid, comm, filename
        );

        if violations >= self.config.threshold && !state.blocked_pids.contains(&event.pid) {
            self.provider.block_pid(event.pid)?;
            state.blocked_pids.insert(event.pid);
            println!(
                "\n*** PID {} is now BLOCKED from {}! ***\n",
                event.pid,
                blocking_description(&self.config.strategy)
            );
        }

        Ok(())
    }

    fn matches_pattern(&self, filename: &str) -> bool {
        if self.globs.is_match(filename) {
            return true;
        }
        // Substring fallback for plain patterns that contain no glob metacharacters
        for pattern in &self.config.disallowed_patterns {
            if !pattern.contains(['*', '?', '[', '{']) && filename.contains(pattern.as_str()) {
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn get_violation_count(&self) -> u32 {
        self.state
            .read()
            .unwrap()
            .violation_counts
            .values()
            .sum()
    }

    pub fn get_violation_count_for_pid(&self, pid: u32) -> u32 {
        self.state
            .read()
            .unwrap()
            .violation_counts
            .get(&pid)
            .copied()
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn is_pid_blocked(&self, pid: u32) -> bool {
        self.state.read().unwrap().blocked_pids.contains(&pid)
    }

    pub fn get_blocked_pids(&self) -> Vec<u32> {
        self.state
            .read()
            .unwrap()
            .blocked_pids
            .iter()
            .copied()
            .collect()
    }

    pub fn unblock_pid(&self, pid: u32) -> anyhow::Result<()> {
        let mut state = self.state.write().unwrap();
        if !state.blocked_pids.contains(&pid) {
            anyhow::bail!("PID {} is not blocked", pid);
        }
        self.provider.unblock_pid(pid)?;
        state.blocked_pids.remove(&pid);
        state.violation_counts.remove(&pid);
        println!(
            "\n*** PID {} has been UNBLOCKED and can resume {}. ***\n",
            pid,
            blocking_description(&self.config.strategy)
        );
        Ok(())
    }
}

fn null_term_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn build_glob_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat)?);
    }
    Ok(builder.build()?)
}

fn blocking_description(strategy: &BlockStrategy) -> &'static str {
    match strategy {
        BlockStrategy::BlockNetwork => "socket connections",
        BlockStrategy::BlockBoth => "file opens and socket connections",
        BlockStrategy::BlockFiles => "file opens",
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf_provider::MockEBPFProvider;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn make_handler(
        provider: Arc<MockEBPFProvider>,
        patterns: Vec<&str>,
        threshold: u32,
    ) -> Arc<EventHandler> {
        Arc::new(
            EventHandler::new(
                provider as Arc<dyn EBPFProvider>,
                EventHandlerConfig {
                    disallowed_patterns: patterns.into_iter().map(String::from).collect(),
                    threshold,
                    target_pid: 0,
                    strategy: BlockStrategy::BlockFiles,
                },
            )
            .unwrap(),
        )
    }

    /// Wait for the mock provider to drain all events, then cancel the handler
    /// and wait for it to exit. Returns once the handler has cleanly stopped.
    async fn drain_and_stop(
        provider: Arc<MockEBPFProvider>,
        token: CancellationToken,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        // Wait until all events have been consumed AND the last one processed.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !provider.drained.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed out waiting for events to drain");

        // Cancel and directly shut down the provider so the blocking read_event() unblocks.
        token.cancel();
        provider.shutdown();

        // Wait for the handler task to exit cleanly.
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("handler task timed out")
            .expect("handler task panicked")
            .expect("handler returned an error");
    }

    #[tokio::test]
    async fn test_violation_increments() {
        let events = vec![MockEBPFProvider::make_event(100, 1000, "test", "/etc/passwd")];
        let provider = Arc::new(MockEBPFProvider::new(events));
        let handler = make_handler(provider.clone(), vec!["/etc/passwd"], 5);

        let token = CancellationToken::new();
        let h = handler.clone();
        let t = token.clone();
        let task = tokio::spawn(async move { h.run(t).await });

        drain_and_stop(provider, token, task).await;

        assert_eq!(handler.get_violation_count_for_pid(100), 1);
        assert!(!handler.is_pid_blocked(100));
    }

    #[tokio::test]
    async fn test_pid_blocked_at_threshold() {
        let events = vec![
            MockEBPFProvider::make_event(42, 0, "proc", "/etc/shadow"),
            MockEBPFProvider::make_event(42, 0, "proc", "/etc/shadow"),
        ];
        let provider = Arc::new(MockEBPFProvider::new(events));
        let handler = make_handler(provider.clone(), vec!["/etc/shadow"], 2);

        let token = CancellationToken::new();
        let h = handler.clone();
        let t = token.clone();
        let task = tokio::spawn(async move { h.run(t).await });

        let p = provider.clone();
        drain_and_stop(p, token, task).await;

        assert_eq!(handler.get_violation_count_for_pid(42), 2);
        assert!(handler.is_pid_blocked(42));
        assert!(provider.is_pid_blocked(42));
    }

    #[tokio::test]
    async fn test_non_matching_file_ignored() {
        let events = vec![MockEBPFProvider::make_event(7, 0, "proc", "/tmp/harmless.txt")];
        let provider = Arc::new(MockEBPFProvider::new(events));
        let handler = make_handler(provider.clone(), vec!["/etc/passwd"], 1);

        let token = CancellationToken::new();
        let h = handler.clone();
        let t = token.clone();
        let task = tokio::spawn(async move { h.run(t).await });

        drain_and_stop(provider, token, task).await;

        assert_eq!(handler.get_violation_count(), 0);
        assert!(!handler.is_pid_blocked(7));
    }

    #[tokio::test]
    async fn test_glob_wildcard_match() {
        let events = vec![MockEBPFProvider::make_event(5, 0, "logger", "/var/log/app.log")];
        let provider = Arc::new(MockEBPFProvider::new(events));
        let handler = make_handler(provider.clone(), vec!["/var/log/*.log"], 1);

        let token = CancellationToken::new();
        let h = handler.clone();
        let t = token.clone();
        let task = tokio::spawn(async move { h.run(t).await });

        drain_and_stop(provider, token, task).await;

        assert!(handler.is_pid_blocked(5));
    }

    #[tokio::test]
    async fn test_unblock_pid() {
        let events = vec![MockEBPFProvider::make_event(99, 0, "proc", "/etc/passwd")];
        let provider = Arc::new(MockEBPFProvider::new(events));
        let handler = make_handler(provider.clone(), vec!["/etc/passwd"], 1);

        let token = CancellationToken::new();
        let h = handler.clone();
        let t = token.clone();
        let task = tokio::spawn(async move { h.run(t).await });

        let p = provider.clone();
        drain_and_stop(p, token, task).await;

        assert!(handler.is_pid_blocked(99));
        handler.unblock_pid(99).unwrap();
        assert!(!handler.is_pid_blocked(99));
        assert!(!provider.is_pid_blocked(99));
    }

    #[test]
    fn test_matches_pattern_glob() {
        let handler = make_handler(
            Arc::new(MockEBPFProvider::new(vec![])),
            vec!["/var/log/**/*.log"],
            1,
        );
        assert!(handler.matches_pattern("/var/log/app/debug.log"));
        assert!(!handler.matches_pattern("/etc/passwd"));
    }

    #[test]
    fn test_matches_pattern_substring() {
        let handler = make_handler(
            Arc::new(MockEBPFProvider::new(vec![])),
            vec!["secret"],
            1,
        );
        assert!(handler.matches_pattern("/home/user/secret/file.txt"));
        assert!(!handler.matches_pattern("/home/user/public/file.txt"));
    }
}
