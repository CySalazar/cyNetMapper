//! Timing and rate limiting for cyNetMapper scans

use crate::config::{Config, TimingTemplate};
use crate::error::{Error, Result};

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tracing::{debug, trace};

/// Timing controller for scan operations
#[derive(Debug, Clone)]
pub struct TimingController {
    /// Configuration reference
    config: Arc<Config>,
    /// Current timing template
    template: TimingTemplate,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Concurrency limiter
    concurrency_limiter: Arc<Semaphore>,
    /// Adaptive timing state
    adaptive_state: Arc<tokio::sync::Mutex<AdaptiveTimingState>>,
}

/// Rate limiter for controlling scan speed
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum packets per second
    max_pps: u64,
    /// Token bucket for rate limiting
    token_bucket: Arc<tokio::sync::Mutex<TokenBucket>>,
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Current number of tokens
    tokens: f64,
    /// Maximum number of tokens
    capacity: f64,
    /// Token refill rate (tokens per second)
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

/// Adaptive timing state
#[derive(Debug)]
struct AdaptiveTimingState {
    /// Current round trip time estimate
    rtt_estimate: Duration,
    /// RTT variance
    rtt_variance: Duration,
    /// Number of timeouts encountered
    timeout_count: u64,
    /// Number of successful responses
    success_count: u64,
    /// Current congestion window
    congestion_window: u32,
    /// Slow start threshold
    ssthresh: u32,
    /// Last adjustment time
    last_adjustment: Instant,
}

/// Timing configuration for different scan phases
#[derive(Debug, Clone)]
pub struct ScanTiming {
    /// Initial timeout
    pub initial_timeout: Duration,
    /// Maximum timeout
    pub max_timeout: Duration,
    /// Minimum timeout
    pub min_timeout: Duration,
    /// Retry count
    pub max_retries: u32,
    /// Delay between retries
    pub retry_delay: Duration,
    /// Host timeout
    pub host_timeout: Duration,
    /// Scan delay (between probes)
    pub scan_delay: Duration,
    /// Maximum rate (packets per second)
    pub max_rate: u64,
    /// Parallelism level
    pub parallelism: u32,
}

/// Timing statistics
#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Total timeouts
    pub timeouts: u64,
    /// Total retries
    pub retries: u64,
    /// Average RTT
    pub avg_rtt: Duration,
    /// Minimum RTT
    pub min_rtt: Duration,
    /// Maximum RTT
    pub max_rtt: Duration,
    /// Current rate (packets per second)
    pub current_rate: f64,
    /// Scan start time
    pub start_time: Option<Instant>,
    /// Scan duration
    pub duration: Duration,
}

/// Timing event for adaptive adjustments
#[derive(Debug, Clone)]
pub enum TimingEvent {
    /// Successful response received
    Success {
        /// Round trip time
        rtt: Duration,
    },
    /// Timeout occurred
    Timeout {
        /// Timeout duration
        timeout: Duration,
    },
    /// Error occurred
    Error {
        /// Error type
        error_type: String,
    },
    /// Rate limit hit
    RateLimit,
    /// Congestion detected
    Congestion,
}

impl TimingController {
    /// Create a new timing controller
    pub fn new(config: &Config) -> Result<Self> {
        let timing_config = &config.timing;
        let template = timing_config.timing_template;
        
        // Use rate_limit or default to 1000 pps
        let max_rate = timing_config.rate_limit.unwrap_or(1000.0) as u64;
        let rate_limiter = Arc::new(RateLimiter::new(max_rate));
        
        // Use max_concurrency from scan config or default to 100
        let max_concurrency = config.scan.max_concurrency;
        let concurrency_limiter = Arc::new(Semaphore::new(max_concurrency));
        
        let adaptive_state = Arc::new(tokio::sync::Mutex::new(AdaptiveTimingState::new()));
        
        Ok(Self {
            config: Arc::new(config.clone()),
            template,
            rate_limiter,
            concurrency_limiter,
            adaptive_state,
        })
    }
    
    /// Get timing configuration for scan phase
    pub fn get_scan_timing(&self, phase: ScanPhase) -> ScanTiming {
        match self.template {
            TimingTemplate::T0 => self.get_paranoid_timing(phase),
            TimingTemplate::T1 => self.get_sneaky_timing(phase),
            TimingTemplate::T2 => self.get_polite_timing(phase),
            TimingTemplate::T3 => self.get_normal_timing(phase),
            TimingTemplate::T4 => self.get_aggressive_timing(phase),
            TimingTemplate::T5 => self.get_insane_timing(phase),
        }
    }
    
    /// Wait for rate limit permission
    pub async fn wait_for_rate_limit(&self) -> Result<()> {
        self.rate_limiter.acquire().await
    }
    
    /// Acquire concurrency permit
    pub async fn acquire_concurrency_permit(&self) -> Result<tokio::sync::SemaphorePermit> {
        self.concurrency_limiter.acquire().await
            .map_err(|e| Error::Internal { message: format!("Failed to acquire concurrency permit: {}", e) })
    }
    
    /// Execute operation with timeout
    pub async fn with_timeout<F, T>(&self, operation: F, timeout_duration: Duration) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        match timeout(timeout_duration, operation).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout { timeout_ms: timeout_duration.as_millis() as u64 }),
        }
    }
    
    /// Record timing event for adaptive adjustments
    pub async fn record_event(&self, event: TimingEvent) {
        let mut state = self.adaptive_state.lock().await;
        state.record_event(event).await;
    }
    
    /// Get current timing statistics
    pub async fn get_stats(&self) -> TimingStats {
        let state = self.adaptive_state.lock().await;
        state.get_stats()
    }
    
    /// Get adaptive timeout based on current conditions
    pub async fn get_adaptive_timeout(&self, base_timeout: Duration) -> Duration {
        let state = self.adaptive_state.lock().await;
        state.calculate_adaptive_timeout(base_timeout)
    }
    
    /// Get paranoid timing (very slow and stealthy)
    fn get_paranoid_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_secs(300),
            max_timeout: Duration::from_secs(900),
            min_timeout: Duration::from_secs(100),
            max_retries: 10,
            retry_delay: Duration::from_secs(60),
            host_timeout: Duration::from_secs(900),
            scan_delay: Duration::from_secs(5),
            max_rate: 1, // 1 packet per second
            parallelism: 1,
        }
    }
    
    /// Get sneaky timing (slow and stealthy)
    fn get_sneaky_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_secs(15),
            max_timeout: Duration::from_secs(300),
            min_timeout: Duration::from_secs(5),
            max_retries: 5,
            retry_delay: Duration::from_secs(15),
            host_timeout: Duration::from_secs(300),
            scan_delay: Duration::from_secs(1),
            max_rate: 10,
            parallelism: 1,
        }
    }
    
    /// Get polite timing (respectful of target resources)
    fn get_polite_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_secs(10),
            max_timeout: Duration::from_secs(60),
            min_timeout: Duration::from_secs(2),
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            host_timeout: Duration::from_secs(60),
            scan_delay: Duration::from_millis(400),
            max_rate: 100,
            parallelism: 10,
        }
    }
    
    /// Get normal timing (balanced speed and stealth)
    fn get_normal_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_secs(3),
            max_timeout: Duration::from_secs(30),
            min_timeout: Duration::from_millis(500),
            max_retries: 2,
            retry_delay: Duration::from_secs(1),
            host_timeout: Duration::from_secs(30),
            scan_delay: Duration::from_millis(100),
            max_rate: 1000,
            parallelism: 50,
        }
    }
    
    /// Get aggressive timing (fast scanning)
    fn get_aggressive_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_secs(1),
            max_timeout: Duration::from_secs(10),
            min_timeout: Duration::from_millis(100),
            max_retries: 1,
            retry_delay: Duration::from_millis(250),
            host_timeout: Duration::from_secs(15),
            scan_delay: Duration::from_millis(10),
            max_rate: 5000,
            parallelism: 100,
        }
    }
    
    /// Get insane timing (maximum speed, may overwhelm targets)
    fn get_insane_timing(&self, _phase: ScanPhase) -> ScanTiming {
        ScanTiming {
            initial_timeout: Duration::from_millis(250),
            max_timeout: Duration::from_secs(5),
            min_timeout: Duration::from_millis(50),
            max_retries: 0,
            retry_delay: Duration::from_millis(100),
            host_timeout: Duration::from_secs(5),
            scan_delay: Duration::from_millis(1),
            max_rate: 10000,
            parallelism: 300,
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_pps: u64) -> Self {
        let token_bucket = Arc::new(tokio::sync::Mutex::new(TokenBucket::new(max_pps as f64)));
        
        Self {
            max_pps,
            token_bucket,
        }
    }
    
    /// Acquire permission to send a packet
    pub async fn acquire(&self) -> Result<()> {
        let mut bucket = self.token_bucket.lock().await;
        
        // Refill tokens based on elapsed time
        bucket.refill();
        
        // Check if we have tokens available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            trace!("Rate limit token acquired, {} tokens remaining", bucket.tokens);
            Ok(())
        } else {
            // Calculate wait time for next token
            let wait_time = Duration::from_secs_f64(1.0 / bucket.refill_rate);
            trace!("Rate limit exceeded, waiting {:?}", wait_time);
            
            // Release lock before sleeping
            drop(bucket);
            
            // Wait for token refill
            sleep(wait_time).await;
            
            // Try again
            Box::pin(self.acquire()).await
        }
    }
    
    /// Update rate limit
    pub async fn update_rate(&self, new_rate: u64) {
        let mut bucket = self.token_bucket.lock().await;
        bucket.refill_rate = new_rate as f64;
        bucket.capacity = new_rate as f64;
        debug!("Rate limit updated to {} pps", new_rate);
    }
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity,
            last_refill: Instant::now(),
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        if elapsed > 0.0 {
            let new_tokens = elapsed * self.refill_rate;
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}

impl AdaptiveTimingState {
    /// Create new adaptive timing state
    fn new() -> Self {
        Self {
            rtt_estimate: Duration::from_millis(100),
            rtt_variance: Duration::from_millis(50),
            timeout_count: 0,
            success_count: 0,
            congestion_window: 1,
            ssthresh: 65535,
            last_adjustment: Instant::now(),
        }
    }
    
    /// Record a timing event
    async fn record_event(&mut self, event: TimingEvent) {
        match event {
            TimingEvent::Success { rtt } => {
                self.success_count += 1;
                self.update_rtt_estimate(rtt);
                self.increase_congestion_window();
            },
            TimingEvent::Timeout { timeout: _ } => {
                self.timeout_count += 1;
                self.decrease_congestion_window();
            },
            TimingEvent::Error { error_type: _ } => {
                self.decrease_congestion_window();
            },
            TimingEvent::RateLimit => {
                // Rate limit hit, slow down
                self.decrease_congestion_window();
            },
            TimingEvent::Congestion => {
                self.decrease_congestion_window();
            },
        }
        
        self.last_adjustment = Instant::now();
    }
    
    /// Update RTT estimate using exponential weighted moving average
    fn update_rtt_estimate(&mut self, rtt: Duration) {
        let alpha = 0.125; // Standard TCP alpha
        let beta = 0.25;   // Standard TCP beta
        
        // Update RTT estimate
        let rtt_diff = if rtt > self.rtt_estimate {
            rtt - self.rtt_estimate
        } else {
            self.rtt_estimate - rtt
        };
        
        self.rtt_variance = Duration::from_nanos(
            ((1.0 - beta) * self.rtt_variance.as_nanos() as f64 + 
             beta * rtt_diff.as_nanos() as f64) as u64
        );
        
        self.rtt_estimate = Duration::from_nanos(
            ((1.0 - alpha) * self.rtt_estimate.as_nanos() as f64 + 
             alpha * rtt.as_nanos() as f64) as u64
        );
    }
    
    /// Increase congestion window (slow start or congestion avoidance)
    fn increase_congestion_window(&mut self) {
        if self.congestion_window < self.ssthresh {
            // Slow start: exponential increase
            self.congestion_window *= 2;
        } else {
            // Congestion avoidance: linear increase
            self.congestion_window += 1;
        }
        
        // Cap at reasonable maximum
        self.congestion_window = self.congestion_window.min(1000);
    }
    
    /// Decrease congestion window (congestion detected)
    fn decrease_congestion_window(&mut self) {
        self.ssthresh = self.congestion_window / 2;
        self.congestion_window = self.ssthresh.max(1);
    }
    
    /// Calculate adaptive timeout
    fn calculate_adaptive_timeout(&self, base_timeout: Duration) -> Duration {
        // Use TCP-style RTO calculation
        let rto = self.rtt_estimate + Duration::from_nanos((4 * self.rtt_variance.as_nanos()).max(1).min(u64::MAX as u128) as u64);
        
        // Use the larger of base timeout and calculated RTO
        base_timeout.max(rto)
    }
    
    /// Get timing statistics
    fn get_stats(&self) -> TimingStats {
        let total_packets = self.success_count + self.timeout_count;
        let loss_rate = if total_packets > 0 {
            self.timeout_count as f64 / total_packets as f64
        } else {
            0.0
        };
        
        TimingStats {
            packets_sent: total_packets,
            packets_received: self.success_count,
            timeouts: self.timeout_count,
            retries: 0, // TODO: Track retries separately
            avg_rtt: self.rtt_estimate,
            min_rtt: self.rtt_estimate, // TODO: Track min/max separately
            max_rtt: self.rtt_estimate,
            current_rate: if loss_rate < 0.1 { 100.0 } else { 10.0 }, // Simplified
            start_time: None,
            duration: Duration::from_secs(0),
        }
    }
}

/// Scan phases for timing configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    /// Host discovery phase
    HostDiscovery,
    /// Port scanning phase
    PortScanning,
    /// Service detection phase
    ServiceDetection,
    /// OS fingerprinting phase
    OsFingerprinting,
    /// Script scanning phase
    ScriptScanning,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_timing_controller_creation() {
        let config = Config::default();
        let controller = TimingController::new(&config);
        assert!(controller.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(10); // 10 pps
        
        // Should be able to acquire immediately
        let start = Instant::now();
        limiter.acquire().await.unwrap();
        let first_acquire = start.elapsed();
        
        // Second acquire should be delayed
        limiter.acquire().await.unwrap();
        let second_acquire = start.elapsed();
        
        assert!(second_acquire > first_acquire);
        assert!(second_acquire >= Duration::from_millis(90)); // Allow some tolerance
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10.0);
        
        // Consume all tokens
        bucket.tokens = 0.0;
        
        // Wait for refill
        sleep(Duration::from_millis(200)).await;
        bucket.refill();
        
        // Should have some tokens now
        assert!(bucket.tokens > 0.0);
    }

    #[tokio::test]
    async fn test_adaptive_timing() {
        let mut state = AdaptiveTimingState::new();
        
        // Record successful events
        for _ in 0..10 {
            state.record_event(TimingEvent::Success {
                rtt: Duration::from_millis(50),
            }).await;
        }
        
        // Congestion window should have increased
        assert!(state.congestion_window > 1);
        
        // Record timeout
        state.record_event(TimingEvent::Timeout {
            timeout: Duration::from_secs(1),
        }).await;
        
        // Congestion window should have decreased
        assert!(state.congestion_window < 10);
    }

    #[tokio::test]
    async fn test_timing_templates() {
        let config = Config::default();
        let controller = TimingController::new(&config).unwrap();
        
        // Test different timing templates
        let paranoid = controller.get_scan_timing(ScanPhase::PortScanning);
        assert!(paranoid.max_rate <= 1);
        assert!(paranoid.parallelism <= 1);
        
        // Change to aggressive template
        let mut aggressive_config = config.clone();
        aggressive_config.timing.timing_template = TimingTemplate::T4;
        let aggressive_controller = TimingController::new(&aggressive_config).unwrap();
        
        let aggressive = aggressive_controller.get_scan_timing(ScanPhase::PortScanning);
        assert!(aggressive.max_rate >= 1000);
        assert!(aggressive.parallelism >= 50);
    }

    #[tokio::test]
    async fn test_concurrency_limiting() {
        let config = Config::default();
        let controller = TimingController::new(&config).unwrap();
        
        // Acquire multiple permits
        let permit1 = controller.acquire_concurrency_permit().await.unwrap();
        let permit2 = controller.acquire_concurrency_permit().await.unwrap();
        
        // Permits should be valid when acquired successfully
        drop(permit1);
        drop(permit2);
    }

    #[tokio::test]
    async fn test_timeout_operation() {
        let config = Config::default();
        let controller = TimingController::new(&config).unwrap();
        
        // Test successful operation
        let result = controller.with_timeout(
            async { Ok("success") },
            Duration::from_secs(1)
        ).await;
        assert!(result.is_ok());
        
        // Test timeout
        let result = controller.with_timeout(
            async {
                sleep(Duration::from_secs(2)).await;
                Ok("should timeout")
            },
            Duration::from_millis(100)
        ).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_configurations() {
        let config = Config::default();
        let controller = TimingController::new(&config).unwrap();
        
        // Test all timing templates
        let templates = [
            TimingTemplate::T0,
            TimingTemplate::T1,
            TimingTemplate::T2,
            TimingTemplate::T3,
            TimingTemplate::T4,
            TimingTemplate::T5,
        ];
        
        for template in &templates {
            let mut test_config = config.clone();
            test_config.timing.timing_template = *template;
            let test_controller = TimingController::new(&test_config).unwrap();
            
            let timing = test_controller.get_scan_timing(ScanPhase::PortScanning);
            
            // Verify timing makes sense
            assert!(timing.min_timeout <= timing.initial_timeout);
            assert!(timing.initial_timeout <= timing.max_timeout);
            assert!(timing.max_retries <= 10);
            assert!(timing.parallelism >= 1);
            assert!(timing.max_rate >= 1);
        }
    }
}