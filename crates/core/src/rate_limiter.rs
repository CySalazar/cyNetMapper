//! Rate limiting and network congestion control for cyNetMapper
//!
//! This module provides adaptive rate limiting capabilities to prevent
//! network congestion and respect target system limitations.

use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::time::sleep;

/// Adaptive rate limiter that adjusts based on network conditions
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimiter {
    /// Maximum packets per second
    max_pps: f64,
    /// Current packets per second
    current_pps: f64,
    /// Minimum packets per second
    min_pps: f64,
    /// Rate adjustment factor
    adjustment_factor: f64,
    /// Window for measuring response times
    response_times: VecDeque<Duration>,
    /// Maximum window size
    max_window_size: usize,
    /// Last packet send time
    last_send: Option<Instant>,
    /// Congestion detection threshold
    congestion_threshold: Duration,
    /// Recovery factor when congestion clears
    recovery_factor: f64,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(initial_pps: f64, min_pps: f64, max_pps: f64) -> Self {
        Self {
            max_pps,
            current_pps: initial_pps,
            min_pps,
            adjustment_factor: 0.8,
            response_times: VecDeque::new(),
            max_window_size: 100,
            last_send: None,
            congestion_threshold: Duration::from_millis(1000),
            recovery_factor: 1.1,
        }
    }
    
    /// Wait for the appropriate delay before sending next packet
    pub async fn wait_for_next(&mut self) {
        let now = Instant::now();
        
        if let Some(last) = self.last_send {
            let elapsed = now.duration_since(last);
            let required_interval = Duration::from_secs_f64(1.0 / self.current_pps);
            
            if elapsed < required_interval {
                let wait_time = required_interval - elapsed;
                sleep(wait_time).await;
            }
        }
        
        self.last_send = Some(Instant::now());
    }
    
    /// Record a response time and adjust rate accordingly
    pub fn record_response(&mut self, response_time: Duration) {
        self.response_times.push_back(response_time);
        
        if self.response_times.len() > self.max_window_size {
            self.response_times.pop_front();
        }
        
        self.adjust_rate();
    }
    
    /// Record a timeout or error and reduce rate
    pub fn record_timeout(&mut self) {
        // Treat timeouts as very slow responses
        self.record_response(self.congestion_threshold * 2);
    }
    
    /// Adjust the current rate based on recent response times
    fn adjust_rate(&mut self) {
        if self.response_times.len() < 10 {
            return; // Not enough data
        }
        
        let avg_response_time = self.average_response_time();
        
        if avg_response_time > self.congestion_threshold {
            // Congestion detected, reduce rate
            self.current_pps = (self.current_pps * self.adjustment_factor).max(self.min_pps);
        } else if avg_response_time < self.congestion_threshold / 2 {
            // Good performance, can increase rate
            self.current_pps = (self.current_pps * self.recovery_factor).min(self.max_pps);
        }
    }
    
    /// Calculate average response time from recent samples
    fn average_response_time(&self) -> Duration {
        if self.response_times.is_empty() {
            return Duration::from_millis(0);
        }
        
        let total: Duration = self.response_times.iter().sum();
        total / self.response_times.len() as u32
    }
    
    /// Get current packets per second rate
    pub fn current_rate(&self) -> f64 {
        self.current_pps
    }
    
    /// Set maximum rate
    pub fn set_max_rate(&mut self, max_pps: f64) {
        self.max_pps = max_pps;
        self.current_pps = self.current_pps.min(max_pps);
    }
    
    /// Reset the rate limiter
    pub fn reset(&mut self) {
        self.response_times.clear();
        self.last_send = None;
        self.current_pps = self.max_pps;
    }
}

/// Simple token bucket rate limiter
#[derive(Debug, Clone)]
pub struct TokenBucketLimiter {
    /// Maximum tokens in bucket
    capacity: u32,
    /// Current tokens available
    tokens: u32,
    /// Tokens added per second
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucketLimiter {
    /// Create a new token bucket limiter
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }
    
    /// Try to consume a token, returns true if successful
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
    
    /// Wait until a token is available and consume it
    pub async fn consume(&mut self) {
        while !self.try_consume() {
            let wait_time = Duration::from_secs_f64(1.0 / self.refill_rate);
            sleep(wait_time).await;
        }
    }
    
    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let tokens_to_add = (elapsed.as_secs_f64() * self.refill_rate) as u32;
        
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
    
    /// Get current token count
    pub fn available_tokens(&mut self) -> u32 {
        self.refill();
        self.tokens
    }
}

/// Network congestion detector
#[derive(Debug, Clone)]
pub struct CongestionDetector {
    /// Recent packet loss rates
    loss_rates: VecDeque<f64>,
    /// Recent RTT measurements
    rtt_measurements: VecDeque<Duration>,
    /// Window size for measurements
    window_size: usize,
    /// Congestion threshold for packet loss
    loss_threshold: f64,
    /// RTT increase threshold for congestion
    rtt_increase_threshold: f64,
}

impl CongestionDetector {
    /// Create a new congestion detector
    pub fn new() -> Self {
        Self {
            loss_rates: VecDeque::new(),
            rtt_measurements: VecDeque::new(),
            window_size: 50,
            loss_threshold: 0.05, // 5% packet loss
            rtt_increase_threshold: 2.0, // 2x RTT increase
        }
    }
    
    /// Record packet loss rate for a batch of packets
    pub fn record_loss_rate(&mut self, loss_rate: f64) {
        self.loss_rates.push_back(loss_rate);
        if self.loss_rates.len() > self.window_size {
            self.loss_rates.pop_front();
        }
    }
    
    /// Record RTT measurement
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_measurements.push_back(rtt);
        if self.rtt_measurements.len() > self.window_size {
            self.rtt_measurements.pop_front();
        }
    }
    
    /// Check if network congestion is detected
    pub fn is_congested(&self) -> bool {
        self.is_loss_congested() || self.is_rtt_congested()
    }
    
    /// Check congestion based on packet loss
    fn is_loss_congested(&self) -> bool {
        if self.loss_rates.len() < 10 {
            return false;
        }
        
        let avg_loss: f64 = self.loss_rates.iter().sum::<f64>() / self.loss_rates.len() as f64;
        avg_loss > self.loss_threshold
    }
    
    /// Check congestion based on RTT increase
    fn is_rtt_congested(&self) -> bool {
        if self.rtt_measurements.len() < 20 {
            return false;
        }
        
        let recent_avg = self.recent_rtt_average();
        let baseline_avg = self.baseline_rtt_average();
        
        if baseline_avg.is_zero() {
            return false;
        }
        
        let increase_ratio = recent_avg.as_secs_f64() / baseline_avg.as_secs_f64();
        increase_ratio > self.rtt_increase_threshold
    }
    
    /// Get average RTT from recent measurements
    fn recent_rtt_average(&self) -> Duration {
        let recent_count = self.rtt_measurements.len().min(10);
        if recent_count == 0 {
            return Duration::from_millis(0);
        }
        
        let recent_sum: Duration = self.rtt_measurements
            .iter()
            .rev()
            .take(recent_count)
            .sum();
        
        recent_sum / recent_count as u32
    }
    
    /// Get baseline RTT average from older measurements
    fn baseline_rtt_average(&self) -> Duration {
        let total_len = self.rtt_measurements.len();
        if total_len < 20 {
            return Duration::from_millis(0);
        }
        
        let baseline_count = (total_len - 10).min(10);
        let baseline_sum: Duration = self.rtt_measurements
            .iter()
            .skip(total_len - 20)
            .take(baseline_count)
            .sum();
        
        baseline_sum / baseline_count as u32
    }
}

impl Default for CongestionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_adaptive_rate_limiter() {
        let mut limiter = AdaptiveRateLimiter::new(10.0, 1.0, 100.0);
        
        // Test normal operation
        limiter.wait_for_next().await;
        assert_eq!(limiter.current_rate(), 10.0);
        
        // Simulate good response times
        for _ in 0..15 {
            limiter.record_response(Duration::from_millis(50));
        }
        
        // Rate should increase
        assert!(limiter.current_rate() > 10.0);
        
        // Simulate congestion
        for _ in 0..15 {
            limiter.record_response(Duration::from_millis(2000));
        }
        
        // Rate should decrease
        assert!(limiter.current_rate() < 10.0);
    }
    
    #[tokio::test]
    async fn test_token_bucket_limiter() {
        let mut limiter = TokenBucketLimiter::new(5, 2.0);
        
        // Should be able to consume initial tokens
        for _ in 0..5 {
            assert!(limiter.try_consume());
        }
        
        // Should be empty now
        assert!(!limiter.try_consume());
        
        // Wait for refill
        sleep(Duration::from_millis(600)).await;
        assert!(limiter.try_consume());
    }
    
    #[test]
    fn test_congestion_detector() {
        let mut detector = CongestionDetector::new();
        
        // Add normal measurements
        for _ in 0..15 {
            detector.record_loss_rate(0.01);
            detector.record_rtt(Duration::from_millis(100));
        }
        
        assert!(!detector.is_congested());
        
        // Add high loss rate
        for _ in 0..10 {
            detector.record_loss_rate(0.1);
        }
        
        assert!(detector.is_congested());
    }
}