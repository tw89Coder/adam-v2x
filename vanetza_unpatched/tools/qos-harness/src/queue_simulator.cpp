#include "qos_harness/queue_simulator.hpp"
#include <random>
#include <iostream>

namespace qos_harness {

QueueSimulator::QueueSimulator(double lambda_pps, int total_packets)
    : lambda_pps_(lambda_pps), total_packets_(total_packets), producer_done_(false) {
}

QueueSimulator::~QueueSimulator() {
    wait_until_done();
}

void QueueSimulator::start(ProducerFunc producer_func, ConsumerFunc consumer_func) {
    producer_done_ = false;
    producer_ = std::thread(&QueueSimulator::producer_thread_func, this, producer_func);
    consumer_ = std::thread(&QueueSimulator::consumer_thread_func, this, consumer_func);
}

void QueueSimulator::wait_until_done() {
    if (producer_.joinable()) {
        producer_.join();
    }
    if (consumer_.joinable()) {
        consumer_.join();
    }
}

void QueueSimulator::producer_thread_func(ProducerFunc producer_func) {
    std::mt19937 generator(42); // fixed seed for reproducibility or can pass as param
    std::exponential_distribution<double> exp_dist(lambda_pps_);

    auto current_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < total_packets_; ++i) {
        // Generate inter-arrival time in seconds
        double inter_arrival_time_s = exp_dist(generator);
        auto wait_duration = std::chrono::nanoseconds(static_cast<long long>(inter_arrival_time_s * 1e9));

        // Sleep to simulate the arrival interval
        // Wait, for 1000000 packets at 3000pps, it takes ~333 seconds. We actually sleep.
        std::this_thread::sleep_for(wait_duration);

        // Record exact physical arrival time
        auto arrival_time = std::chrono::high_resolution_clock::now();

        // Get payload
        auto payload = producer_func(i);

        QueuePacket pkt;
        pkt.id = i;
        pkt.is_malware = payload.first;
        pkt.buffer = std::move(payload.second);
        pkt.arrival_time = arrival_time;

        // Push to queue
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(pkt));
        }
        cv_.notify_one();
    }

    producer_done_ = true;
    cv_.notify_one();
}

void QueueSimulator::consumer_thread_func(ConsumerFunc consumer_func) {
    int processed = 0;
    while (true) {
        QueuePacket pkt;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !queue_.empty() || producer_done_; });
            
            if (queue_.empty() && producer_done_) {
                break;
            }
            
            pkt = std::move(queue_.front());
            queue_.pop();
        }

        // Process the packet in consumer logic
        consumer_func(pkt);
        processed++;
    }
}

} // namespace qos_harness
