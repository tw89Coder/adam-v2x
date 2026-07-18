#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <functional>
#include <vanetza/common/byte_buffer.hpp>

namespace qos_harness {

struct QueuePacket {
    int id;
    bool is_malware;
    vanetza::ByteBuffer buffer;
    std::chrono::high_resolution_clock::time_point arrival_time;
};

class QueueSimulator {
public:
    // lambda_pps: arrival rate in packets per second
    QueueSimulator(double lambda_pps, int total_packets);
    ~QueueSimulator();

    // The consumer logic (what to do with a packet)
    using ConsumerFunc = std::function<void(const QueuePacket&)>;
    
    // The producer logic (how to get the next packet payload and type)
    // Returns {is_malware, buffer}
    using ProducerFunc = std::function<std::pair<bool, vanetza::ByteBuffer>(int packet_index)>;

    void start(ProducerFunc producer_func, ConsumerFunc consumer_func);
    void wait_until_done();

private:
    void producer_thread_func(ProducerFunc producer_func);
    void consumer_thread_func(ConsumerFunc consumer_func);

    double lambda_pps_;
    int total_packets_;
    
    std::queue<QueuePacket> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> producer_done_;
    
    std::thread producer_;
    std::thread consumer_;
};

} // namespace qos_harness
