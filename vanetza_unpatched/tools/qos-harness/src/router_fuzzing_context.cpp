/**
 * @file router_fuzzing_context.cpp
 * @brief Implementation of the mock ETSI C-ITS Geonet Router context for fuzzing evaluations.
 * 
 * DESIGN CONTEXT & SIMULATOR HARNESS:
 * This file constructs a mock implementation of the Vanetza Geonet Router.
 * It provides empty transport and DCC request interfaces to isolate packet parsing,
 * security decryption, and routing table lookup logic, enabling latency profiling without 
 * actual wireless transceiver hardware.
 */

#include "qos_harness/router_fuzzing_context.hpp"

namespace vanetza
{

/**
 * @brief Mock implementation of the Decentralized Congestion Control (DCC) RequestInterface.
 */
class FuzzingRequestInterface : public dcc::RequestInterface
{
    void request(const dcc::DataRequest&, std::unique_ptr<ChunkPacket>) override {}
};

/**
 * @brief Mock implementation of the Geonet TransportInterface.
 */
class FuzzingTransportInterface : public geonet::TransportInterface
{
    void indicate(const geonet::DataIndication&, std::unique_ptr<geonet::UpPacket>) override {}
};

RouterFuzzingContext::RouterFuzzingContext() :
    runtime(vanetza::Clock::at("2010-12-23 18:29")),
    security(runtime),
    req_ifc(std::make_unique<FuzzingRequestInterface>()),
    ind_ifc(std::make_unique<FuzzingTransportInterface>())
{
    initialize();
}

/**
 * @brief Sets up mock MAC addresses, security hooks, and routes BTP transport protocol handlers.
 */
void RouterFuzzingContext::initialize()
{
    router = std::make_unique<geonet::Router>(runtime, mib);
    router->set_security_entity(&security.entity());
    router->set_access_interface(req_ifc.get());
    router->set_transport_handler(geonet::UpperProtocol::BTP_B, ind_ifc.get());

    geonet::Address gn_addr;
    gn_addr.mid(MacAddress{0, 0, 0, 0, 0, 1});
    router->set_address(gn_addr);
}

/**
 * @brief Simulates receiving a packet buffer at the link-layer and routes it to the Geonet router parser.
 * 
 * @param buffer Raw packet byte buffer payload.
 */
void RouterFuzzingContext::indicate(ByteBuffer&& buffer)
{
    MacAddress source { 0, 0, 0, 0, 0, 2 };
    MacAddress destination { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    auto packet = std::make_unique<geonet::UpPacket>(CohesivePacket { std::move(buffer), OsiLayer::Network });
    router->indicate(std::move(packet), source, destination);
}

} // namespace vanetza
