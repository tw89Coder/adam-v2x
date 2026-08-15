/**
 * @file test_presenter.cpp
 * @brief C++ unit test validating ConsolePresenter layout boxes and GUI alignment.
 */

#include "qos_harness/console_presenter.hpp"
#include <iostream>
#include <string>

using namespace qos_harness;

void test_diagnosis_layout() {
    std::cout << "\n[TEST] Printing Diagnosis Header and End Box layout...\n";
    ConsolePresenter::printDiagnosisHeader();
    ConsolePresenter::printDiagnosisEndBox();
}

void test_profiler_layout() {
    std::cout << "\n[TEST] Printing Profiler Header and End Box layout...\n";
    ConsolePresenter::printProfilerHeader();
    
    // Simulate typical path lengths for unpatched/patched to test clipping/padding
    std::string csv_path = "outputs/csv_raw/unpatched/amplification_profile.csv";
    std::string bin_path = "outputs/amp_packets/amp_10000_size01400.bin";
    
    ConsolePresenter::printProfilerEndBox(1400, csv_path, bin_path);
}

void test_security_report_layout() {
    std::cout << "\n[TEST] Printing Security Report layout...\n";
    ConsolePresenter::printSecurityReport(100000, 20051, 20051, 79949, 0, 0);
}

void test_data_plane_diagnostics_layout() {
    std::cout << "\n[TEST] Printing Data-Plane Diagnostics layout...\n";
    DataPlaneDiagnostics report;
    report.packets = 1000000;
    report.inspected = 750000;
    report.skipped = 250000;
    report.dropped = 1000;
    report.f2_ticks_total = 123456789;
    report.filter_inspected_ns = 5000000000ULL;
    report.filter_skipped_ns = 10000000ULL;
    report.parser_legitimate_count = 998000;
    report.parser_legitimate_ns = 2000000000ULL;
    report.parser_malicious_count = 1000;
    report.parser_malicious_ns = 300000000ULL;
    report.state_packets[0] = 500000;
    report.state_packets[1] = 200000;
    report.state_packets[2] = 200000;
    report.state_packets[3] = 100000;
    ConsolePresenter::printDataPlaneDiagnostics(report, "ONNX");
}

int main() {
    std::cout << "======================================================================\n";
    std::cout << "                 qos-harness-test: GUI Box Alignment Unit Test\n";
    std::cout << "======================================================================\n";

    test_diagnosis_layout();
    test_profiler_layout();
    test_security_report_layout();
    test_data_plane_diagnostics_layout();

    std::cout << "======================================================================\n";
    std::cout << "       [SUCCESS] All ConsolePresenter layout tests printed successfully!\n";
    std::cout << "======================================================================\n";
    return 0;
}
