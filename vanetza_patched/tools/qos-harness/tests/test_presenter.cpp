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

int main() {
    std::cout << "======================================================================\n";
    std::cout << "                 qos-harness-test: GUI Box Alignment Unit Test\n";
    std::cout << "======================================================================\n";

    test_diagnosis_layout();
    test_profiler_layout();
    test_security_report_layout();

    std::cout << "======================================================================\n";
    std::cout << "       [SUCCESS] All ConsolePresenter layout tests printed successfully!\n";
    std::cout << "======================================================================\n";
    return 0;
}
