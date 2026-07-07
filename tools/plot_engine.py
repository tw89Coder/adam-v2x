#!/usr/bin/env python3
# plot_engine.py
import os
import sys
import argparse
from engine.logger import LogStyle

def main():
    # Dynamically resolve paths relative to the physical location of this script file
    # script_dir resolves to: ~/term-project/CSE625_QoS/tools
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # project_root resolves to: ~/term-project/CSE625_QoS
    project_root = os.path.dirname(script_dir)
    # default_outputs resolves perfectly to: ~/term-project/CSE625_QoS/outputs
    default_outputs = os.path.join(project_root, "outputs")

    parser = argparse.ArgumentParser(
        description="Industrial-Grade Verification and Plotting Engine for Academic Publication Manuscripts.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"{LogStyle.BOLD}Available Plotting Types and Semantic Meanings:{LogStyle.RESET}\n"
               f"  {LogStyle.STAGE}amp{LogStyle.RESET}         : Packet amplification ratio profiling (Defense metrics comparison)\n"
               f"  {LogStyle.STAGE}qos{LogStyle.RESET}         : Cumulative Distribution Function (CDF) latency/loss curves\n"
               f"  {LogStyle.STAGE}timeline{LogStyle.RESET}    : Multi-modal temporal attack execution traces\n"
               f"  {LogStyle.STAGE}debug{LogStyle.RESET}       : Diagnostics diagnostic log output checks\n"
               f"  {LogStyle.STAGE}budget{LogStyle.RESET}      : Resource depletion threshold boundaries under mitigations\n"
               f"  {LogStyle.STAGE}convergence{LogStyle.RESET} : DRL offline/online training Episode-Reward convergence metrics\n"
               f"  {LogStyle.STAGE}window{LogStyle.RESET}      : Dynamic timeline curves of window-level sampling, attack, and leakage rates"
    )
    
    parser.add_argument('--all', action='store_true', help="Execute entire pipeline suite (Generates all stats, charts, tables).")
    parser.add_argument('--type', choices=['amp', 'qos', 'timeline', 'debug', 'budget', 'convergence', 'window'], 
                        help="Isolate target execution pipelines (see type details below).")
    parser.add_argument('-m', '--mode', type=int, default=0, help="Target protocol simulation state logic mode (Default: 0).")
    parser.add_argument('-r', '--rate', type=str, default="10.0", help="Attack intensity flood multiplier scaling percentage or space-separated list (Default: 10.0).")
    parser.add_argument('--output-dir', type=str, default=default_outputs, help="Override standard relative root target location for data export.")
    parser.add_argument('--onnx', action='store_true', help="Use ONNX actual deployment results instead of heuristic FSM filtered results for QoS plots.")

    args = parser.parse_args()

    # Deferred initialization pass to prevent heavy library load overhead on help flags
    from engine import AmplificationPlotter, QoSPlotter, ConvergencePlotter

    # Enforce absolute path casting on final target boundary
    base_dir = os.path.abspath(args.output_dir)
    
    if not (args.all or args.type):
        LogStyle.log_warn("No specific execution pipeline flags declared. Defaulting to full processing synthesis (--all).")
        args.all = True
 
    # Validate target output root infrastructure before runtime initiation
    if not os.path.exists(base_dir):
        LogStyle.log_error(f"Configured output directory boundary does not exist: '{base_dir}'")
        sys.exit(1)
 
    amp_engine = AmplificationPlotter(root_output_dir=base_dir)
    qos_engine = QoSPlotter(root_output_dir=base_dir, use_onnx=args.onnx)
    conv_engine = ConvergencePlotter(root_output_dir=base_dir)

    try:
        if args.all:
            amp_engine.execute()
            qos_engine.compute_all_combinations_stats()
            
            for m in qos_engine.MODES:
                for r in qos_engine.RATES:
                    qos_engine.plot_master_cdf(target_mode=m, target_rate=r)
            
            qos_engine.plot_pulse_timeline()
            qos_engine.plot_periodic_timeline()
            qos_engine.print_diagnostic_debug()
            
            # Auto-run convergence plot if training logs exist
            csv_path = os.path.join(project_root, "checkpoints", "training_progress.csv")
            conv_engine.execute(csv_path)
            
            LogStyle.log_success("Comprehensive analytical evaluation cycle finished cleanly without failures.")
            return

        if args.type == 'amp':
            amp_engine.execute()

        elif args.type == 'qos':
            qos_engine.compute_all_combinations_stats()
            if not any(arg in sys.argv for arg in ['-r', '--rate']):
                rates = qos_engine.RATES
            else:
                rates = [float(r) for r in args.rate.split()]
            for r in rates:
                qos_engine.plot_master_cdf(target_mode=args.mode, target_rate=r)

        elif args.type == 'timeline':
            qos_engine.plot_pulse_timeline()
            qos_engine.plot_periodic_timeline()

        elif args.type == 'debug':
            qos_engine.print_diagnostic_debug()

        elif args.type == 'budget':
            rates = [float(r) for r in args.rate.split()]
            for r in rates:
                qos_engine.plot_budget_vs_attack(target_mode=args.mode, target_rate=r)
                
        elif args.type == 'convergence':
            csv_path = os.path.join(project_root, "checkpoints", "training_progress.csv")
            conv_engine.execute(csv_path)

        elif args.type == 'window':
            # 1. Plot online training telemetry if available
            qos_engine.plot_online_training_telemetry()
            # 2. Auto-scan outputs/rl_env and plot all existing deployment window traces
            qos_engine.plot_all_existing_window_metrics()

    except KeyboardInterrupt:
        print(f"\n{LogStyle.WARN}[SIGINT DETECTED] Processing loop gracefully aborted by user event link.{LogStyle.RESET}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()