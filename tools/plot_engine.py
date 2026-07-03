#!/usr/bin/env python3
# plot_engine.py
import os
import sys
import argparse

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
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('--all', action='store_true', help="Execute entire pipeline suite (Generates all stats, charts, tables).")
    parser.add_argument('--type', choices=['amp', 'qos', 'timeline', 'debug', 'budget'], help="Isolate target execution pipelines.")
    parser.add_argument('-m', '--mode', type=int, default=0, help="Target protocol simulation state logic mode (Default: 0).")
    parser.add_argument('-r', '--rate', type=str, default="10.0", help="Attack intensity flood multiplier scaling percentage or space-separated list (Default: 10.0).")
    parser.add_argument('--output-dir', type=str, default=default_outputs, help="Override standard relative root target location for data export.")

    args = parser.parse_args()

    # Deferred initialization pass to prevent heavy library load overhead on help flags
    from engine import LogStyle, AmplificationPlotter, QoSPlotter

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
    qos_engine = QoSPlotter(root_output_dir=base_dir)

    try:
        if args.all:
            amp_engine.execute()
            qos_engine.compute_all_combinations_stats()
            
            for m in QoSPlotter.MODES:
                for r in QoSPlotter.RATES:
                    qos_engine.plot_master_cdf(target_mode=m, target_rate=r)
            
            qos_engine.plot_pulse_timeline()
            qos_engine.plot_periodic_timeline()
            qos_engine.print_diagnostic_debug()
            LogStyle.log_success("Comprehensive analytical evaluation cycle finished cleanly without failures.")
            return

        if args.type == 'amp':
            amp_engine.execute()

        elif args.type == 'qos':
            qos_engine.compute_all_combinations_stats()
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

    except KeyboardInterrupt:
        print(f"\n{LogStyle.WARN}[SIGINT DETECTED] Processing loop gracefully aborted by user event link.{LogStyle.RESET}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()