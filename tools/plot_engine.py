#!/usr/bin/env python3
# plot_engine.py
import os
import sys
import argparse
from engine.logger import LogStyle

def parse_run_selection(value):
    """Parse run selections such as '1-20', '1,3,5-8', or 'all'."""
    normalized = value.strip().lower()
    if normalized == 'all':
        return None

    run_ids = set()
    try:
        for item in normalized.replace(' ', ',').split(','):
            if not item:
                continue
            if '-' in item:
                start_text, end_text = item.split('-', 1)
                start, end = int(start_text), int(end_text)
                if start < 1 or end < start:
                    raise ValueError
                run_ids.update(range(start, end + 1))
            else:
                run_id = int(item)
                if run_id < 1:
                    raise ValueError
                run_ids.add(run_id)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "use 'all', a range such as '1-20', or a list such as '1,3,5-8'"
        ) from exc

    if not run_ids:
        raise argparse.ArgumentTypeError("at least one run must be selected")
    return tuple(sorted(run_ids))

def main():
    # Dynamically resolve paths relative to the physical location of this script file
    # script_dir resolves to: ~/term-project/CSE625_QoS/tools
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # project_root resolves to: ~/term-project/CSE625_QoS
    project_root = os.path.dirname(script_dir)
    # default_outputs resolves perfectly to: ~/term-project/CSE625_QoS/outputs
    default_outputs = os.path.join(project_root, "outputs")

    parser = argparse.ArgumentParser(
        description=(
            "Generate ADAM paper statistics and figures from experiment outputs. "
            "Use -M for the 20-run publication aggregation path."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"{LogStyle.BOLD}Plot types:{LogStyle.RESET}\n"
               f"  {LogStyle.STAGE}amp{LogStyle.RESET}         Parser workload amplification\n"
               f"  {LogStyle.STAGE}qos{LogStyle.RESET}         Latency CDF/jitter and summary statistics\n"
               f"  {LogStyle.STAGE}timeline{LogStyle.RESET}    Mode 1 pulse and Mode 2 periodic timelines\n"
               f"  {LogStyle.STAGE}debug{LogStyle.RESET}       Input-data diagnostics\n"
               f"  {LogStyle.STAGE}budget{LogStyle.RESET}      Risk-budget behavior\n"
               f"  {LogStyle.STAGE}convergence{LogStyle.RESET} Training convergence\n"
               f"  {LogStyle.STAGE}window{LogStyle.RESET}      Sampling/attack/leakage window telemetry\n"
               f"  {LogStyle.STAGE}pareto{LogStyle.RESET}      Entropy-depth bound\n\n"
               f"{LogStyle.BOLD}Publication examples:{LogStyle.RESET}\n"
               "  python tools/plot_engine.py -M --runs 1-20\n"
               "  python tools/plot_engine.py --type timeline --onnx\n"
               "  python tools/plot_engine.py --type qos --onnx -m 0 -r '1.0 5.0 10.0'"
    )
    
    parser.add_argument('--all', action='store_true', help="Generate every available single-run statistic and figure (default when no pipeline is selected).")
    parser.add_argument('--type', choices=['amp', 'qos', 'timeline', 'debug', 'budget', 'convergence', 'window', 'pareto'], 
                        help="Generate only one single-run plot/statistics family (see below).")
    parser.add_argument('-m', '--mode', type=int, choices=[0, 1, 2, 3], default=0, help="Attack schedule: 0=continuous, 1=single pulse, 2=periodic, 3=mixed training (default: 0).")
    parser.add_argument('-r', '--rate', type=str, default="10.0", help="Attack percentage or a space-separated list, e.g. '1.0 5.0 10.0' (default: 10.0).")
    parser.add_argument('--output-dir', type=str, default=default_outputs, help="Experiment output root (default: <repository>/outputs).")
    parser.add_argument('--onnx', action='store_true', help="Use deployed ONNX-policy results instead of FSM-only filtered results for single-run QoS plots.")
    parser.add_argument('--no-patched', action='store_true', help="Omit recursion-depth-limited comparison curves from single-run QoS plots.")
    parser.add_argument('-M', '--multi-run', action='store_true', help="Aggregate publication trials from outputs/multi_runs and regenerate multi-run CSV, console tables, and figures.")
    parser.add_argument(
        '--runs', type=parse_run_selection, default=parse_run_selection('1-20'),
        metavar='SELECTION',
        help="Multi-run trial selection: '1-20' (default), '1,3,5-8', or 'all'."
    )

    args = parser.parse_args()

    # Deferred initialization pass to prevent heavy library load overhead on help flags
    from engine import AmplificationPlotter, QoSPlotter, QoSMultiPlotter, ConvergencePlotter, ParetoPlotter

    # Enforce absolute path casting on final target boundary
    base_dir = os.path.abspath(args.output_dir)
    
    if not (args.all or args.type or args.multi_run):
        LogStyle.log_warn("No specific execution pipeline flags declared. Defaulting to full processing synthesis (--all).")
        args.all = True
 
    # Validate target output root infrastructure before runtime initiation
    if not os.path.exists(base_dir):
        LogStyle.log_error(f"Configured output directory boundary does not exist: '{base_dir}'")
        sys.exit(1)

    if args.multi_run:
        selection_text = 'all discovered runs' if args.runs is None else f'{len(args.runs)} selected runs'
        LogStyle.log_stage(
            f"[PLOT ENGINE] Multi-Run Pipeline Active. Processing {selection_text}..."
        )
        qos_multi_engine = QoSMultiPlotter(
            root_output_dir=base_dir,
            use_onnx=True,
            run_ids=args.runs,
        )
        df_summary = qos_multi_engine.process_all_multi_runs()
        if df_summary is not None:
            LogStyle.log_success("Multi-run trial evaluation, statistical aggregation, and dual-format tables completed cleanly.")
        return

    amp_engine = AmplificationPlotter(root_output_dir=base_dir)
    qos_engine = QoSPlotter(root_output_dir=base_dir, use_onnx=args.onnx, no_patched=args.no_patched)
    conv_engine = ConvergencePlotter(root_output_dir=base_dir)
    pareto_engine = ParetoPlotter(root_output_dir=base_dir)

    try:
        if args.all:
            try:
                amp_engine.execute()
            except SystemExit:
                LogStyle.log_warn("Amplification profile data absent/skipped. Proceeding cleanly with QoS pipeline...")
            except Exception as e:
                LogStyle.log_warn(f"Amplification pipeline bypassed ({e}). Proceeding cleanly with QoS pipeline...")

            qos_engine.compute_all_combinations_stats()
            
            for m in qos_engine.MODES:
                for r in qos_engine.RATES:
                    qos_engine.plot_master_cdf(target_mode=m, target_rate=r)
            
            qos_engine.plot_pulse_timeline()
            qos_engine.plot_periodic_timeline()
            qos_engine.plot_online_training_telemetry()
            qos_engine.plot_all_existing_window_metrics()
            qos_engine.print_diagnostic_debug()
            
            # Auto-run convergence plot if training logs exist
            csv_path = os.path.join(project_root, "checkpoints", "training_progress.csv")
            conv_engine.execute(csv_path)

            # Auto-run Pareto frontier plot
            pareto_engine.execute()
            
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

        elif args.type == 'pareto':
            pareto_engine.execute()

    except KeyboardInterrupt:
        print(f"\n{LogStyle.WARN}[SIGINT DETECTED] Processing loop gracefully aborted by user event link.{LogStyle.RESET}\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
