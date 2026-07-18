# engine/convergence.py
import os
import pandas as pd
import matplotlib.pyplot as plt
from engine.base import BasePlotter
from engine.logger import LogStyle

class ConvergencePlotter(BasePlotter):
    """
    Subclass plotter responsible for reading reinforcement learning training telemetry
    logs and exporting academic-grade convergence curve charts.
    """
    def __init__(self, root_output_dir="outputs"):
        super().__init__(root_output_dir=root_output_dir)

    def execute(self, csv_path):
        """
        Loads the training progress CSV file, performs rolling average smoothing
        for visual clarity, and saves the convergence analysis curves.
        """
        import matplotlib.ticker as ticker

        if not os.path.exists(csv_path):
            LogStyle.log_warn(f"Training progress logs not found at: {csv_path}. Skipping DRL convergence plot.")
            return

        df = self._load_csv_file(csv_path, comment_char=None)
        if len(df) == 0:
            LogStyle.log_warn("Training progress log file is empty. Skipping DRL convergence plot.")
            return

        x = df["update"]
        reward = df["reward"]
        loss = df["loss"]

        # Dynamic rolling average calculation for smoothing noisy RL trajectories
        window = max(2, len(df) // 10)
        smoothed_reward = reward.rolling(window=window, min_periods=1).mean()
        std_reward = reward.rolling(window=window, min_periods=1).std().fillna(0)

        # Standard academic paper aspect ratio (8 x 4.5 inches)
        fig, ax1 = plt.subplots(figsize=(8, 4.5))

        color_reward = "#4c72b0"
        ax1.set_xlabel("Training Updates (Batches)", fontweight="normal")
        ax1.set_ylabel("Mean Reward", color=color_reward, fontweight="normal")

        # Plot raw reward underlay and smoothed mean overlay
        line_raw, = ax1.plot(x, reward, color=color_reward, alpha=0.15, linestyle="-", linewidth=0.75, label="Raw Reward")
        line_smooth, = ax1.plot(x, smoothed_reward, color=color_reward, linewidth=1.5, label=f"Smoothed Reward (window={window})")
        ax1.fill_between(x, smoothed_reward - 0.5 * std_reward, smoothed_reward + 0.5 * std_reward, 
                         color=color_reward, alpha=0.08)
        ax1.tick_params(axis='y', labelcolor=color_reward)

        # Configure clean grid on primary axis and disable twin axis grid to prevent overlaps
        ax1.grid(True, linestyle=":", alpha=0.3, color="gray")

        # Secondary Y axis for loss metrics
        ax2 = ax1.twinx()
        ax2.spines['right'].set_visible(True)  # Re-enable the twin spine that was globally despined
        color_loss = "#c44e52"
        ax2.set_ylabel("Training Loss", color=color_loss, fontweight="normal")

        smoothed_loss = loss.rolling(window=window, min_periods=1).mean()
        line_loss, = ax2.plot(x, smoothed_loss, color=color_loss, linewidth=1.2, linestyle="--", alpha=0.7, label="Training Loss")
        ax2.tick_params(axis='y', labelcolor=color_loss)
        ax2.grid(False)

        # De-densified y-axis tick intervals for Loss (0.5 or 1.0 steps based on maximum value)
        max_loss = loss.max()
        if max_loss > 2.0:
            ax2.yaxis.set_major_locator(ticker.MultipleLocator(1.0))
        elif max_loss > 1.0:
            ax2.yaxis.set_major_locator(ticker.MultipleLocator(0.5))
        elif max_loss > 0.1:
            ax2.yaxis.set_major_locator(ticker.MultipleLocator(0.1))
        else:
            ax2.yaxis.set_major_locator(ticker.MaxNLocator(nbins=5))

        # Combine all legend handles and labels into a horizontal box placed below the chart
        lines = [line_raw, line_smooth, line_loss]
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=3, 
                   frameon=True, edgecolor='black', facecolor='white', framealpha=0.9)

        # Apply tight layout to ensure labels are not cropped and верхней space is saved (Title is handled by LaTeX caption)
        fig.tight_layout()

        self.export_figure(fig, category="rl_env", filename_prefix="convergence_curve")
        plt.close(fig)
