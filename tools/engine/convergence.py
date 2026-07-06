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

        fig, ax1 = plt.subplots(figsize=(7, 4.5))

        color_reward = "#1f77b4"
        ax1.set_xlabel("Training Updates (Batches)", fontweight="bold")
        ax1.set_ylabel("Mean Reward", color=color_reward, fontweight="bold")

        # Plot raw reward underlay and smoothed mean overlay
        ax1.plot(x, reward, color=color_reward, alpha=0.2, linestyle="-", linewidth=1.0, label="Raw Reward")
        ax1.plot(x, smoothed_reward, color=color_reward, linewidth=2.0, label=f"Smoothed Reward (window={window})")
        ax1.fill_between(x, smoothed_reward - 0.5 * std_reward, smoothed_reward + 0.5 * std_reward, 
                         color=color_reward, alpha=0.1)
        ax1.tick_params(axis='y', labelcolor=color_reward)
        ax1.legend(loc="upper left")

        # Secondary Y axis for loss metrics
        ax2 = ax1.twinx()
        color_loss = "#d62728"
        ax2.set_ylabel("Training Loss", color=color_loss, fontweight="bold")

        smoothed_loss = loss.rolling(window=window, min_periods=1).mean()
        ax2.plot(x, smoothed_loss, color=color_loss, linewidth=1.5, linestyle="--", alpha=0.8, label="Training Loss")
        ax2.tick_params(axis='y', labelcolor=color_loss)
        ax2.legend(loc="upper right")

        plt.title("Deep Reinforcement Learning (DRL) Convergence Analysis", pad=15)
        fig.tight_layout()

        self.export_figure(fig, category="rl_env", filename_prefix="convergence_curve")
        plt.close(fig)
