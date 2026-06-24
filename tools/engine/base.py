# engine/base.py
import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from engine.logger import LogStyle

class BasePlotter:
    """
    Abstract base class enforcing academic publication graphics layouts, unified data
    ingestion, directory tracking, and dual vector/raster image exportation.
    """
    def __init__(self, root_output_dir="outputs"):
        self.root_output_dir = root_output_dir
        self.plots_dir = os.path.join(root_output_dir, "plots")
        self.stats_dir = os.path.join(root_output_dir, "stats")
        self._apply_academic_style()

    def _apply_academic_style(self):
        """
        Enforces top-tier IEEE/ACM venue formatting standards across all subplots.
        """
        plt.rcParams.update({
            'font.family': 'serif',
            'font.serif': ['Times New Roman', 'DejaVu Serif'],
            'font.size': 12,
            'axes.labelsize': 13,
            'axes.titlesize': 14,
            'axes.titleweight': 'bold',
            'axes.linewidth': 1.2,
            'legend.fontsize': 11,
            'legend.frameon': True,
            'legend.edgecolor': 'black',
            'legend.framealpha': 1.0,
            'xtick.labelsize': 11,
            'ytick.labelsize': 11,
            'xtick.direction': 'in',
            'ytick.direction': 'in',
            'xtick.major.size': 5,
            'ytick.major.size': 5,
            'axes.grid': True,
            'grid.alpha': 0.4,
            'grid.linestyle': ':',
            'lines.linewidth': 2.5,
            'lines.markersize': 8,
            'figure.dpi': 300,
            'savefig.bbox': 'tight',
            'savefig.pad_inches': 0.05
        })

    def _ensure_directory_exists(self, target_path):
        """
        Instantiates specific directories dynamically if not registered by the filesystem.
        """
        if not os.path.exists(target_path):
            os.makedirs(target_path, exist_ok=True)

    def _load_csv_file(self, file_path, comment_char='#'):
        """
        Performs data ingestion with proactive error feedback blocks.
        """
        if not os.path.exists(file_path):
            LogStyle.log_error(f"Target file asset not found: '{file_path}'")
            sys.exit(1)
        try:
            return pd.read_csv(file_path, comment=comment_char)
        except Exception as e:
            LogStyle.log_error(f"Failed to parse CSV matrix at '{file_path}'. Context: {str(e)}")
            sys.exit(1)

    def export_figure(self, fig, category, filename_prefix):
        """
        Saves the current target figure as a high-resolution raster PNG and an uncompressed vector PDF.
        """
        target_dir = os.path.join(self.plots_dir, category)
        self._ensure_directory_exists(target_dir)

        png_path = os.path.join(target_dir, f"{filename_prefix}.png")
        pdf_path = os.path.join(target_dir, f"{filename_prefix}.pdf")

        fig.savefig(png_path, dpi=300, bbox_inches='tight')
        fig.savefig(pdf_path, format='pdf', bbox_inches='tight')
        LogStyle.log_success(f"Generated Art: [{category}] -> {filename_prefix}.{{png,pdf}}")