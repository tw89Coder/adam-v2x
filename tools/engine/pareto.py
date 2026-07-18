# engine/pareto.py
import os
import numpy as np
import matplotlib.pyplot as plt
from engine.base import BasePlotter
from engine.logger import LogStyle

class ParetoPlotter(BasePlotter):
    """
    Subclass plotter responsible for generating the analytical Pareto frontier
    representing the entropy-depth security-performance tradeoff.
    """
    def __init__(self, root_output_dir="outputs"):
        super().__init__(root_output_dir=root_output_dir)

    def execute(self):
        """
        Plots the theoretical bound and the empirical discrete sample points,
        highlighting the chosen detector operating point, and saves the plots.
        """
        # Create standard academic single-column plot size (approx 5.2 x 4.0 inches)
        fig, ax = plt.subplots(figsize=(5.2, 4.0))

        # ---------------------------------------------------------------------
        # Seaborn Palette & Aesthetic Emulation
        # ---------------------------------------------------------------------
        # Seaborn 'deep' palette colors
        color_blue = '#4c72b0'  # Soft deep blue
        color_red = '#c44e52'   # Soft deep red
        
        # Despine the top and right borders (Classic Seaborn look)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        # Generate theoretical bound curve: y = 1400 / (2 + x)
        x_curve = np.linspace(0, 128, 400)
        y_curve = 1400 / (2 + x_curve)
        
        # Plot theoretical curve
        ax.plot(x_curve, y_curve, color=color_blue, linestyle='-', linewidth=2.5, label='Theoretical Bound')

        # Empirical sample points
        samples_x = [0, 16, 32, 48, 64, 80, 96, 112, 128]
        samples_y = [700, 77, 41, 28, 21, 17, 14, 12, 10]
        
        # Plot standard samples
        ax.scatter(samples_x, samples_y, color=color_red, marker='o', s=45, zorder=3, label='Empirical Samples')

        # Highlight the selected operating point (64, 21)
        op_x, op_y = 64, 21
        ax.scatter([op_x], [op_y], color=color_blue, marker='o', s=90, edgecolors='black', linewidths=1.5, zorder=4, label='Operating Point')

        # Annotate the operating point with a clean arrow and label (coordinates adjusted for linear scale)
        ax.annotate(
            "Detector\nOperating Point\n($w=64$)",
            xy=(op_x, op_y),
            xytext=(op_x + 25, 140),
            arrowprops=dict(
                arrowstyle="->",
                color=color_blue,
                lw=1.5,
                connectionstyle="arc3,rad=-0.15"
            ),
            fontsize=9.5,
            color='black',
            bbox=dict(boxstyle="round,pad=0.3", fc="#f7f7f7", ec="#cccccc", lw=0.8),
            ha='left',
            va='bottom',
            zorder=5
        )

        # Set labels
        ax.set_xlabel(r'$S_{\mathrm{entropy}}$ (Bytes)', fontweight='normal', labelpad=8)
        ax.set_ylabel(r'$D_{\max}$', fontweight='normal', labelpad=8)
        
        # ---------------------------------------------------------------------
        # Linear Scale & Clean Ticks (ICC Reviewer Recommended)
        # ---------------------------------------------------------------------
        # Using linear scale to preserve the visual impact of the sharp hyperbolic curve,
        # but using uniform linear tick marks to avoid text overlaps.
        ax.set_yscale('linear')
        
        ticks_y = [0, 100, 200, 300, 400, 500, 600, 700]
        ax.set_yticks(ticks_y)
        ax.set_yticklabels([str(t) for t in ticks_y])

        ax.set_xticks(samples_x)
        
        # Keep limits tidy
        ax.set_xlim(-5, 135)
        ax.set_ylim(-20, 750)

        # Add clean academic grid lines (aligned with the linear ticks)
        ax.grid(True, linestyle=':', alpha=0.5, color='gray')

        # Legend and layout tweaks
        ax.legend(loc='upper right', frameon=True, edgecolor='#cccccc', facecolor='#fbfbfb', framealpha=0.9, fontsize=9.5)
        fig.tight_layout()

        # Save using the BasePlotter export function
        self.export_figure(fig, category="pareto", filename_prefix="pareto_frontier")
        plt.close(fig)
