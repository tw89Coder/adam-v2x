"""
@file registry.py
@brief Global registry and dynamic import loader for V2X DRL algorithms.
"""

import importlib
import logging
from typing import Dict, Callable, Tuple, Any

# Setup basic logging config
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

_ALGORITHM_REGISTRY: Dict[str, Callable[..., Tuple[Any, Any, Any]]] = {}

def register_algorithm(name: str):
    """
    Decorator to register an algorithm pipeline builder.
    """
    def decorator(builder_func: Callable[..., Tuple[Any, Any, Any]]):
        _ALGORITHM_REGISTRY[name.lower()] = builder_func
        return builder_func
    return decorator

def get_algorithm_builder(name: str) -> Callable[..., Tuple[Any, Any, Any]]:
    """
    Dynamically loads the algorithm module and retrieves its builder function.
    Guarantees zero-touch extensibility (OCP compliant).
    """
    algo_name = name.lower()
    
    # 1. If not yet registered, attempt dynamic lazy loading of the module
    if algo_name not in _ALGORITHM_REGISTRY:
        module_path = f"src.algorithms.{algo_name}_learner"
        try:
            importlib.import_module(module_path)
            logging.info(f"[REGISTRY] Dynamically imported and registered module: {module_path}")
        except ImportError as e:
            raise ValueError(
                f"Algorithm module '{module_path}' could not be imported. "
                f"Please ensure it exists under src/algorithms/ and is named {algo_name}_learner.py. "
                f"Underlying error: {e}"
            )
            
    # 2. Retrieve registered builder
    builder = _ALGORITHM_REGISTRY.get(algo_name)
    if not builder:
        raise RuntimeError(
            f"Module src.algorithms.{algo_name}_learner was successfully loaded, "
            f"but did not register algorithm '{algo_name}'. "
            f"Ensure the builder function has the @register_algorithm('{algo_name}') decorator."
        )
        
    return builder
