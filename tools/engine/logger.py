# engine/logger.py

class LogStyle:
    """
    Standard ANSI escape sequence terminal logger for industrial software pipelines.
    """
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    STAGE = '\033[1;35m'    # Magenta for execution pipeline stages
    INFO = '\033[1;36m'     # Cyan for verbose data processing details
    SUCCESS = '\033[1;32m'  # Green for successful resource generations
    WARN = '\033[1;33m'     # Yellow for graceful recovery configurations
    ERROR = '\033[1;41;37m' # High-contrast Red for unrecoverable state alerts
    LINE = '\033[38;5;240m' # Dark Gray border line

    @classmethod
    def log_stage(cls, message):
        print(f"{cls.STAGE}[STAGE] {message}{cls.RESET}")

    @classmethod
    def log_info(cls, message):
        print(f"{cls.INFO}[INFO]  {message}{cls.RESET}")

    @classmethod
    def log_success(cls, message):
        print(f"{cls.SUCCESS}[SUCCESS] {message}{cls.RESET}")

    @classmethod
    def log_warn(cls, message):
        print(f"{cls.WARN}[WARN]  {message}{cls.RESET}")

    @classmethod
    def log_error(cls, message):
        print(f"\n{cls.ERROR}[FATAL ERROR] {message}{cls.RESET}")
        print(f"{cls.ERROR}[PROCESS ABORTED] Dependency resolution failure.{cls.RESET}\n")