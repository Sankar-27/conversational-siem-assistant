import logging
import sys

try:
    import structlog
    def setup_logging(debug: bool = False) -> None:
        log_level = logging.DEBUG if debug else logging.INFO
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer() if debug else structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        logging.basicConfig(stream=sys.stdout, level=log_level)
    logger = structlog.get_logger()
except ImportError:
    class _FallbackLogger:
        def __init__(self, name: str):
            self._logger = logging.getLogger(name)

        def _log(self, level: int, event: str, **fields) -> None:
            message = event
            if fields:
                message = f"{event} {fields}"
            self._logger.log(level, message)

        def debug(self, event: str, **fields) -> None:
            self._log(logging.DEBUG, event, **fields)

        def info(self, event: str, **fields) -> None:
            self._log(logging.INFO, event, **fields)

        def warning(self, event: str, **fields) -> None:
            self._log(logging.WARNING, event, **fields)

        def error(self, event: str, **fields) -> None:
            self._log(logging.ERROR, event, **fields)

    def setup_logging(debug: bool = False) -> None:
        logging.basicConfig(
            stream=sys.stdout,
            level=logging.DEBUG if debug else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
    logger = _FallbackLogger("siem")

