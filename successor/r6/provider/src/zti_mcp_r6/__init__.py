"""Public R6 tool integration API; trusted plugins, one local transaction."""
from .integration import ExecutionContext, Footprint, TableSpec, ToolSpec, Writer

__version__ = '0.3.0'
__all__ = ['ExecutionContext', 'Footprint', 'TableSpec', 'ToolSpec', 'Writer']
