#!/usr/bin/env python3
"""
Base Agent Class for Noctis-MCP
=================================

Abstract base class defining the agent interface and common functionality.

All Noctis agents inherit from BaseAgent and implement the execute() method.

Author: Noctis-MCP Community
License: MIT
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List, Optional, Tuple
import logging
import time
from datetime import datetime


@dataclass
class AgentResult:
    """
    Standardized result format for all agents.

    This ensures consistent return values across all agent types.
    """
    success: bool
    data: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0  # Seconds
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)

    def __str__(self) -> str:
        """String representation"""
        status = "✓ SUCCESS" if self.success else "✗ FAILED"
        return f"AgentResult({status}, {len(self.errors)} errors, {len(self.warnings)} warnings)"


class BaseAgent(ABC):
    """
    Abstract base class for all Noctis agents.

    Design Principles:
    - Stateful: Agents maintain state across operations
    - Composable: Agents can use other components and agents
    - Observable: Rich logging and metrics
    - Lifecycle: init → validate → execute → cleanup
    - Fault-tolerant: Graceful error handling

    Subclasses must implement:
    - execute(**kwargs) -> AgentResult
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize agent with configuration.

        Args:
            config: Configuration dictionary with paths, settings, etc.
                   Should include keys like:
                   - db_path: Path to knowledge database
                   - metadata_path: Path to technique metadata
                   - output_dir: Directory for generated files
                   - etc.
        """
        self.config = config
        self.state = {}
        self.metrics = {
            'executions': 0,
            'successes': 0,
            'failures': 0,
            'total_execution_time': 0.0
        }
        self.logger = self._setup_logger()

        # Call subclass initialization if needed
        self._init_agent()

    def _setup_logger(self) -> logging.Logger:
        """Setup logger for this agent"""
        logger_name = f"Agent.{self.__class__.__name__}"
        logger = logging.getLogger(logger_name)

        # If not already configured, set up basic config
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
                datefmt='%H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

        return logger

    def _init_agent(self):
        """
        Initialize agent-specific resources.

        Subclasses can override this for custom initialization.
        """
        pass

    @abstractmethod
    def execute(self, **kwargs) -> AgentResult:
        """
        Execute agent's primary function.

        This is the main method that subclasses must implement.

        Args:
            **kwargs: Agent-specific parameters

        Returns:
            AgentResult with success status, data, errors, warnings

        Example:
            result = agent.execute(target_av="Windows Defender", objective="evasion")
            if result.success:
                print(result.data)
            else:
                print(result.errors)
        """
        pass

    def run(self, **kwargs) -> AgentResult:
        """
        Wrapper around execute() with validation, timing, and metrics.

        This is the public interface - users should call run() not execute().

        Args:
            **kwargs: Agent-specific parameters

        Returns:
            AgentResult
        """
        start_time = time.time()
        self.logger.info(f"{self.__class__.__name__} starting...")

        try:
            # 1. Validate inputs
            is_valid, validation_errors = self.validate_inputs(**kwargs)
            if not is_valid:
                self.logger.error(f"Input validation failed: {validation_errors}")
                self.metrics['failures'] += 1
                return AgentResult(
                    success=False,
                    data={},
                    errors=validation_errors,
                    warnings=[],
                    metadata={'validated': False}
                )

            # 2. Execute agent logic
            result = self.execute(**kwargs)

            # 3. Update metrics
            execution_time = time.time() - start_time
            result.execution_time = execution_time
            self.metrics['executions'] += 1
            self.metrics['total_execution_time'] += execution_time

            if result.success:
                self.metrics['successes'] += 1
                self.logger.info(f"{self.__class__.__name__} completed successfully in {execution_time:.2f}s")
            else:
                self.metrics['failures'] += 1
                self.logger.error(f"{self.__class__.__name__} failed: {result.errors}")

            return result

        except Exception as e:
            # Catch any unhandled exceptions
            execution_time = time.time() - start_time
            self.metrics['failures'] += 1
            self.logger.exception(f"{self.__class__.__name__} crashed: {e}")

            return AgentResult(
                success=False,
                data={},
                errors=[f"Agent crashed: {str(e)}"],
                warnings=[],
                metadata={'exception': type(e).__name__},
                execution_time=execution_time
            )

    def validate_inputs(self, **kwargs) -> Tuple[bool, List[str]]:
        """
        Validate input parameters.

        Subclasses can override this for custom validation.

        Args:
            **kwargs: Parameters to validate

        Returns:
            (is_valid, error_messages)

        Example:
            def validate_inputs(self, **kwargs):
                errors = []
                if 'target_av' not in kwargs:
                    errors.append("target_av is required")
                return len(errors) == 0, errors
        """
        # Default: no validation, all inputs valid
        return True, []

    def cleanup(self):
        """
        Cleanup agent resources.

        Subclasses can override this for custom cleanup (closing files, DB connections, etc.)
        """
        self.logger.debug(f"{self.__class__.__name__} cleanup")
        self.state.clear()

    def get_state(self) -> Dict:
        """
        Get current agent state.

        Returns:
            Copy of state dict
        """
        return self.state.copy()

    def get_metrics(self) -> Dict:
        """
        Get agent metrics.

        Returns:
            Metrics dict with execution statistics
        """
        metrics = self.metrics.copy()

        # Add computed metrics
        if metrics['executions'] > 0:
            metrics['success_rate'] = metrics['successes'] / metrics['executions']
            metrics['avg_execution_time'] = metrics['total_execution_time'] / metrics['executions']
        else:
            metrics['success_rate'] = 0.0
            metrics['avg_execution_time'] = 0.0

        return metrics

    def reset_metrics(self):
        """Reset all metrics to zero"""
        self.metrics = {
            'executions': 0,
            'successes': 0,
            'failures': 0,
            'total_execution_time': 0.0
        }
        self.logger.info("Metrics reset")

    def __repr__(self) -> str:
        """String representation"""
        return f"<{self.__class__.__name__} executions={self.metrics['executions']} success_rate={self.get_metrics()['success_rate']:.1%}>"
