#!/usr/bin/env python3
"""
Noctis-MCP Agent System
========================

Agent-based architecture for autonomous malware development workflows.

Available agents:
- TechniqueSelectionAgent: AI-powered technique recommendation
- MalwareDevelopmentAgent: End-to-end malware creation
- OpsecOptimizationAgent: Iterative OPSEC improvement
- LearningAgent: Feedback collection and learning

Author: Noctis-MCP Community
License: MIT
"""

from typing import Dict, Optional
import logging

# Import base classes
from .base_agent import BaseAgent, AgentResult



logger = logging.getLogger(__name__)


class AgentRegistry:
    """
    Centralized agent management with lifecycle control.

    Features:
    - Lazy initialization of agents
    - Dependency injection via config
    - Singleton pattern per agent type
    - Metrics collection
    - Graceful cleanup
    """

    _instances: Dict[str, BaseAgent] = {}
    _config: Dict = {}
    _initialized: bool = False

    @classmethod
    def initialize(cls, config: Dict):
        """
        Initialize registry with configuration.

        Args:
            config: Configuration dict with paths, settings, etc.
        """
        if cls._initialized:
            logger.warning("AgentRegistry already initialized, reinitializing...")
            cls.cleanup_all()

        cls._config = config
        cls._initialized = True
        logger.info(f"AgentRegistry initialized with config: {list(config.keys())}")

    @classmethod
    def set_learning_engine(cls, learning_engine):
        """
        Set learning engine after initialization to break circular dependency.

        Args:
            learning_engine: The AgenticLearningEngine instance
        """
        cls._config['learning_engine'] = learning_engine
        logger.info("Learning engine injected into AgentRegistry")

    @classmethod
    def get_agent(cls, agent_type: str) -> BaseAgent:
        """
        Get or create agent instance.

        Args:
            agent_type: Type of agent ('technique_selection', 'malware_development', etc.)

        Returns:
            BaseAgent instance

        Raises:
            ValueError: If agent type is unknown
            RuntimeError: If registry not initialized
        """
        if not cls._initialized:
            raise RuntimeError("AgentRegistry not initialized. Call initialize() first.")

        # Create agent if not exists
        if agent_type not in cls._instances:
            logger.info(f"Creating new agent instance: {agent_type}")
            cls._instances[agent_type] = cls._create_agent(agent_type)

        return cls._instances[agent_type]

    @classmethod
    def _create_agent(cls, agent_type: str) -> BaseAgent:
        """
        Create agent instance based on type.

        Args:
            agent_type: Type of agent to create

        Returns:
            BaseAgent instance

        Raises:
            ValueError: If agent type is unknown
        """
        # Import here to avoid circular dependencies
        # Will be uncommented as agents are implemented
        from .technique_selection_agent import TechniqueSelectionAgent
        from .malware_development_agent import MalwareDevelopmentAgent
        from .opsec_optimization_agent import OpsecOptimizationAgent
        from .learning_agent import LearningAgent

        agents = {
            'technique_selection': TechniqueSelectionAgent,
            'malware_development': MalwareDevelopmentAgent,
            'opsec_optimization': OpsecOptimizationAgent,
            'learning': LearningAgent
        }

        if agent_type not in agents:
            raise ValueError(f"Unknown agent type: {agent_type}. Available: {list(agents.keys())}")

        agent_class = agents[agent_type]
        return agent_class(cls._config)

    @classmethod
    def list_agents(cls) -> Dict[str, Dict]:
        """
        List all registered agent instances with their status.

        Returns:
            Dict mapping agent type to status info
        """
        status = {}
        for agent_type, agent in cls._instances.items():
            status[agent_type] = {
                'type': agent.__class__.__name__,
                'state': agent.get_state(),
                'metrics': agent.get_metrics()
            }
        return status

    @classmethod
    def cleanup_all(cls):
        """Cleanup all agent instances"""
        logger.info(f"Cleaning up {len(cls._instances)} agent instances...")

        for agent_type, agent in cls._instances.items():
            try:
                logger.debug(f"Cleaning up agent: {agent_type}")
                agent.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up {agent_type}: {e}")

        cls._instances.clear()
        cls._initialized = False
        logger.info("All agents cleaned up")


__all__ = [
    'BaseAgent',
    'AgentResult',
    'AgentRegistry',
]
