"""
Attack Testing System

LLM-powered attack testing system for evaluating agent detection capabilities.
"""

__version__ = "0.1.0"

from attack_testing.attack_generator import AttackGenerator, AttackData, HackerScenario
from attack_testing.chat_interface import ChatInterface, ChatResponse, AttackIntent
from attack_testing.test_orchestrator import TestOrchestrator
from attack_testing.test_results import TestResult, TestReport, SequenceTestResult
from attack_testing.api import create_app, run_api_server

__all__ = [
    'AttackGenerator',
    'AttackData',
    'HackerScenario',
    'ChatInterface',
    'ChatResponse',
    'AttackIntent',
    'TestOrchestrator',
    'TestResult',
    'TestReport',
    'SequenceTestResult',
    'create_app',
    'run_api_server',
]
