import asyncio

from blind_test import run_blind_test
from chaos_test import run_chaos_test
from final_blind_test import run_blind_test as run_final_blind_test
from resiliency_test import run_resiliency_test
from scale_test import run_scale_test


def test_blind_validation():
    asyncio.run(run_blind_test())


def test_chaos_validation():
    asyncio.run(run_chaos_test())


def test_final_blind_validation():
    asyncio.run(run_final_blind_test())


def test_resiliency_validation():
    asyncio.run(run_resiliency_test())


def test_scale_validation():
    asyncio.run(run_scale_test())
