"""Регресійні тести РГР: кожна підтверджена вразливість V1–V9 НЕ повинна відтворюватися.

Тест виконує той самий PoC-сценарій, що й exploits/poc.py, на живому стенді й очікує,
що атака заблокована. На коміті «до» виправлень усі тести падають (вразливості є),
після виправлень — проходять. Повернення дефекту знову зробить тест червоним.
"""
import pytest

from exploits import poc


@pytest.mark.parametrize("scenario", poc.ALL, ids=lambda f: f.__name__.split("_")[0].upper())
def test_vulnerability_is_not_exploitable(scenario):
    result = scenario(None)
    assert not result.exploited, f"{result.vid} ({result.level}): {result.title} — {result.detail}"
