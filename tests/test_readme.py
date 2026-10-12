from redteam.config import Settings
from redteam.readme import END, START, render, update
from redteam.suite import run_suite


def test_render_has_markers_and_table():
    report = run_suite(Settings(llm_provider="stub"))
    text = render(report)
    assert text.startswith(START) and text.endswith(END)
    assert "Attack success rate" in text and "LLM01" in text


def test_stub_runs_never_touch_the_readme(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"intro\n{START}\nold\n{END}\n", encoding="utf-8")
    report = run_suite(Settings(llm_provider="stub"))
    assert update(readme, report) is False
    assert "old" in readme.read_text(encoding="utf-8")


def test_real_run_replaces_only_the_block(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"intro\n{START}\nold\n{END}\noutro\n", encoding="utf-8")
    report = run_suite(Settings(llm_provider="stub"))
    report["provider"] = "groq"  # pretend it was a real run
    assert update(readme, report) is True
    text = readme.read_text(encoding="utf-8")
    assert text.startswith("intro") and text.rstrip().endswith("outro") and "old" not in text
