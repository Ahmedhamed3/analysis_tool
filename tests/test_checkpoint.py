from pathlib import Path

from app.utils.checkpoint import Checkpoint, load_checkpoint, save_checkpoint


def test_checkpoint_load_save(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    checkpoint = Checkpoint(last_record_id=42)
    save_checkpoint(path, checkpoint)
    loaded = load_checkpoint(path)
    assert loaded.last_record_id == 42


def test_checkpoint_missing_returns_default(tmp_path: Path) -> None:
    path = tmp_path / "missing.json"
    loaded = load_checkpoint(path)
    assert loaded.last_record_id == 0
