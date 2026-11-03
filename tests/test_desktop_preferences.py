from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace

from tkinter import ttk
import pytest

import novaguard.config as config
import novaguard.ui.dashboard as dashboard
from novaguard.core.premium import PremiumState
from novaguard.models import AppSettings


class PreviewEngine:
    """In-memory desktop fixture: no monitoring, quarantine or network access."""

    def __init__(self):
        self.settings = AppSettings(language="fr")
        self.state = {
            "scan_in_progress": False, "scan_cancel_requested": False, "scan_label": "Idle",
            "scan_progress": 0, "files_scanned": 0, "scan_total_files": 0, "threats_found": 0,
            "last_scan_summary": "No scan yet",
        }
        self.quarantine = SimpleNamespace(restore=lambda key: None, delete=lambda key: None)

    def get_snapshot(self):
        return {"settings": self.settings, "state": self.state, "history": [], "events": [],
                "quarantine": [], "current_scan_threats": [], "incidents": [], "telemetry": {}}

    def get_premium_state(self):
        return PremiumState(False, "inactive")

    def quick_scan(self):
        pass

    full_scan = quick_scan
    panic_mode = quick_scan
    release_panic_mode = quick_scan

    def update_settings(self, settings):
        self.settings = settings

    def update_window_geometry(self, geometry):
        self.settings.window_geometry = geometry


@pytest.fixture(scope="module")
def window():
    monkeypatch = pytest.MonkeyPatch()
    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(dashboard, "ensure_icon_assets", lambda: (root / "installer/novasentinel_icon.png", root / "installer/novasentinel_icon.ico"))
    monkeypatch.setattr(dashboard.NovaSentinelWindow, "check_for_updates", lambda self: None)
    monkeypatch.setattr(config, "save_settings", lambda settings: None)
    app = dashboard.NovaSentinelWindow(PreviewEngine())
    app.withdraw()
    yield app
    for callback in app.tk.call("after", "info"):
        app.tk.call("after", "cancel", callback)
    app.destroy()
    monkeypatch.undo()


def test_theme_switch_updates_native_tables_and_keeps_view(window):
    window.show_view("Scan Center")
    window.target_entry.insert(0, "C:/sample")
    for mode in (True, False):
        window.dark_mode_var.set(mode)
        window.change_appearance()
        assert window.engine.settings.appearance_mode == ("dark" if mode else "light")
        assert window.current_view == "Scan Center"
        assert window.target_entry.get() == "C:/sample"
        style = ttk.Style(window)
        assert style.lookup("Nova.Treeview", "background") == window._theme_color("bg")


def test_scan_completion_never_opens_modal(window, monkeypatch):
    monkeypatch.setattr(dashboard.messagebox, "showinfo", lambda *args: pytest.fail("Unexpected modal"))
    monkeypatch.setattr(dashboard.messagebox, "showwarning", lambda *args: pytest.fail("Unexpected modal"))
    notifications = []
    window.notifier = lambda *args: notifications.append(args)
    window._notify_scan_transition("Quick scan completed: 1 files, 0 threats.")
    assert not notifications
    window.engine.settings.notify_scan_completion = True
    window._notify_scan_transition("Quick scan completed: 2 files, 0 threats.")
    assert len(notifications) == 1
    window._notify_scan_transition("Quick scan completed: 2 files, 0 threats.")
    assert len(notifications) == 1


def test_settings_and_theme_survive_language_rebuild(window):
    window.settings_vars["notify_scan_completion"].set(True)
    window.language_var.set("English")
    window.save_settings()
    assert window.language == "en"
    assert window.engine.settings.notify_scan_completion
    assert window.dark_mode_var.get() is False


def test_review_identifies_full_path_and_preserves_selection(window):
    items = [{"path": f"C:/{folder}/same.exe", "score": 71, "severity": "medium",
              "scanned_at": "2026-11-03", "hits": [{"explanation": "review", "evidence": "static"}]}
             for folder in ("one", "two")]
    window._refresh_scan_threats(items)
    selected = "C:/two/same.exe::0"
    window.scan_threat_tree.selection_set(selected)
    items[1]["action_taken"] = "ignored"
    window._refresh_scan_threats(items)
    assert window.scan_threat_tree.selection() == (selected,)
    calls = []
    window.engine.ignore_current_threat = lambda path: (calls.append(path) or True, "saved")
    window.review_selected_threat("ignore")
    assert calls == ["C:/two/same.exe"]


def test_navigation_exposes_expert_tools_and_keeps_breadcrumb(window):
    for name in window.frames:
        window.show_view(name)
        assert window.current_view == name
        assert window.breadcrumb_var.get()
    window.show_view("Forensics")
    assert window._advanced_expanded
    assert window.advanced_navigation.winfo_manager() == "pack"
    window.show_view("Dashboard")


def test_home_values_use_settings_and_real_review_actions(window):
    snapshot = window.engine.get_snapshot()
    snapshot["settings"] = replace(snapshot["settings"], realtime_enabled=False)
    snapshot["current_scan_threats"] = [{"action_taken": action} for action in ("none", "ignored", "quarantined")]
    snapshot["quarantine"] = [{"id": "a", "original_name": "example.ps1"}]
    window._refresh_workspace(snapshot)
    assert window.home_values["shields"].get() == "2 / 3"
    assert window.home_values["review"].get() == "1"
    assert window.home_values["quarantine"].get() == "1"
    assert window.home_title_var.get() == window.u("partial")
    window._refresh_workspace(window.engine.get_snapshot())


def test_home_scan_opens_progress_without_starting_duplicate(window, monkeypatch):
    calls = []
    monkeypatch.setattr(window.engine, "quick_scan", lambda: calls.append("quick"))
    window.engine.state["scan_in_progress"] = False
    window._home_scan()
    assert calls == ["quick"]
    assert window.current_view == "Scan Center"
    window.engine.state["scan_in_progress"] = True
    try:
        window._home_scan()
        assert calls == ["quick"]
    finally:
        window.engine.state["scan_in_progress"] = False


def test_activity_filters_events_and_file_history(window):
    snapshot = window.engine.get_snapshot()
    snapshot["events"] = [
        {"level": "info", "title": "Routine scan", "description": "all clear"},
        {"level": "warning", "title": "Client document", "description": "needs review"},
    ]
    snapshot["history"] = [
        {"severity": "low", "path": "C:/safe.exe", "score": 25},
        {"severity": "medium", "path": "C:/client.exe", "score": 71},
    ]
    window.activity_kind_var.set(window.u("events_tab"))
    window.activity_search_var.set("client")
    window.activity_alerts_var.set(True)
    window._refresh_activity(snapshot)
    assert len(window.event_tree.get_children()) == 1
    window.activity_kind_var.set(window.u("files_tab"))
    window._refresh_activity(snapshot)
    ids = window.activity_result_tree.get_children()
    assert len(ids) == 1
    assert window.activity_result_tree.item(ids[0], "values")[3] == "C:/client.exe"
    window.activity_search_var.set("no match exists")
    assert window.activity_empty.winfo_manager() == "pack"
    assert not window.activity_result_tree.container.winfo_manager()
    window.activity_search_var.set("")
    window.activity_alerts_var.set(False)
    window.activity_kind_var.set(window.u("events_tab"))


def test_running_or_failed_scan_does_not_display_all_clear(window):
    window._refresh_scan_empty_state([], {"scan_in_progress": True, "last_scan_summary": "No scan yet"})
    assert window.scan_empty_title.cget("text") == window.u("scan_running")
    window._refresh_scan_empty_state([], {"scan_in_progress": False, "last_scan_summary": "Quick scan failed after 3 files: error"})
    assert window.scan_empty_title.cget("text") == window.t("notify.interrupted")


def test_custom_scan_validates_target_inline(window, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(window.engine, "custom_scan", calls.append, raising=False)
    window.target_entry.delete(0, "end")
    window.scan_custom_target()
    assert not calls
    assert window.scan_input_feedback_var.get() == window.u("target_required")
    sample = tmp_path / "ordinary.txt"
    sample.write_text("ordinary text", encoding="utf-8")
    window.target_entry.insert(0, str(sample))
    window.scan_custom_target()
    assert calls == [str(sample)]
    assert not window.scan_input_feedback_var.get()


def test_quarantine_actions_wait_for_explicit_confirmation(window, monkeypatch):
    calls = []
    entry = {"id": "b" * 32, "original_name": "sample.exe", "original_path": "C:/sample.exe"}
    window._refresh_quarantine([entry])
    window.quarantine_tree.selection_set(entry["id"])
    window._refresh_quarantine_actions()
    assert window.quarantine_delete_button.cget("state") == "normal"
    monkeypatch.setattr(window.engine.quarantine, "delete", lambda key: calls.append(key) or True)
    monkeypatch.setattr(dashboard.messagebox, "askyesno", lambda *args, **kwargs: False)
    window.delete_selected()
    assert not calls
    monkeypatch.setattr(dashboard.messagebox, "askyesno", lambda *args, **kwargs: True)
    window.delete_selected()
    assert calls == [entry["id"]]
    assert window.quarantine_feedback_var.get() == window.u("action_done")
    assert window.quarantine_delete_button.cget("state") == "disabled"


def test_update_badge_can_be_shown_in_sidebar_footer(window, monkeypatch):
    monkeypatch.setattr(window, "update_info", SimpleNamespace(version="0.2.5"))
    window._refresh_update_button()
    assert window.update_button.winfo_manager() == "pack"


def test_unsaved_preferences_survive_navigation_and_theme_switch(window):
    window.show_view("Settings")
    previous = window.settings_vars["notify_scan_completion"].get()
    window.settings_vars["notify_scan_completion"].set(not previous)
    window.paths_box.delete("1.0", "end")
    window.paths_box.insert("1.0", "C:/chosen-folder")
    window.show_view("Dashboard")
    window.dark_mode_var.set(True)
    window.change_appearance()
    window.show_view("Settings")
    assert window.settings_vars["notify_scan_completion"].get() == (not previous)
    assert window.paths_box.get("1.0", "end").strip() == "C:/chosen-folder"


def test_one_file_row_expands_all_evidence_on_selection(window):
    item = {"path": "C:/review/sample.ps1", "score": 71, "severity": "medium",
            "hits": [{"explanation": "First explanation", "evidence": "first signal"},
                     {"explanation": "Second explanation", "evidence": "second signal"}]}
    window._refresh_scan_threats([item])
    assert len(window.scan_threat_tree.get_children()) == 1
    window.scan_threat_tree.selection_set("C:/review/sample.ps1::0")
    window._refresh_review_actions()
    assert "second signal" in window.scan_detail_text.get("1.0", "end")
    assert window.scan_detail_card.winfo_manager() == "pack"
    window._refresh_scan_threats([])
    assert not window.scan_detail_card.winfo_manager()
    assert all(button.cget("state") == "disabled" for button in window.review_buttons)


def test_full_refresh_keeps_completed_summary_and_reports_no_ui_error(window):
    previous = window.engine.state["last_scan_summary"]
    window.engine.state["last_scan_summary"] = "Quick scan completed: 418 files, 0 threats."
    try:
        window.refresh_view()
        assert "418" in window.quick_summary_var.get()
        assert not window.status_var.get().startswith("UI refresh recovered")
    finally:
        window.engine.state["last_scan_summary"] = previous
