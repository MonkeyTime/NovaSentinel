from novaguard.research import RESEARCH_NOTES, research_summary


def test_research_summary_includes_latest_integrated_and_roadmap_notes():
    summary = research_summary("fr")
    titles = {note["title"] for note in RESEARCH_NOTES}

    assert "Enhancing Ransomware Threat Detection" in " ".join(titles)
    assert "Ransomware Detection Using Windows API Calls" in " ".join(titles)
    assert "Generating Adversarial Malware Examples" in " ".join(titles)
    assert "An Explainable Memory Forensics Approach for Malware Analysis" in " ".join(titles)
    assert "integre" in summary
    assert "post-alert" in summary
    assert "Integration NovaSentinel" in summary
    assert "familles d'intention API" in summary


def test_research_notes_include_concrete_product_mapping():
    for note in RESEARCH_NOTES:
        assert note["idea"]
        assert note["implemented"]
        assert note["status"] in {"integrated", "roadmap"}
