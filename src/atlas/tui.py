"""Compatibility entry point for the integrated ATLAS terminal panel."""


def run_tui() -> None:
    from atlas.panel import AtlasPanel

    AtlasPanel().run()
