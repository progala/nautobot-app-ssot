"""Plugin declaration for nautobot_ssot."""
# Metadata is inherited from Nautobot. If not including Nautobot in the environment, this should be added
try:
    from importlib import metadata
except ImportError:
    # Python version < 3.8
    import importlib_metadata as metadata

__version__ = metadata.version(__name__)

from nautobot.extras.plugins import PluginConfig


class NautobotSSOTPluginConfig(PluginConfig):
    """Plugin configuration for the nautobot_ssot plugin."""

    name = "nautobot_ssot"
    verbose_name = "Single Source of Truth"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot Single Source of Truth."
    base_url = "ssot"
    required_settings = []
    min_version = "1.0.3"
    max_version = "1.9999"
    default_settings = {
        "hide_example_jobs": False,
    }
    caching_config = {}


config = NautobotSSOTPluginConfig  # pylint:disable=invalid-name
