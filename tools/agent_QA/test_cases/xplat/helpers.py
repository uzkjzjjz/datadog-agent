from test_builder import Platform


def confDir(config):
    if config.platform == Platform.linux:
        return "in `/etc/datadog/conf.d/qa.d/conf.yaml`"

    if config.platform == Platform.mac:
        return "in `~/.datadog-agent/conf.d/conf.d/qa.d/conf.yaml`"

    if config.platform == Platform.windows:
        return "in `C:\\programdata\\datadog\\conf.d\\qa.d\\conf.yaml` (you may need to enable showing hidden files to see `c:\\programdata`):"


def filePositionSharedSteps():
    return """
Repeat the steps with:
- `start_position: end` (with an existing `registry.json` for this source, previous `start_position` should be `beginning`) should tail from the end of the file, not the offset in registry (ie, same as `forceEnd`)
- `start_position: end` (with an existing `registry.json` for this source, previous `start_position` should be `end`) should tail from the offset in registry
- `start_position: beginning` (with an existing `registry.json` for this source, previous `start_position` should be `end`) - should tail from the offset in registry
- `start_position: end` and delete the `registry.json` first - should start from the end
- `start_position: beginning` and delete the `registry.json` first - should start from the beginning
- `start_position: forceBeginning` (with an existing `registry.json` for this source) - should tail from the beginning, ignoring the offset from the registry
- `start_position: forceEnd` (with an existing `registry.json` for this source) - should tail from the end, ignoring the offset from the registry
"""
