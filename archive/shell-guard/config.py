#!/usr/bin/env python3
"""
Generate C headers from config.yaml for shell-guard and compartment-root.

Produces:
  config.h                  — shell-guard compile-time policy
  compartment-root-config.h — compartment-root default policy
"""
import yaml
import sys


def c_escape(s):
    """Escape a string for use in a C string literal."""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def write_string_array(f, name, items):
    f.write(f'static const char *{name}[] = {{\n')
    for item in items:
        f.write(f'    "{c_escape(str(item))}",\n')
    f.write('    NULL\n};\n\n')


def write_uid_array(f, name, items, type_name='uid_t'):
    f.write(f'static const {type_name} {name}[] = {{\n')
    for item in items:
        if not isinstance(item, int) or item < 0:
            print(f'ERROR: {name}: expected non-negative integer, got {item!r}', file=sys.stderr)
            sys.exit(1)
        f.write(f'    {item},\n')
    f.write(f'    ({type_name})-1\n}};\n\n')


def generate_shell_guard_header(config, header_file):
    """Generate config.h for shell-guard (compile-time policy)."""
    shared = config
    sg = config.get('shell_guard', {})

    with open(header_file, 'w') as f:
        f.write('/* Auto-generated from config.yaml — do not edit manually */\n')
        f.write('/* Policy header for shell-guard */\n\n')
        f.write('#ifndef SHELL_GUARD_CONFIG_H\n')
        f.write('#define SHELL_GUARD_CONFIG_H\n\n')

        write_uid_array(f, 'allowed_uids', sg.get('allowed_uids', []), 'uid_t')
        write_uid_array(f, 'allowed_gids', sg.get('allowed_gids', []), 'gid_t')

        write_string_array(f, 'allowed_cwds', sg.get('allowed_cwds', []))
        write_string_array(f, 'allowed_executables', sg.get('allowed_executables', []))
        write_string_array(f, 'forbidden_env_vars', shared.get('forbidden_env_vars', []))
        write_string_array(f, 'allowed_env_vars', shared.get('allowed_env_vars', []))
        write_string_array(f, 'allowed_network_ranges', shared.get('allowed_network_ranges', []))
        write_string_array(f, 'seccomp_allowed_syscalls', sg.get('seccomp_allowed_syscalls', []))

        f.write('#endif /* SHELL_GUARD_CONFIG_H */\n')


def generate_compartment_root_header(config, header_file):
    """Generate compartment-root-config.h (default policy, overridable by CLI).

    NOTE: This header is generated but not yet #included by any C source.
    Kept for forward compatibility — compartment-root will use it once
    compile-time defaults are wired in.
    """
    shared = config
    cr = config.get('compartment_root', {})

    with open(header_file, 'w') as f:
        f.write('/* Auto-generated from config.yaml — do not edit manually */\n')
        f.write('/* Default policy for compartment-root (CLI flags override) */\n\n')
        f.write('#ifndef COMPARTMENT_ROOT_CONFIG_H\n')
        f.write('#define COMPARTMENT_ROOT_CONFIG_H\n\n')

        write_string_array(f, 'default_forbidden_env_vars', shared.get('forbidden_env_vars', []))
        write_string_array(f, 'default_seccomp_allowed', cr.get('seccomp_allowed_syscalls', []))
        write_string_array(f, 'default_cap_deny', cr.get('cap_deny', []))

        f.write('#endif /* COMPARTMENT_ROOT_CONFIG_H */\n')


def main():
    yaml_file = 'config.yaml'
    if len(sys.argv) > 1:
        yaml_file = sys.argv[1]

    with open(yaml_file, 'r') as f:
        config = yaml.safe_load(f)

    required_keys = ['forbidden_env_vars', 'allowed_env_vars', 'allowed_network_ranges']
    for key in required_keys:
        if key not in config:
            print(f'ERROR: missing required key "{key}" in {yaml_file}', file=sys.stderr)
            sys.exit(1)

    if 'shell_guard' not in config:
        print(f'WARNING: no "shell_guard" section in {yaml_file}', file=sys.stderr)
    if 'compartment_root' not in config:
        print(f'WARNING: no "compartment_root" section in {yaml_file}', file=sys.stderr)

    generate_shell_guard_header(config, 'config.h')
    print(f'Generated: config.h (shell-guard)')

    generate_compartment_root_header(config, 'compartment-root-config.h')
    print(f'Generated: compartment-root-config.h (compartment-root)')


if __name__ == '__main__':
    main()
