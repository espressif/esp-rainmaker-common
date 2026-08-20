#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""Assert that the ESP-IDF default port stays strippable, and that the core names no backend.

rmaker_aws_sign reaches the outside world through the function-pointer tables in
include/esp_rmaker_aws_sign.h. The ESP-IDF implementations live in port/esp/, and
src/esp_rmaker_aws_sign_default.c - which holds esp_rmaker_aws_sign_port_install_default() and
nothing else - is their only referrer.

That is the link-strip guarantee. An application calling
esp_rmaker_aws_sign_port_install() and never esp_rmaker_aws_sign_port_install_default() leaves
esp_rmaker_aws_sign_default.o unreferenced, so the linker never pulls it out of
librmaker_aws_sign.a, and the default port stays out of the image along with the
esp_http_client, esp-tls, mbedtls, FreeRTOS-semaphore and esp_log code it would
have dragged in. It works at archive-member granularity, so it does not depend on
--gc-sections.

It is also fragile in a way no compiler warns about, and it has three halves:

  1. No second referrer *inside the component*. Naming an
     esp_rmaker_aws_sign_esp_*_ops table from any other file here makes the tables
     reachable from an object every caller already needs. Application code is free
     to name them - that is what esp_rmaker_aws_sign_esp_port.h is for, and it
     only links what it names.

  2. No second reason to link esp_rmaker_aws_sign_default.o. The guarantee rests
     on esp_rmaker_aws_sign_port_install_default() being the *only* external symbol in that
     object. Adding any other non-static function or variable to it - a version
     getter, a helper, a counter - gives every caller of that symbol a reason to
     pull the member in, and the default port comes with it.

  3. No backend named in the core. No file under src/ may mention mbedtls,
     openssl, psa_, cJSON, esp_http_client or esp_log. This is the check that
     stops the crypto and HTTP ports quietly decaying back into direct calls, and
     it is what keeps the platform-independent half's PRIV_REQUIRES empty.

Checked at source level rather than with nm on a built ELF because demonstrating
the strip needs an application that installs a non-ESP port.

Known limits, so the next reader does not over-trust this:
  - Half 2 relies on the repo's formatting (definitions start at column zero,
    OTBS braces). It is a lint, not a C parser. A definition written in an
    unusual layout can slip past it.
  - None of the halves see through macros. A reference assembled by token pasting
    is not detected.
  - Comments and string literals are stripped before matching, so discussing a
    table name or a backend in prose is fine and quoting one is not a reference.

Usage:
    check_port_isolation.py [--root <component-dir>]
"""

import argparse
import re
import sys
from pathlib import Path

# Referencing any of these forces the corresponding port/esp object into the link.
PORT_SYMBOL_RE = re.compile(r'\besp_rmaker_aws_sign_esp_(?:\w+_ops|log)\b')

# The declaration site, and the one definition site permitted to name them.
ALLOWED = {
    Path('src/esp_rmaker_aws_sign_default.c'),
    Path('include/esp_rmaker_aws_sign_esp_port.h'),
}

# port/esp/*.c each define their own table; that is the definition, not a
# cross-reference, and those files are already inside the strippable set.
ALLOWED_DIRS = {Path('port/esp')}

SEARCH_DIRS = ('src', 'include', 'priv_include', 'port')

# The file whose external surface must stay at exactly one symbol, and that symbol.
SOLE_REFERRER = Path('src/esp_rmaker_aws_sign_default.c')
SOLE_EXPORT = 'esp_rmaker_aws_sign_port_install_default'

# Backends the core must never name. Every one of them belongs behind a port.
BACKEND_RE = re.compile(r'\b(?:mbedtls\w*|MBEDTLS_\w+|openssl|OPENSSL_\w+|psa_\w+|cJSON\w*|'
                        r'esp_http_client\w*|esp_log\w*|ESP_LOG[A-Z]|xSemaphore\w+)\b')
BACKEND_DIRS = ('src',)

# A definition at file scope: no leading whitespace, and not a continuation.
# Deliberately conservative - see "Known limits" above.
EXTERNAL_DEF_RE = re.compile(
    r'''^(?!\s)                     # column zero
        (?!static\b|extern\b|typedef\b)
        (?P<decl>[A-Za-z_][^;{()]*?)   # return type / type and qualifiers
        \b(?P<name>[A-Za-z_]\w*)\s*
        (?:\((?P<params>[^;{]*)\)\s*\{ # function definition (body follows)
          |=                           # or an initialised object definition
        )''',
    re.VERBOSE | re.MULTILINE)


def strip_comments_and_strings(text):
    """Blank out comments and string/char literals, preserving line structure.

    Replacing rather than deleting keeps every line number intact, so a reported
    line matches the file.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == '/*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join(c if c == '\n' else ' ' for c in text[i:j]))
            i = j
        elif two == '//':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif ch in '"\'':
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(''.join(c if c == '\n' else ' ' for c in text[i:j]))
            i = j
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def sources(root, directories):
    for directory in directories:
        for path in sorted((root / directory).rglob('*')):
            if path.suffix in ('.c', '.h') and path.is_file():
                yield path


def check_no_second_referrer(root):
    """Half 1: only the allowed files may name an esp_rmaker_aws_sign_esp_*_ops table."""
    offenders, checked = [], 0
    for path in sources(root, SEARCH_DIRS):
        rel = path.relative_to(root)
        checked += 1
        if rel in ALLOWED or rel.parent in ALLOWED_DIRS:
            continue
        code = strip_comments_and_strings(path.read_text())
        for lineno, line in enumerate(code.splitlines(), 1):
            match = PORT_SYMBOL_RE.search(line)
            if match:
                offenders.append((rel, lineno, match.group(0), line.strip()))
    return offenders, checked


def check_sole_export(root):
    """Half 2: the default file must define nothing but esp_rmaker_aws_sign_port_install_default."""
    path = root / SOLE_REFERRER
    if not path.is_file():
        return [(SOLE_REFERRER, 0, '<missing>', 'file not found')]
    code = strip_comments_and_strings(path.read_text())
    extras = []
    for match in EXTERNAL_DEF_RE.finditer(code):
        name = match.group('name')
        if name == SOLE_EXPORT:
            continue
        lineno = code.count('\n', 0, match.start()) + 1
        extras.append((SOLE_REFERRER, lineno, name, match.group(0).strip()))
    return extras


def check_no_backend_in_core(root):
    """Half 3: no file under src/ may name a crypto, HTTP, JSON or logging backend."""
    offenders = []
    for path in sources(root, BACKEND_DIRS):
        rel = path.relative_to(root)
        if rel in ALLOWED:
            continue
        code = strip_comments_and_strings(path.read_text())
        for lineno, line in enumerate(code.splitlines(), 1):
            match = BACKEND_RE.search(line)
            if match:
                offenders.append((rel, lineno, match.group(0), line.strip()))
    return offenders


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=Path(__file__).parent, type=Path,
                    help="component directory (default: this script's directory)")
    args = ap.parse_args()

    offenders, checked = check_no_second_referrer(args.root)
    extras = check_sole_export(args.root)
    backends = check_no_backend_in_core(args.root)

    if not offenders and not extras and not backends:
        print(f'PASS: only {SOLE_REFERRER} and port/esp/ name the default port tables,')
        print(f'      {SOLE_REFERRER} exports nothing but {SOLE_EXPORT}(),')
        print('      and no file under src/ names a backend')
        print(f'      checked {checked} sources')
        return 0

    print('FAIL: the port layer no longer holds')

    if offenders:
        print('\n  Referenced outside its single referrer:')
        for rel, lineno, symbol, line in offenders:
            print(f'    {rel}:{lineno}: {symbol}')
            print(f'      {line}')
        print('\n    Any such reference links the default port - and')
        print('    esp_http_client, esp-tls, mbedtls and esp_log - into every')
        print('    build, including applications that only call')
        print('    esp_rmaker_aws_sign_port_install(). Keep the reference in')
        print(f'    {SOLE_REFERRER}, or add the new file to ALLOWED here if it')
        print('    is genuinely part of the default port.')

    if extras:
        print(f'\n  Extra external symbols in {SOLE_REFERRER}:')
        for rel, lineno, name, line in extras:
            print(f'    {rel}:{lineno}: {name}')
            print(f'      {line}')
        print(f'\n    {SOLE_REFERRER} must export only {SOLE_EXPORT}(). Any other')
        print('    external symbol gives its callers a reason to pull this')
        print('    object out of the archive, which links the default port even')
        print('    into applications that never call esp_rmaker_aws_sign_port_install_default().')
        print('    Put the new symbol in another file, or make it static.')

    if backends:
        print('\n  Backend named in the core:')
        for rel, lineno, symbol, line in backends:
            print(f'    {rel}:{lineno}: {symbol}')
            print(f'      {line}')
        print('\n    Crypto, HTTP, JSON and logging reach the outside world only')
        print('    through the installed port. Naming a backend under src/ makes')
        print('    it a dependency of the platform-independent half, which is')
        print('    what RMAKER_AWS_SIGN_PRIV_REQUIRES being empty depends on.')
        print('    Put the call in a port/ file and reach it through the ops table.')

    return 1


if __name__ == '__main__':
    sys.exit(main())
