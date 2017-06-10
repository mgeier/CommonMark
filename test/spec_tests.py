#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from difflib import unified_diff
import argparse
import re
import json
from normalize import normalize_html

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run cmark tests.')
    parser.add_argument('-p', '--program', dest='program', nargs='?', default=None,
            help='program to test')
    parser.add_argument('-s', '--spec', dest='spec', nargs='?', default='spec.txt',
            help='path to spec')
    parser.add_argument('-P', '--pattern', dest='pattern', nargs='?',
            default=None, help='limit to sections matching regex pattern')
    parser.add_argument('--library-dir', dest='library_dir', nargs='?',
            default=None, help='directory containing dynamic library')
    parser.add_argument('--no-normalize', dest='normalize',
            action='store_const', const=False, default=True,
            help='do not normalize HTML')
    parser.add_argument('-d', '--dump-tests', dest='dump_tests',
            action='store_const', const=True, default=False,
            help='dump tests in JSON format')
    parser.add_argument('--debug-normalization', dest='debug_normalization',
            action='store_const', const=True,
            default=False, help='filter stdin through normalizer for testing')
    parser.add_argument('-n', '--number', type=int, default=None,
            help='only consider the test with the given number')
    args = parser.parse_args(sys.argv[1:])

def out(str):
    sys.stdout.buffer.write(str.encode('utf-8')) 

def print_test_header(headertext, example_number, start_line, end_line):
    out("Example %d (lines %d-%d) %s\n" % (example_number,start_line,end_line,headertext))

def do_test(func, test, normalize, result_counts):
    try:
        actual_html = func(test['markdown'])
    except ExternalProgramError as e:
        print_test_header(test['section'], test['example'],
                          test['start_line'], test['end_line'])
        out('program returned error code %d\n' % e.returncode)
        sys.stdout.buffer.write(e.stderr)
        result_counts['error'] += 1
        return

    expected_html = test['html']
    unicode_error = None
    if normalize:
        try:
            passed = (normalize_html(actual_html) ==
                      normalize_html(expected_html))
        except UnicodeDecodeError as e:
            unicode_error = e
            passed = False
    else:
        passed = actual_html == expected_html
    if passed:
        result_counts['pass'] += 1
    else:
        print_test_header(test['section'], test['example'],
                          test['start_line'], test['end_line'])
        out(test['markdown'] + '\n')
        if unicode_error:
            out('Unicode error: ' + str(unicode_error) + '\n')
            out('Expected: ' + repr(expected_html) + '\n')
            out('Got:      ' + repr(actual_html) + '\n')
        else:
            expected_html_lines = expected_html.splitlines(keepends=True)
            actual_html_lines = actual_html.splitlines(keepends=True)
            for diffline in unified_diff(expected_html_lines,
                                         actual_html_lines,
                                         'expected HTML', 'actual HTML'):
                out(diffline)
        out('\n')
        result_counts['fail'] += 1


def get_tests(specfile):
    line_number = 0
    start_line = 0
    end_line = 0
    example_number = 0
    markdown_lines = []
    html_lines = []
    state = 0  # 0 regular text, 1 markdown example, 2 html output
    headertext = ''
    tests = []

    header_re = re.compile('#+ ')

    with open(specfile, 'r', encoding='utf-8', newline='\n') as specf:
        for line in specf:
            line_number = line_number + 1
            l = line.strip()
            if l == "`" * 32 + " example":
                state = 1
            elif state == 2 and l == "`" * 32:
                state = 0
                example_number = example_number + 1
                end_line = line_number
                tests.append({
                    "markdown":''.join(markdown_lines).replace('→',"\t"),
                    "html":''.join(html_lines).replace('→',"\t"),
                    "example": example_number,
                    "start_line": start_line,
                    "end_line": end_line,
                    "section": headertext})
                start_line = 0
                markdown_lines = []
                html_lines = []
            elif l == ".":
                state = 2
            elif state == 1:
                if start_line == 0:
                    start_line = line_number - 1
                markdown_lines.append(line)
            elif state == 2:
                html_lines.append(line)
            elif state == 0 and re.match(header_re, line):
                headertext = header_re.sub('', line).strip()
    return tests


def select_tests(specfile, pattern, number):
    all_tests = get_tests(specfile)
    if pattern:
        pattern_re = re.compile(pattern, re.IGNORECASE)
    else:
        pattern_re = re.compile('.')
    tests = [ test for test in all_tests if re.search(pattern_re, test['section']) and (not number or test['example'] == number) ]
    skipped = len(all_tests) - len(tests)
    return tests, skipped


def run_tests(func, tests, normalize):
    result_counts = {'pass': 0, 'fail': 0, 'error': 0}
    for test in tests:
        do_test(func, test, normalize, result_counts)
    return result_counts


def use_program(prog):
    import shlex
    from subprocess import Popen, PIPE

    def to_html(text):
        p1 = Popen(shlex.split(prog), stdout=PIPE, stdin=PIPE, stderr=PIPE)
        stdout, stderr = p1.communicate(input=text.encode('utf-8'))
        if p1.returncode:
            raise ExternalProgramError(p1.returncode, stdout, stderr)
        return stdout.decode('utf-8')

    return to_html


def use_library(library_dir):
    from ctypes import CDLL, c_char_p, c_long
    import platform
    import os

    sysname = platform.system()
    if sysname == 'Darwin':
        libname = 'libcmark.dylib'
    elif sysname == 'Windows':
        libname = 'cmark.dll'
    else:
        libname = 'libcmark.so'
    if library_dir:
        libpath = os.path.join(library_dir, libname)
    else:
        libpath = os.path.join('build', 'src', libname)
    cmark = CDLL(libpath)
    markdown = cmark.cmark_markdown_to_html
    markdown.restype = c_char_p
    markdown.argtypes = c_char_p, c_long

    def to_html(text):
        textbytes = text.encode('utf-8')
        textlen = len(textbytes)
        return markdown(textbytes, textlen, 0).decode('utf-8')

    return to_html


class ExternalProgramError(Exception):

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


if __name__ == "__main__":
    if args.debug_normalization:
        out(normalize_html(sys.stdin.read()))
        exit(0)

    tests, skipped = select_tests(args.spec, args.pattern, args.number)

    if args.dump_tests:
        out(json.dumps(tests, ensure_ascii=False, indent=2))
        exit(0)
    else:
        if args.program:
            to_html = use_program(args.program)
        else:
            to_html = use_library(args.library_dir)
        result_counts = run_tests(to_html, tests, args.normalize)
        result_counts['skip'] = skipped
        out('{pass} passed, {fail} failed, {error} errored, {skip} skipped\n'
            .format(**result_counts))
        exit(result_counts['fail'] + result_counts['error'])
