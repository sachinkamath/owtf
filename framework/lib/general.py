#!/usr/bin/env python
"""
Declare the helper functions for the framework.
"""

from collections import defaultdict
import os
import re
import base64
import errno


def cprint(message):
    pad = "[-] "
    print pad + str(message).replace("\n", "\n" + pad)
    return message


def multiple_replace(text, replace_dict):
    """
    Perform multiple replacements in one go using the replace dictionary
    in format: { 'search' : 'replace' }
    """
    new_text = text
    for search, replace in replace_dict.items():
        new_text = new_text.replace(search, str(replace))
    return new_text


def check_pid(pid):
    """Check whether pid exists in the current process table.
    UNIX only.
    """
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True


def wipe_bad_char_filename(filename):
    return multiple_replace(filename, {'(': '', ' ': '_', ')': '', '/': '_'})


def remove_list_blanks(src):
    return [el for el in src if el]


def list_to_dict_keys(list):
    dictionary = defaultdict(list)
    for item in list:
        dictionary[item] = ''
    return dictionary


def add_to_dict(from_dict, to_dict):
    for key, value in from_dict.items():
        if hasattr(value, 'copy') and callable(getattr(value, 'copy')):
            to_dict[key] = value.copy()
        else:
            to_dict[key] = value


def merge_dicts(dict1, dict2):
    """
    Returns a by-value copy contained the merged content of the 2 passed
    dictionaries
    """
    new_dict = defaultdict(list)
    add_to_dict(dict1, new_dict)
    add_to_dict(dict2, new_dict)
    return new_dict


def trunk_line(str, num_lines, EOL="\n"):
    return EOL.join(str.split(EOL)[0:num_lines])


def derive_http_method(method, data):  # Derives the HTTP method from Data, etc
    d_method = method
    # Method not provided: Determine method from params
    if d_method is None or d_method == '':
        d_method = 'GET'
        if data != '' and data is not None:
            d_method = 'POST'
    return d_method


def get_random_str(length):
    """function returns random strings of length len"""
    return base64.urlsafe_b64encode(os.urandom(length))[0:length]


def scrub_output(output):
    """remove all ANSI control sequences from the output"""
    ansi_escape = re.compile(r'\x1b[^m]*m')
    return ansi_escape.sub('', output)


def get_file_as_list(filename):
    try:
        with open(filename, 'r') as f:
            output = f.read().split("\n")
            cprint("Loaded file: %s" % filename)
    except IOError, error:
        log("Cannot open file: %s (%s)" % (filename, str(sys.exc_info())))
        output = []
    return output


def paths_exist(PathList):
    valid_paths = True
    for path in path_list:
        if path and not os.path.exists(path):
            log("WARNING: The path %s does not exist!" % path)
            valid_paths = False
    return valid_paths
