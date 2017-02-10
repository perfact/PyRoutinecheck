#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# generic.py  -  Generic utilities
#
# $Revision: 1.4 $
#
# Copyright (C) 2015 Jan Jockusch <jan.jockusch@perfact.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# $Id: generic.py,v 1.4 2015/10/24 13:58:16 perfact Exp $

# For html_quote
import cgi
# For literal parsing:
import ast
import operator
# For encryption and salting:
import sha
import binascii
import base64
import os
import random
# For unique logger IDs
import uuid

# Other useful imports may include:
# url_quote urlencode url_query restructured_text


def html_quote(v):
    '''Smaller implementation of Products.PythonScripts.standard.html_quote
    But: This one takes only one string parameter.
    '''
    return cgi.escape(v, 1)


def html_unquote(v):
    '''Unquote quoted HTML text.'''
    tokens = [
        ('&lt;', '<',),
        ('&gt;', '>',),
        ('&quot;', '"',),
        ('&amp;', '&',),
    ]
    for before, after in tokens:
        v = v.replace(before, after)
    return v


def obj_hash(val):
    '''Build a hash value from a pickleable object.'''
    ser = flatten_dictionaries(val)
    # Clumsy but repeatable string representation. Perhaps we can
    # "pickle" to get something better...
    if type(ser) in (type(''), type(u'')):
        string_representation = str((ser,))[1:-2]
    else:
        string_representation = str(ser)
    return sha.sha(string_representation).hexdigest()


def flatten_dictionaries(val):
    '''Convert all dictionaries in this object to sorted items
    lists.'''

    # Do this depth first, so you can replace the objects whenever
    # possible.
    if type(val) == type({}):
        items = val.items()
        items.sort()
        for key, value in items:
            # Recursion happens here
            value = flatten_dictionaries(value)
        # Replace the dictionary
        return items
    # Everything that's not a dictionary stays the same.
    return val


def safe_eval(value, **kw):
    '''Use the expression evaluator from PageTemplates anywhere!

    This method is largely deprecated because we have a better parser
    from the "ast" module.
    '''
    if kw:
        raise AssertionError("Keyword arguments unsupported")

    return literal_eval(value)

    # Old Zope based version with keyword arguments.
    #
    # import Products.PageTemplates
    # e = Products.PageTemplates.Expressions.getEngine()
    # expr = e.compile(value)
    # return expr(e.getContext(**kw))


def literal_eval(value):
    '''Literal evaluator (with a bit more power than PT).

    This evaluator is capable of parsing large data sets, and it has
    basic arithmetic operators included.
    '''
    _safe_names = {'None': None, 'True': True, 'False': False}
    if isinstance(value, basestring):
        value = ast.parse(value, mode='eval')

    bin_ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.div,
        ast.Mod: operator.mod,
    }

    def _convert(node):
        if isinstance(node, ast.Expression):
            return _convert(node.body)
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Tuple):
            return tuple(map(_convert, node.elts))
        elif isinstance(node, ast.List):
            return list(map(_convert, node.elts))
        elif isinstance(node, ast.Dict):
            return dict((_convert(k), _convert(v)) for k, v
                        in zip(node.keys, node.values))
        elif isinstance(node, ast.Name):
            if node.id in _safe_names:
                return _safe_names[node.id]
        elif isinstance(node, ast.BinOp):
            return bin_ops[type(node.op)](_convert(node.left), _convert(node.right))
        else:
            raise Exception('Unsupported type {}'.format(dir(node)))
    return _convert(value)


def same_type(a, b):
    '''Provide a replacement for the missing "type" functionality in
    PythonScripts.
    '''
    return type(a) == type(b)


def get_type(a):
    '''String representation of a's type.
    '''
    ret = str(type(a))
    if ret.startswith("<type '"):
        ret = ret[7:-2]
    return ret

# Deprecated method encrypt_pw. Replaced by secret_encrypt()


def encrypt_pw(password):
    '''This method is used to store encrypted passwords in the external
    user database instead of cleartext.

    Code is cited from AuthEncryption.py in Zope.
    '''
    if password[:5] == '{SHA}':
        return password
    return '{SHA}' + binascii.b2a_base64(sha.new(password).digest())[:-1]


def base64decode(value):
    return binascii.a2b_base64(value)


def base64encode(value):
    return binascii.b2a_base64(value)


# Additional functions for safer login methods:
# SHA and SSHA encryption for cookies and passwords
# os.urandom wrapper for cookie generation
# base64 wrappers
def secret_encrypt(secret, salt=None):
    '''This function performs SHA or seeded SHA encryption according to
    RFC 2307 and returns the according string for storage in a
    database.  Set salt = True to generate standard salt.
    '''
    enc = sha.new(secret)
    if salt:
        salt_string = os.urandom(4)
        enc.update(salt_string)
        return '{SSHA}' + base64.encodestring(enc.digest() + salt_string).strip()
    return '{SHA}' + base64.encodestring(enc.digest()).strip()


def secret_check(encrypted, secret):
    '''Check a secret against its encrypted form.
    '''
    encoded = encrypted[encrypted.find('}') + 1:]
    challenge_bytes = base64.urlsafe_b64decode(encoded)
    digest = challenge_bytes[:20]
    hr = sha.new(secret)
    if len(challenge_bytes) > 20:
        salt = challenge_bytes[20:]
        hr.update(salt)
    return digest == hr.digest()


def generate_random_string(length=32, mode='normal'):
    '''Generate a random string good enough for encryption purposes.
    '''
    if mode not in ('normal', 'digits'):
        raise ValueError, "invalid mode chosen: " + str(mode)

    if mode == 'normal':
        binary = os.urandom(length)
        ascii = base64.encodestring(binary)
        # Make this string URL safe:
        safestring = ascii.replace('+', '-').replace('/', '_')
        return safestring[:length]
    if mode == 'digits':
        packet_size = 3
        out = ''
        packets = length / packet_size
        remainder = length % packet_size
        fmt = '%%0%dd' % packet_size
        for i in range(packets):
            out += fmt % random.randrange(0, 10 ** packet_size)
        if remainder:
            out += fmt % random.randrange(0, 10 ** remainder)
        return out


def get_uuid4():
    return str(uuid.uuid4())

# Alternative implementation for older systems:
# def get_uuid4():
#    return os.popen('uuid -v 4', 'r').read().strip()


# Residing in zLayout:
def to_ustring(value, enc='utf-8'):
    if type(value) == type(u''):
        return value
    if type(value) == type(''):
        return value.decode(enc, 'ignore')

    try:
        return u'' + str(value)
    except:
        pass
    raise ValueError("could not convert '%s' to ustring!" % str((value,)))


def to_string(value, enc='utf-8'):
    if type(value) == type(''):
        return value
    if type(value) == type(u''):
        return value.encode(enc)

    try:
        return str(value)
    except:
        pass
    raise ValueError("could not convert '%s' to string!" % str((value,)))


def to_cssclassname(value):
    '''ensure a valid css class name'''
    valid_firstchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
    valid_chars = valid_firstchars + "0123456789"

    if not value:
        return ''

    # Prepend with _ if the first character is invalid
    if value[0] not in valid_firstchars:
        value = '_' + value

    # Dump invalid characters
    out = ''
    for char in value:
        if char in valid_chars:
            out += char

    return out


# Diffing
def conserv_split(val, splitby='\n'):
    '''Split by a character, conserving it in the result.'''
    output = map(lambda a: a + splitby, val.split(splitby))
    output[-1] = output[-1][:-len(splitby)]
    if output[-1] == '':
        output.pop()
    return output


def token_split(val):
    '''Split into groups of alpha, space and other chars.'''
    val = to_ustring(val)
    tokens = []
    cat = ''
    token = u''

    def iskind(v, group):
        for c in v:
            if c not in group:
                return False
        return True

    def getcat(v):
        if v.isalpha():
            return 'alnum'
        if v.isdigit():
            return 'alnum'
        if v.isspace():
            return 'space'
        if iskind(v, '.,;:'):
            return 'punct'
        return 'other'

    while val:
        char = val[0]
        val = val[1:]

        # Category change?
        c_cat = getcat(char)
        if token and cat != c_cat:
            # Different category
            tokens.append(token)
            token = ''

        # Same or new category:
        token += char
        cat = c_cat

    if token:
        tokens.append(token)

    return tokens


def diff_lines(a=None, b=None, use_tokens=False, max_range=10, test__=None):
    '''Compare two texts by splitting into lines and comparing those.
    Return in the form of blocks with "before", "oldtext", and "newtext" entries.
    '''
    if test__ == '1':
        a = 'Line1\nLine2\nLine3.'
        b = 'Line1\nLine1a\nLine2\nLine3change.'

    if a is None:
        a = ''
    if b is None:
        b = ''

    a = to_ustring(a)
    b = to_ustring(b)

    if use_tokens:
        lines_a = token_split(a)
        lines_b = token_split(b)
    else:
        lines_a = conserv_split(a)
        lines_b = conserv_split(b)

    blocks = []
    sametext = []
    oldtext = []
    newtext = []

    while lines_a or lines_b:

        l_a = lines_a and lines_a[0] or None
        l_b = lines_b and lines_b[0] or None

        if l_a is not None and l_b is not None and l_a == l_b:
            # Match found. Close the former block
            if newtext or oldtext:
                blocks.append({
                    'before': ''.join(sametext),
                    'oldtext': ''.join(oldtext),
                    'newtext': ''.join(newtext),
                })
                sametext = []
                oldtext = []
                newtext = []

            sametext.append(l_a)
            lines_a.pop(0)
            lines_b.pop(0)
            continue

        # Not same: search in both directions
        try:
            ind_a = lines_a.index(l_b)
        except:
            ind_a = None
        try:
            ind_b = lines_b.index(l_a)
        except:
            ind_b = None

        # Enforce maximum range
        if max_range:
            if ind_a > max_range:
                ind_a = None
            if ind_b > max_range:
                ind_b = None

        # No match? The line simply differs
        if ind_a is None and ind_b is None:
            if l_a:
                oldtext.append(l_a)
                lines_a.pop(0)
            if l_b:
                newtext.append(l_b)
                lines_b.pop(0)
            continue

        # Choose the smaller index

        if ind_a is None or (ind_a is not None and
                             ind_b is not None and ind_b <= ind_a):
            # Hit found as ind_b in lines_b for l_a, thus we ignore l_a,
            # and append all lines_b up to the index to the newtext
            newtext.extend(lines_b[:ind_b])
            lines_b = lines_b[ind_b:]
            # Next line will close the block, because it is the same.
            continue

        if ind_b is None or (ind_a is not None and
                             ind_b is not None and ind_a < ind_b):
            # Hit found as ind_a in lines_a for l_b, thus we ignore l_b,
            # and append all lines_a up to the index to the oldtext
            oldtext.extend(lines_a[:ind_a])
            lines_a = lines_a[ind_a:]
            # Next line will close the block, because it is the same.
            continue

        raise ValueError("This should never happen: " + str((ind_a, ind_b, l_a, l_b)))

    if sametext or newtext or oldtext:
        blocks.append({
            'before': ''.join(sametext),
            'oldtext': ''.join(oldtext),
            'newtext': ''.join(newtext),
        })

    if test__:
        out = []
        for b in blocks:
            out.append(b + '\n')
        return ''.join(out)

    return blocks


def diff_words(a=None, b=None, test__=None):
    '''Compare texts word for word, marking differences.
    Return a list of data structures for easy interactive patching.
    '''
    if test__ == '1':
        a = 'Das Schiff liegt nicht auf Reede, aussbooten mit alten Zodiacs.'
        b = 'Hinweis: Das Schiff liegt auf Reede, ausbooten mit guten alten Zodiacs. Zusatz.'

    if a is None:
        a = ''
    if b is None:
        b = ''

    def pos_split(val):
        # Split retaining the position information
        out = []
        coll = ''
        pos = None
        for i in range(len(val)):
            c = val[i]
            if c.isspace():
                if coll:
                    out.append((pos, i, coll))
                    coll = ''
                    pos = None
                continue
            coll += c
            if pos is None:
                pos = i
        if coll:
            out.append((pos, len(val), coll))
        return out

    ta = pos_split(a)
    tb = pos_split(b)

    print_output = []

    if test__:
        print_output.append("Tokenizations:" + '\n')
        print_output.append(str(ta) + '\n')
        print_output.append(str(tb) + '\n')
        print_output.append('\n')

    ia = 0
    ib = 0
    blocks = []
    while True:
        if len(ta) <= ia:
            # rest of text has been added
            new = tb[ib:]
            blocks.append({'type': 'change',
                           'old': [(len(a), len(a), '')],
                           'new': tb[ib:]})
            break
        if len(tb) <= ib:
            # rest of text has been removed
            blocks.append({'type': 'change',
                           'old': ta[ia:],
                           'new': [(len(b), len(b), '')]})
            break

        if ta[ia][2] == tb[ib][2]:
            # in sync.
            ia += 1
            ib += 1
            continue

        # out of sync. search for next equal
        ra = len(ta) - ia
        rb = len(tb) - ib
        radius = (ra < rb) and ra or rb
        c = False
        for r in range(1, radius):
            for rr in range(0, r + 1):
                if ta[ia + r][2] == tb[ib + rr][2]:
                    # words have been removed
                    old = ta[ia:ia + r]
                    new = tb[ib:ib + rr]
                    if not new:
                        new = [(tb[ib][0], (tb[ib][0] or 1) - 1, '')]
                        if tb[ib][0] == 0:
                            old[-1] = (old[-1][0], old[-1][1] + 1, old[-1][2] + ' ')
                    blocks.append({'type': 'change',
                                   'old': old,
                                   'new': new})  # XXX
                    ia += r
                    ib += rr
                    c = True
                    break
                if ta[ia + rr][2] == tb[ib + r][2]:
                    # words have been added
                    old = ta[ia:ia + rr]
                    new = tb[ib:ib + r]
                    if not old:
                        old = [(ta[ia][0], (ta[ia][0] or 1) - 1, '')]
                        if ta[ia][0] == 0:
                            new[-1] = (new[-1][0], new[-1][1] + 1, new[-1][2] + ' ')
                    blocks.append({'type': 'change',
                                   'old': old,
                                   'new': new})
                    ia += rr
                    ib += r
                    c = True
                    break
            if c:
                break
        if c:
            continue

        # end of text differs
        blocks.append({'type': 'change',
                       'old': ta[ia:],
                       'new': tb[ib:]})
        break

    if test__:
        print_output.append("Blocks:" + '\n')
        for block in blocks:
            print_output.append(str(block) + '\n')
        print_output.append('\n')

    # Highlight changes
    out = ''
    pos = 0
    for block in blocks:
        if block['type'] == 'change':
            block['change'] = True
            old, new = block['old'], block['new']
            if old and len(old):
                block['oldtext'] = a[old[0][0]:old[-1][1]]
            else:
                block['oldtext'] = ''

            if new and len(new):
                block['newtext'] = b[new[0][0]:new[-1][1]]
            else:
                block['newtext'] = ''

            block['repl_from'] = old[0][0] + 1
            block['repl_for'] = old[-1][1] - old[0][0]

            if new and len(new):
                block['before'] = b[pos:new[0][0]]
                pos = new[-1][1]
            else:
                block['before'] = ''

    tail = b[pos:]
    if tail:
        blocks.append({'type': 'tail', 'before': tail, 'change': False, })

    if not test__:
        return blocks

    # Debugging info:

    print_output.append("Original texts:" + '\n')
    print_output.append(a + '\n')
    print_output.append(b + '\n')
    print_output.append('\n')

    print_output.append("Formatting hints:" + '\n')
    for block in blocks:
        print_output.append('\n')
        print_output.append("Before: " + block['before'] + '\n')
        print_output.append("Type: " + block['type'] + '\n')
        if block['type'] == 'change':
            print_output.append('"%(oldtext)s" -> "%(newtext)s"' % block + '\n')
            print_output.append("From %(repl_from)d for %(repl_for)d" % block + '\n')
        # print_output.append( str(block) + '\n')
    return ''.join(print_output)


def safe_syscall(cmds, raisemode=False):
    '''Send a command and return both the return code and the output.  If
    used as a compatibility replacement for os.system(), pass
    "raisemode=True", which will mean that you don't get the return
    code, but instead an error.
    '''
    # Split command into list for safer parsing.
    if type(cmds) == type(''):
        cmds = cmds.split()

    import subprocess
    try:
        output = subprocess.check_output(cmds, stderr=subprocess.STDOUT)
        retcode = 0
    except subprocess.CalledProcessError, e:
        retcode = e.returncode
        output = e.output

    if raisemode and retcode:
        raise AssertionError("safe_syscall returned %s on %s" % (retcode, cmds))

    return retcode, output


# --- Generic, but Zope-specific
def read_pdata(obj):
    '''Avoid authentication problems when reading linked pdata.'''
    if type(obj.data) == type(''):
        source = obj.data
    else:
        data = obj.data
        source = ''
        while data is not None:
            source += data.data
            data = data.next
    return source


def get_property_or_method(context, name, acquire=True):
    '''Locate the given property or method. Acquisition can optionally be
    turned off.'''

    if acquire:
        value = getattr(context, name, None)
    else:
        value = context.getProperty(name, None)
        if value is None:
            # Test if object is locally defined
            localobj = getattr(context.aq_explicit, name, None)
            if localobj:
                # Re-read the object with acquisition.
                value = getattr(context, name, None)

    if callable(value):
        value = value()
    return value
