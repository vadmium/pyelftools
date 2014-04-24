#-------------------------------------------------------------------------------
# elftools: elf/dynamic.py
#
# ELF Dynamic Tags
#
# Mike Frysinger (vapier@gentoo.org)
# This code is in the public domain
#-------------------------------------------------------------------------------
import itertools
from collections import defaultdict

from .sections import Section
from .segments import Segment
from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from .strings import StringTable


class DynamicTag(object):
    """ Dynamic Tag object - representing a single dynamic tag entry from a
        dynamic section.

        Allows dictionary-like access to the dynamic structure. For special
        tags (those listed in the _HANDLED_TAGS set below), creates additional
        attributes for convenience. For example, .soname will contain the actual
        value of DT_SONAME (fetched from the dynamic symbol table).
    """
    _HANDLED_TAGS = frozenset(
        ['DT_NEEDED', 'DT_RPATH', 'DT_RUNPATH', 'DT_SONAME',
         'DT_SUNW_FILTER'])

    def __init__(self, entry, stringtable):
        if stringtable is None:
            raise ELFError('Creating DynamicTag without string table')
        self.entry = entry
        if entry.d_tag in self._HANDLED_TAGS:
            setattr(self, entry.d_tag[3:].lower(),
                    stringtable.get_string(self.entry.d_val))

    def __getitem__(self, name):
        """ Implement dict-like access to entries
        """
        return self.entry[name]

    def __repr__(self):
        return '<DynamicTag (%s): %r>' % (self.entry.d_tag, self.entry)

    def __str__(self):
        if self.entry.d_tag in self._HANDLED_TAGS:
            s = '"%s"' % getattr(self, self.entry.d_tag[3:].lower())
        else:
            s = '%#x' % self.entry.d_ptr
        return '<DynamicTag (%s) %s>' % (self.entry.d_tag, s)


class Dynamic(object):
    """ Shared functionality between dynamic sections and segments.
    """
    def __init__(self, stream, elffile, stringtable=None, position=None):
        if position is None:
            raise TypeError('"position" argument is required')
        
        self._stream = stream
        self._elffile = elffile
        self._elfstructs = elffile.structs
        self._entries = None  # Loaded on demand
        self._offset = position
        self._tagsize = self._elfstructs.Elf_Dyn.sizeof()
        
        # Determined after loading entries if not provided
        self._stringtable = stringtable

    def iter_tags(self, type=None):
        """ Yield all tags in arbitrary order (limit to |type| if specified)
        """
        self._load_entries()
        if type is None:
            entries = self._entries
        else:
            entries = self._entry_type_map.get(type, ())
        for entry in entries:
            yield DynamicTag(entry, self._stringtable)

    def get_tag(self, n):
        """ Get the tag at index #n from the file (DynamicTag object)
        """
        self._load_entries()
        return DynamicTag(self._entries[n], self._stringtable)

    def num_tags(self):
        """ Number of dynamic tags in the file
        """
        self._load_entries()
        return len(self._entries)
    
    def _load_entries(self):
        """ Prepare entry lists and string table if necessary
        """
        if self._entries is not None:  # Already loaded
            return
        
        self._entries = list()
        self._entry_type_map = defaultdict(list)  # Entry lists by tag type
        for n in itertools.count():
            offset = self._offset + n * self._tagsize
            entry = struct_parse(
                self._elfstructs.Elf_Dyn,
                self._stream,
                stream_pos=offset)
            self._entries.append(entry)
            self._entry_type_map[entry.d_tag].append(entry)
            if entry.d_tag == 'DT_NULL':
                break
        self._entry_type_map.default_factory = None
        
        if self._stringtable is not None:  # Already provided
            return
        
        (strtab,) = self._entry_type_map['DT_STRTAB']
        strsz = self._entry_type_map.get('DT_STRSZ')
        if strsz:
            (strsz,) = strsz
            strsz = strsz.d_val
        
        strtab = self._elffile.map(strtab.d_ptr, strsz)
        self._stringtable = StringTable(self._stream, strtab, strsz)


class DynamicSection(Section, Dynamic):
    """ ELF dynamic table section.  Knows how to process the list of tags.
    """
    def __init__(self, header, name, stream, elffile):
        Section.__init__(self, header, name, stream)
        stringtable = elffile.get_section(header['sh_link'])
        Dynamic.__init__(self, stream, elffile, stringtable, self['sh_offset'])


class DynamicSegment(Segment, Dynamic):
    """ ELF dynamic table segment.  Knows how to process the list of tags.
    """
    def __init__(self, header, stream, elffile):
        Segment.__init__(self, header, stream)
        Dynamic.__init__(self, stream, elffile, position=self['p_offset'])
