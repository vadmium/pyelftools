#-------------------------------------------------------------------------------
# elftools tests
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os

from utils import setup_syspath; setup_syspath()
from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicTag, DynamicSegment
from elftools.elf.elffile import ELFFile


class TestDynamicTag(unittest.TestCase):
    def test_requires_stringtable(self):
        with self.assertRaises(ELFError):
            dt = DynamicTag('', None)

class TestDynamicSegment(unittest.TestCase):
    def test_segs_only(self):
        """ Make sure parsing only uses segments, not sections
        """
        # This file has DT_STRTAB pointing at
        # a different string table to
        # the string table referenced by the dynamic linking section
        path = os.path.join('test', 'testfiles_for_unittests',
            'lib_with_two_dynstr_sections_reversed.so.1.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg['p_type'] != 'PT_DYNAMIC':
                    continue
                
                (strtab,) = seg.iter_tags('DT_STRTAB')  # Load string table
                self.assertEqual(0x490, seg._stringtable._position)
                
                needed = seg.iter_tags('DT_NEEDED')
                needed = tuple(tag.needed for tag in needed)
                self.assertSequenceEqual((b'', b''), needed)
                
                (tag,) = seg.iter_tags('DT_SONAME')
                self.assertEqual(b'', tag.soname)


if __name__ == '__main__':
    unittest.main()
