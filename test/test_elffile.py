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

from utils import setup_syspath; setup_syspath()
from elftools.elf.elffile import ELFFile

class TestMap(unittest.TestCase):
    def runTest(self):
        class MockELF(ELFFile):
            __init__ = object.__init__
            def iter_segments(self):
                return iter((
                    dict(p_vaddr=0x10200, p_filesz=0x200, p_offset=0x100),
                    dict(p_vaddr=0x10100, p_filesz=0x100, p_offset=0x400),
                ))
        
        elf = MockELF()
        
        self.assertEqual(elf.map(0x10100), 0x400)
        self.assertEqual(elf.map(0x10120), 0x420)
        self.assertEqual(elf.map(0x101FF), 0x4FF)
        self.assertEqual(elf.map(0x10200), 0x100)
        self.assertRaises(LookupError, elf.map, 0x100FF)
        self.assertRaises(LookupError, elf.map, 0x10400)
        
        self.assertEqual(elf.map(0x10100, 0x100), 0x400)
        self.assertEqual(elf.map(0x10100, 4), 0x400)
        self.assertEqual(elf.map(0x10120, 4), 0x420)
        self.assertEqual(elf.map(0x101FC, 4), 0x4FC)
        self.assertEqual(elf.map(0x10200, 4), 0x100)
        self.assertRaises(LookupError, elf.map, 0x10100, 0x200)
        self.assertRaises(LookupError, elf.map, 0x10000, 0x800)
        self.assertRaises(LookupError, elf.map, 0x100FC, 4)
        self.assertRaises(LookupError, elf.map, 0x100FE, 4)
        self.assertRaises(LookupError, elf.map, 0x101FE, 4)
        self.assertRaises(LookupError, elf.map, 0x103FE, 4)
        self.assertRaises(LookupError, elf.map, 0x10400, 4)


if __name__ == '__main__':
    unittest.main()
