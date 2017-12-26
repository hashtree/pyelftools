#-------------------------------------------------------------------------------
# elftools example: elf_relocations.py
#
# An example of obtaining a relocation section from an ELF file and examining
# the relocation entries it contains.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import print_function
import sys

# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        # Read the .rela.dyn section from the file, by explicitly asking
        # ELFFile for this section
        # The section names are strings
        dynamic_name = '.dynamic'
        dynamic_sec = elffile.get_section_by_name(dynamic_name)

        if not isinstance(dynamic_sec, DynamicSection):
            print('  The file has no %s section' % dynamic_name)

        print('  %s section with %s dynamic items' % (
            dynamic_name, dynamic_sec.num_tags()))

        for dyn in dynamic_sec.iter_tags():
             print('    Dynamic (%s)' % dyn)
        #     # Relocation entry attributes are available through item lookup
        #     print('      offset = %s' % dyn['r_offset'])


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        for filename in sys.argv[2:]:
            process_file(filename)
