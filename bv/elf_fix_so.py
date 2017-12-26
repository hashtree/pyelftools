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
import struct


# If pyelftools is not installed, the example can also run from the root or
# examples/ dir of the source distribution.
sys.path[0:0] = ['.', '..']

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection


def update_sh(elf, secname, key, val):
    obj = elf.get_section_by_name(secname)
    print("  0x{:0>8x} --> 0x{:0>8x} @ [{}][{}]".format(obj[key], val, secname, key))
    obj[key] = val
    elf.set_section_header(secname, obj)


def update_sh_for_dynamic(srcelf):
    secname = '.dynamic'
    dynsec = srcelf.get_section_by_name(secname)

    if not isinstance(dynsec, DynamicSection):
        print('  The file has no {} section'.format(secname))

    for dyn in dynsec.iter_tags():
        if dyn["d_tag"] == "DT_PLTRELSZ":
            update_sh(srcelf, ".rel.plt", "sh_size", dyn["d_val"])
        elif dyn["d_tag"] == "DT_JMPREL":
            update_sh(srcelf, ".rel.plt", "sh_offset", dyn["d_val"])
        elif dyn["d_tag"] == "DT_SYMTAB":
            update_sh(srcelf, ".dynsym", "sh_offset", dyn["d_val"])
        elif dyn["d_tag"] == "DT_STRTAB":
            update_sh(srcelf, ".dynstr", "sh_offset", dyn["d_val"])
        elif dyn["d_tag"] == "DT_STRSZ":
            update_sh(srcelf, ".dynstr", "sh_size", dyn["d_val"])
        elif dyn["d_tag"] == "DT_FINI_ARRAY":
            update_sh(srcelf, ".fini_array", "sh_offset", dyn["d_val"])
        elif dyn["d_tag"] == "DT_FINI_ARRAYSZ":
            update_sh(srcelf, ".fini_array", "sh_size", dyn["d_val"])
        elif dyn["d_tag"] == "DT_INIT_ARRAY":
            update_sh(srcelf, ".init_array", "sh_offset", dyn["d_val"])
        elif dyn["d_tag"] == "DT_INIT_ARRAYSZ":
            update_sh(srcelf, ".init_array", "sh_size", dyn["d_val"])


def move_section(srcelf, dsth, secname):
    # copy section to dump(dst) file
    sec = srcelf.get_section_by_name(secname)
    dsth.seek(0, 2)
    dsth.write(sec.data())
    offset = dsth.tell() - sec.data_size

    # update section header in file
    update_sh(srcelf, secname, 'sh_offset', offset)


def move_section_header(srcelf, dsth):
    # copy section headers to dump(dst) file
    shoff = srcelf['e_shoff']
    shsize = srcelf['e_shnum'] * srcelf['e_shentsize']
    srcelf.stream.seek(shoff)
    sh = srcelf.stream.read(shsize)
    dsth.seek(0, 2)
    dsth.write(sh)

    # update shoff in eh
    shoff = dsth.tell() - shsize
    dsth.seek(0x20)  # sh ptr addr
    dsth.write(struct.pack("<I", shoff))


def check_sh(srcelf, dsth):
    whitelist = [".bss", ".shstrtab"]
    dsth.seek(0, 2)
    max = dsth.tell()
    for nsec, sec in enumerate(srcelf.iter_sections()):
        if sec.name in whitelist or (sec["sh_offset"] < max and sec["sh_offset"]+sec["sh_size"] < max):
            continue
        else:
            print("  invalid section: [offset]0x{:0>8x} [size]0x{:0>8x} {}".format(
                  sec["sh_offset"],
                  sec["sh_size"],
                  sec.name))
            sec["sh_offset"] = 0
            sec["sh_size"] = 0
            srcelf.set_section_header(sec.name, sec)


def process_file(src, dst):
    print('Processing file: {0} -> {1}'.format(src, dst))
    with open(src, 'rb+') as srch:
        with open(dst, 'rb+') as dsth:
            srcelf = ELFFile(srch)
            move_section(srcelf, dsth, '.ARM.attributes')
            move_section(srcelf, dsth, '.shstrtab')
            update_sh_for_dynamic(srcelf)
            check_sh(srcelf, dsth)
            move_section_header(srcelf, dsth)

            dstelf = ELFFile(dsth)

    # print(dstelf)


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        process_file(sys.argv[2], sys.argv[3])
