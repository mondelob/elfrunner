/* elf_header_32.rs defines the 32-bit ELF header
 * Copyright (C) 2019  Bruno Mondelo Giaramita

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

struct ELFHeader32 {
    e_ident :ELFIdent,        /* 0x00: ident */
    e_type :u16,              /* 0x10: specifies the object file type */
    e_machine :u16,           /* 0x12: specifies the target set architecture */
    e_version :u32,           /* 0x14: flag set for the original ELF version */
    e_entry :u32,             /* 0x18: memory address of the entry point */
    e_phoff :u32,             /* 0x1c: points to the program header table */
    e_shoff :u32,             /* 0x20: points to the start of the section header
                                 table */
    e_flags :u32,             /* 0x24: architecture dependant flags */
    e_shsize :u16,            /* 0x28: size of this header */
    e_phentsize :u16,         /* 0x2a: size of the program header table */
    e_phnum :u16,             /* 0x2c: entries in the program header table */
    e_shentsize :u16,         /* 0x2e: zie of a program header table entry */
    e_shnum :u16,             /* 0x30: entries in the section header table */
    e_shstrndx :u16           /* 0x32: index of the section header table
                                 containing section names */
}
/* Structure to define the 32-bit ELF header */

fn parse_elf_header(buf :&[u8; 54]) -> ELFHeader32 {
    let mut ident: [u8; 16] = Default::default();
    ident.copy_from_slice(&buf[0x00..0x10]);
    let e_ident = parse_elf_ident(&ident);

    let mut e_type :u16 = Default::default();
    let mut e_machine :u16 = Default::default();
    let mut e_version :u32 = Default::default();
    let mut e_entry :u32 = Default::default();
    let mut e_phoff :u32 = Default::default();
    let mut e_shoff :u32 = Default::default();
    let mut e_flags :u32 = Default::default();
    let mut e_shsize :u16 = Default::default();
    let mut e_phentsize :u16 = Default::default();
    let mut e_phnum :u16 = Default::default();
    let mut e_shentsize :u16 = Default::default();
    let mut e_shnum :u16 = Default::default();
    let mut e_shstrndx :u16 = Default::default();

    if e_ident.ei_data == EI_DATA_LITTLE {
        e_type = LittleEndian::read_u16(&buf[0x10..0x12]);
        e_machine = LittleEndian::read_u16(&buf[0x12..0x14]);
        e_version = LittleEndian::read_u32(&buf[0x14..0x18]);
        e_entry = LittleEndian::read_u32(&buf[0x18..0x1c]);
        e_phoff = LittleEndian::read_u32(&buf[0x1c..0x20]);
        e_shoff = LittleEndian::read_u32(&buf[0x20..0x24]);
        e_flags = LittleEndian::read_u32(&buf[0x24..0x28]);
        e_shsize = LittleEndian::read_u16(&buf[0x28..0x2a]);
        e_phentsize = LittleEndian::read_u16(&buf[0x2a..0x2c]);
        e_phnum = LittleEndian::read_u16(&buf[0x2c..0x2e]);
        e_shentsize = LittleEndian::read_u16(&buf[0x2e..0x30]);
        e_shnum = LittleEndian::read_u16(&buf[0x30..0x32]);
        e_shstrndx = LittleEndian::read_u16(&buf[0x32..0x34]);
    }
    else if e_ident.ei_data == EI_DATA_BIG {
        e_type = BigEndian::read_u16(&buf[0x10..0x12]);
        e_machine = BigEndian::read_u16(&buf[0x12..0x14]);
        e_version = BigEndian::read_u32(&buf[0x14..0x18]);
        e_entry = BigEndian::read_u32(&buf[0x18..0x1c]);
        e_phoff = BigEndian::read_u32(&buf[0x1c..0x20]);
        e_shoff = BigEndian::read_u32(&buf[0x20..0x24]);
        e_flags = BigEndian::read_u32(&buf[0x24..0x28]);
        e_shsize = BigEndian::read_u16(&buf[0x28..0x2a]);
        e_phentsize = BigEndian::read_u16(&buf[0x2a..0x2c]);
        e_phnum = BigEndian::read_u16(&buf[0x2c..0x2e]);
        e_shentsize = BigEndian::read_u16(&buf[0x2e..0x30]);
        e_shnum = BigEndian::read_u16(&buf[0x30..0x32]);
        e_shstrndx = BigEndian::read_u16(&buf[0x32..0x34]);
    }

    ELFHeader32 {
        e_ident: e_ident,
        e_type: e_type,
        e_machine: e_machine,
        e_version: e_version,
        e_entry: e_entry,
        e_phoff: e_phoff,
        e_shoff: e_shoff,
        e_flags: e_flags,
        e_shsize: e_shsize,
        e_phentsize: e_phentsize,
        e_phnum: e_phnum,
        e_shentsize: e_shentsize,
        e_shnum: e_shnum,
        e_shstrndx: e_shstrndx
    }
}
/* Parses a 54-byte buffer into a 32-bit ELFHeader */

fn read_elf_header(file :&mut File) -> Option<ELFHeader32> {
    let ident = match read_elf_ident(file) {
        None => return None,
        Some(i) => i,
    };

    if ident.ei_class != EI_CLASS_32 {
        return None;
    }

    let mut buf = [0u8; 54];

    if let Err(_) = file.seek(SeekFrom::Start(0)) {
        return None;
    }

    if let Err(_) = file.read_exact(&mut buf) {
        return None;
    }

    let header = parse_elf_header(&buf);

    Some(header)
}
/* Reads the ELF header from file */

impl fmt::Display for ELFHeader32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "e_ident: {{{}}}; ", self.e_ident);

        let _ = write!(f, "e_type: 0x{:02x}; ", self.e_type);
        /* Add match */

        let _ = write!(f, "e_machine: 0x{:02x}; ", self.e_machine);
        /* Add match */

        let _ = write!(f, "e_version: 0x{:02x}; ", self.e_version);

        let _ = write!(f, "e_entry: 0x{:02x}; ", self.e_entry);

        let _ = write!(f, "e_phoff: 0x{:02x}; ", self.e_phoff);

        let _ = write!(f, "e_shoff: 0x{:02x}; ", self.e_shoff);

        let _ = write!(f, "e_flags: 0x{:02x}; ", self.e_flags);

        let _ = write!(f, "e_shsize: 0x{:02x}; ", self.e_shsize);

        let _ = write!(f, "e_phentsize: 0x{:02x}; ", self.e_phentsize);

        let _ = write!(f, "e_phnum: 0x{:02x}; ", self.e_phnum);

        let _ = write!(f, "e_shentsize: 0x{:02x}; ", self.e_shentsize);

        let _ = write!(f, "e_shnum: 0x{:02x}; ", self.e_shnum);

        write!(f, "e_shstrndx: 0x{:02x}", self.e_shstrndx)
    }
}
/* Implementation of format to show 32-bit header */
