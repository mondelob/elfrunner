/* elf_ident.rs defines the structure of an ELF ident section
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

use std::fs::File;
use std::fmt;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

const EI_CLASS_32 :u8 = 0x01;
/* ELF ident 32-bit format */

const EI_CLASS_64 :u8 = 0x02;
/* ELF ident 64-bit format */

const EI_DATA_LITTLE :u8 = 0x01;
/* ELF ident little endian */

const EI_DATA_BIG :u8 = 0x02;
/* ELF ident big endian */

const EI_OSABI_SYSTEM_V :u8 = 0x00;
/* ELF ident System V OS */

const EI_OSABI_HP_UX :u8 = 0x01;
/* ELF ident HP-UX OS */

const EI_OSABI_NETBSD :u8 = 0x02;
/* ELF ident NetBSD OS */

const EI_OSABI_LINUX :u8 = 0x03;
/* ELF ident Linux OS */

const EI_OSABI_GNU_HURD :u8 = 0x04;
/* ELF ident GNU Hurd OS */

/* Where is 0x05? */

const EI_OSABI_SOLARIS :u8 = 0x06;
/* ELF ident Solaris OS */

const EI_OSABI_AIX :u8 = 0x07;
/* ELF ident AIX OS */

const EI_OSABI_IRIX :u8 = 0x08;
/* ELF ident IRIX OS */

const EI_OSABI_FREEBSD :u8 = 0x09;
/* ELF ident FreeBSD OS */

const EI_OSABI_TRU64 :u8 = 0x0a;
/* ELF ident Tru64 OS */

const EI_OSABI_NOVELL_MODESTO :u8 = 0x0b;
/* ELF ident Novell Modesto OS */

const EI_OSABI_OPENBSD :u8 = 0x0c;
/* ELF ident OpenBSD OS */

const EI_OSABI_OPENVMS :u8 = 0x0d;
/* ELF ident OpenVMS OS */

const EI_OSABI_NONSTOP_KERNEL :u8 = 0x0e;
/* ELF ident NonStop Kernel OS */

const EI_OSABI_AROS :u8 = 0x0f;
/* ELF ident AROS OS */

const EI_OSABI_FENIX_OS :u8 = 0x10;
/* ELF ident Fenix OS OS */

const EI_OSABI_CLOUDABI :u8 = 0x11;
/* ELF ident CloudABI OS */

struct ELFIdent {
    ei_mag0 :u8,              /* 0x00: magic number 0: 0x7f*/
    ei_mag1 :u8,              /* 0x01: magic number 1: 0x45 (E) */
    ei_mag2 :u8,              /* 0x02: magic number 2: 0x4c (L) */
    ei_mag3 :u8,              /* 0x03: magic number 2: 0x46 (F) */
    ei_class :u8,             /* 0x04: set to define 32-bit or 64-bit format */
    ei_data :u8,              /* 0x05: set to define the endianness */
    ei_version :u8,           /* 0x06: flag set to the current version of ELF */
    ei_osabi :u8,             /* 0x07: set to indetify the target OS */
    ei_abiversion :u8,        /* 0x08: specifies the ABI version */
    _ei_padding :[u8; 7]      /* 0x09: padding unused */
}
/* Structure to define the ELF Ident */

fn parse_elf_ident(buf :&[u8; 16]) -> ELFIdent {
    ELFIdent {
        ei_mag0: buf[0],
        ei_mag1: buf[1],
        ei_mag2: buf[2],
        ei_mag3: buf[3],
        ei_class: buf[4],
        ei_data: buf[5],
        ei_version: buf[6],
        ei_osabi: buf[7],
        ei_abiversion: buf[8],
        _ei_padding: [0; 7]
    }
}
/* Parses a 16-byte buffer into am ELFIdent */

fn check_elf_ident(ident :&ELFIdent) -> bool {
    if ident.ei_mag0 != 0x7f || ident.ei_mag1 != 0x45 ||
        ident.ei_mag2 != 0x4c || ident.ei_mag3 != 0x46 ||
        (ident.ei_class != EI_CLASS_32 && ident.ei_class != EI_CLASS_64) ||
        (ident.ei_data != EI_DATA_LITTLE && ident.ei_data != EI_DATA_BIG) ||
        (ident.ei_osabi != EI_OSABI_SYSTEM_V &&
        ident.ei_osabi != EI_OSABI_HP_UX && ident.ei_osabi != EI_OSABI_NETBSD &&
        ident.ei_osabi != EI_OSABI_LINUX &&
        ident.ei_osabi != EI_OSABI_GNU_HURD &&
        ident.ei_osabi != EI_OSABI_SOLARIS && ident.ei_osabi != EI_OSABI_AIX &&
        ident.ei_osabi != EI_OSABI_IRIX && ident.ei_osabi != EI_OSABI_FREEBSD &&
        ident.ei_osabi != EI_OSABI_TRU64 &&
        ident.ei_osabi != EI_OSABI_NOVELL_MODESTO &&
        ident.ei_osabi != EI_OSABI_OPENBSD &&
        ident.ei_osabi != EI_OSABI_OPENVMS &&
        ident.ei_osabi != EI_OSABI_NONSTOP_KERNEL &&
        ident.ei_osabi != EI_OSABI_AROS &&
        ident.ei_osabi != EI_OSABI_FENIX_OS &&
        ident.ei_osabi != EI_OSABI_CLOUDABI) {
        return false;
    }

    true
}
/* Checks an ELFIdent */

fn read_elf_ident(file :&mut File) -> Option<ELFIdent> {
    let mut buf = [0u8; 16];

    if let Err(_) = file.seek(SeekFrom::Start(0)) {
        return None;
    }
    
    if let Err(_) = file.read_exact(&mut buf) {
        return None;
    }

    let ident = parse_elf_ident(&buf);

    if !check_elf_ident(&ident) {
        return None;
    }

    Some(ident)
}
/* Reads the ELF ident from file */

impl fmt::Display for ELFIdent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "ei_mag: 0x{0:02x} 0x{1:02x} 0x{2:02x} 0x{3:02x}; ",
            self.ei_mag0, self.ei_mag1, self.ei_mag2, self.ei_mag3);
        
        let _ = write!(f, "ei_class: 0x{0:02x} ", self.ei_class);
        let _ = match self.ei_class {
            EI_CLASS_32 => write!(f, "32 bits; "),
            EI_CLASS_64 => write!(f, "64 bits; "),
            _ => write!(f, "unknown; "),
        };

        let _ = write!(f, "ei_data: 0x{0:02x} ", self.ei_data);
        let _ = match self.ei_data {
            EI_DATA_LITTLE => write!(f, "little endian; "),
            EI_DATA_BIG => write!(f, "bif endian; "),
            _ => write!(f, "unknown; "),
        };

        let _ = write!(f, "ei_version: 0x{:02x}; ", self.ei_version);

        let _ = write!(f, "ei_osabi: 0x{0:02x} ", self.ei_osabi);
        let _ = match self.ei_osabi {
            EI_OSABI_SYSTEM_V  => write!(f, "System V; "),
            EI_OSABI_HP_UX  => write!(f, "HP-UX; "),
            EI_OSABI_NETBSD  => write!(f, "NetBSD; "),
            EI_OSABI_LINUX  => write!(f, "Linux; "),
            EI_OSABI_GNU_HURD  => write!(f, "GNU Hurd; "),
            EI_OSABI_SOLARIS  => write!(f, "Solaris; "),
            EI_OSABI_AIX  => write!(f, "AIX; "),
            EI_OSABI_IRIX  => write!(f, "IRIX; "),
            EI_OSABI_FREEBSD  => write!(f, "FreeBSD; "),
            EI_OSABI_TRU64  => write!(f, "Tru64; "),
            EI_OSABI_NOVELL_MODESTO  => write!(f, "Novell Modesto; "),
            EI_OSABI_OPENBSD  => write!(f, "OpenBSD; "),
            EI_OSABI_OPENVMS  => write!(f, "OpenVMS; "),
            EI_OSABI_NONSTOP_KERNEL  => write!(f, "NonStop Kernel; "),
            EI_OSABI_AROS  => write!(f, "AROS; "),
            EI_OSABI_FENIX_OS  => write!(f, "Fenix OS; "),
            EI_OSABI_CLOUDABI  => write!(f, "CloudABI; "),
            _ => write!(f, "unknown; "),
        };

        write!(f, "ei_abiversion: 0x{:02x}", self.ei_abiversion)
    }
}
/* Implementation of format to show ident */
