pub const MAXPAGESIZE: u64 = 0x1000;

pub const DEFAULT_SCHEME: LayoutScheme<'static> = LayoutScheme {
    entry: "_start",
    segments: &[
        SegmentScheme {
            name: "text-segment",
            start: AddrScheme::Absolute(0x400000),
            alignment: MAXPAGESIZE,
            sections: &[OutSectScheme {
                name: ".text",
                inpsects: &[".text", ".text.*"],
                outsect_type: OutSectType::ProgBits,
            }],
        },
        SegmentScheme {
            name: "rodata-segment",
            start: AddrScheme::CurrentLocation,
            alignment: MAXPAGESIZE,
            sections: &[OutSectScheme {
                name: ".rodata",
                inpsects: &[".rodata", ".rodata.*"],
                outsect_type: OutSectType::ProgBits,
            }],
        },
        SegmentScheme {
            name: "data-segment",
            start: AddrScheme::CurrentLocation,
            alignment: MAXPAGESIZE,
            sections: &[
                OutSectScheme {
                    name: ".data",
                    inpsects: &[".data", ".data.*"],
                    outsect_type: OutSectType::ProgBits,
                },
                OutSectScheme {
                    name: ".bss",
                    inpsects: &[".bss", ".bss.*"],
                    outsect_type: OutSectType::NoBits,
                },
            ],
        },
    ],
};

/* The DEFAULT_SCHEME object constant corresponds to the following linker script. (Note: This is
 * not enough to link any serious project, but enough to carry us forward. Write a runtime
 * converter of a linker scripts to the LayoutScheme).
 *
 * ENTRY(_start)
 * SECTIONS
 * {
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("text-segment", 0x400000);
 *   .text : { *(.text .text.*) }
 *
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("rodata-segment", .);
 *   .rodata : { *(.rodata .rodata.*) }
 *
 *   . = ALIGN(CONSTANT (MAXPAGESIZE));
 *   . = SEGMENT_START("data-segment", .);
 *   .data : { *(.data .data.*) }
 *   .bss : { *(.bss .bss.*) }
 * }
 *
 */

type FileIndex = u16;
type SegmentIndex = u16;

#[derive(Debug)]
pub enum AddrScheme {
    CurrentLocation,
    Absolute(u64),
}

#[derive(Debug)]
pub enum OutSectType {
    NoBits, /* no file-backed */
    ProgBits, /* file-backed */
}

#[derive(Debug)]
pub struct OutSectScheme<'a> {
    pub name: &'a str,
    pub inpsects: &'a [&'a str],
    pub outsect_type: OutSectType,
}

#[derive(Debug)]
pub struct SegmentScheme<'a> {
    name: &'a str,         /* Segment name */
    pub start: AddrScheme, /* Starting address of segment */
    pub alignment: u64,    /* Segment alignment (in bytes) */
    pub sections: &'a [OutSectScheme<'a>],
}

#[derive(Debug)]
pub struct LayoutScheme<'a> {
    entry: &'a str,
    pub segments: &'a [SegmentScheme<'a>],
}

impl<'a> LayoutScheme<'a> {
    pub fn segment_iter(&self) -> impl Iterator<Item = &SegmentScheme<'a>> {
        self.segments.iter()
    }

    pub fn outsect_iter(&self) -> impl Iterator<Item = &OutSectScheme<'a>> {
        self.segment_iter()
            .flat_map(|segment| segment.sections.iter())
    }
}
