meta:
  id: known_met
  endian: le
seq:
  - id: magic
    size: 1
  - id: n_entries
    type: u4
  - id: entries
    type: entry
    repeat: expr
    repeat-expr: n_entries
enums:
  meta_tag_type:
    0x02: string
    0x03: integer
    0x04: float
    0x07: long_str
    0x08: uint16
    0x09: byte
    0x0b: uint64
types:
  entry:
    seq:
      - id: last_written
        type: u4
      - id: ed2k_hash
        size: 16
      - id: n_partial_hashes
        type: u2
      - id: partial_hashes
        type: partial_hash
        repeat: expr
        repeat-expr: n_partial_hashes
      - id: n_meta_tags
        type: u4
      - id: meta_tags
        type: meta_tag
        repeat: expr
        repeat-expr: n_meta_tags

  partial_hash:
    seq:
      - id: hash
        size: 16
  meta_tag:
    seq:
      - id: tag_type
        enum: meta_tag_type
        type: u1
      - id: name_length
        size: 2
      - id: tag_number
        type: u1
      - id: str_size
        type: u2
        if: tag_type == meta_tag_type::string
      - id: str_value
        type: str
        size: str_size
        encoding: UTF-8
        if: tag_type == meta_tag_type::string
      - id: int_value
        type: u4
        if: tag_type == meta_tag_type::integer
      - id: float_value
        type: f4le
        if: tag_type == meta_tag_type::float
      - id: long_str_size
        type: u4
        if: tag_type == meta_tag_type::long_str
      - id: long_str_value
        type: str
        size: long_str_size
        encoding: UTF-8
        if: tag_type == meta_tag_type::long_str
      - id: uint16_value
        type: u2
        if: tag_type == meta_tag_type::uint16
      - id: byte_value
        type: u1
        if: tag_type == meta_tag_type::byte
      - id: uint64_value
        type: u8
        if: tag_type == meta_tag_type::uint64

        
