meta:
  id: test_profile
  file-extension: bin
  endian: le
seq:
  - id: header
    type: header
  # Checked immediately beyond header.
  - id: regex_offsets
    type: regex_contents
    repeat: expr
    repeat-expr: header.regex_count
  # Afterwards, the variable offset table is skipped over.
  - id: variable_offsets
    type: variable_name
    repeat: expr
    repeat-expr: header.variable_count
  # Next, the variable state table.
  # TODO: confirm this is correct
  - id: variable_states
    type: offset
    repeat: expr
    repeat-expr: header.variable_state_count
  # Before we get to profiles, we need to handle
  # something involving instruction counts.
  # ---------
  # Notably, profile_init skip 0x17a during validation,
  # while collection_init skips 0x178 - perhaps that u16
  # is an offset to the profile's name, which goes unused
  # within standalone profiles.
  - id: instruction_table
    type: offset
    repeat: expr
    repeat-expr: header.instruction_count
  # Finally, raw profile operations!
  # Sweet man-made (...compiler-emitted?)
  # horrors beyond our imagination.
    # For individual profiles, their size
    # is the operation count times two.
    # The syscall mask is implied to be that of the header's.
  - id: profile
    type: individual_profile
    if: header.flags == header_flags::individual
    # For collection profiles, their size
    # is also the instruction count times two,
    # but their syscall mask is specified afterwards.
  - id: profiles
    type: collection_profile
    repeat: expr
    repeat-expr: header.profile_count
    if: header.flags == header_flags::collection
  # Per Ghidra, this should be like the following:
  #
  #   instr_offset = offset of instruction table
  #   profile_offset = offset past profile 0x174 in length
  #   padding = (instr_offset - (profile_offset & 6)) + 0x17a
  #
  # However, 0x17c - 0x174 is 8, so we can (8 - (profile_offset & 6)).
  - id: profile_padding
    size: 8 - (_io.pos & 6)
    if: (_io.pos & 6) != 0
  # After profile padding, this occurs.
  # It's not entirely clear on what this is - it may be
  # some sort of address table, given its size.
  # Perhaps we can assume it's related to raw operations.
  # I cannot find it referenced directly within the
  # "ProfileData" structure.
  - id: op_entry
    size: 8
    repeat: expr
    repeat-expr: header.op_entry
  # This additionally is unknown.
  # It comes immediately after op_entry.
  # Maybe it exists to confuse us...
  - id: unknown_3
    size: (0x800)
    repeat: expr
    repeat-expr: header.unknown_3
instances:
  string_table_offset:
    value: _io.pos
types:
  header:
    seq:
    # Seemingly only used to differentiate between
    # a collection (0x8000) and an individual profile (0x0000).
    # It's not clear on whether profiles can have a different first
    # byte or if this is a compiler optimization, but the
    # second byte must be zero.
    - id: flags
      type: u2
      enum: header_flags
    # Likely related to something with offsets.
    # 0x8 in length.
    - id: op_entry
      type: u1
    # This is 0x800 in length, for some godforsaken reason.
    - id: unknown_3
      type: u1
    # This varies by platform - observed values range
    # from 0xb6 (182) to 0xb9 (185).
    # This directly corresponds with the operation
    # table embedded elsewhere within Sandbox.kext,
    # and will be rejected if the count does not match.
    - id: operation_count
      type: u1
    # The amount of pattern variables, such as "PROCESS_TEMP_DIR",
    # "ANY_USER", or "ANY_USER_HOME".
    # Typically at the very end of a profile/collection.
    - id: variable_count
      type: u1
    # TOOD: How does this work?
    - id: variable_state_count
      type: u1
    # Unused, and should be zero.
    - id: unknown_7
      contents: [0x00]
    # Possibly also "policy count", per libsandbox on macOS.
    # This value is only referred to within collections -
    # within profile_init, its value is immediately set to 0.
    - id: profile_count
      type: u2
    # The amount of regexes within this bytecode format.
    - id: regex_count
      type: u2
    # The amount of instructions embedded within this
    # bytecode format.
    # TODO: What defines an instruction?
    - id: instruction_count
      type: u2
  # A generic u16 offset.
  # These should always reference data going forwards,
  # and should not exceed the file's length.
  # Typically, these offsets are within the "misc data"
  offset:
    seq:
      - id: offset
        type: u2

  # An individual profile, consisting only of operations.
  individual_profile:
    seq:
      - id: operations
        type: u2
        repeat: expr
        repeat-expr: _root.header.operation_count

  # A collection profile consists of operations, a name,
  # an index, and an indiviudual syscall mask.
  collection_profile:
    seq:
      - id: name_offset
        type: variable_name
      - id: syscall_mask
        type: u2
      - id: operations
        type: u2
        repeat: expr
        repeat-expr: _root.header.operation_count

  variable_name:
    seq:
      - id: string_offset
        type: u2
    instances:
      variable_name_offset:
        value: _root.string_table_offset + (string_offset * 8)
      variable_name:
        type: pascal_string
        pos: variable_name_offset

  regex_contents:
    seq:
      - id: regex_offset
        type: u2
    instances:
      regex_content_offset:
        value: _root.string_table_offset + (regex_offset * 8)
      regex_contents:
        type: sized_data
        pos: regex_content_offset

  # Permits for reading a pascal string:
  # a string prefixed with its length as a uint16_t.
  pascal_string:
    seq:
      - id: length
        type: u2
      - id: value
        type: strz
        encoding: ASCII
        size: length

  # Permits for reading data of a fixed length.
  sized_data:
    seq:
      - id: data_length
        type: u2
      - id: data
        size: data_length
enums:
  # Guessed flag values.
  header_flags:
    '0x0000': individual
    '0x8000': collection

