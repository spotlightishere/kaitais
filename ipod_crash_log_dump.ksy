meta:
  id: ipod_crash_log_dump
  file-extension: bin
  endian: le
  encoding: ascii
  
####################
# Base file format #
####################
seq:
  - id: magic
    contents: [0x73, 0x7B, 0xBE, 0x30, 0xDF, 0x5C, 0xE5, 0x48, 0x92, 0x9A, 0x5D, 0xD1, 0x50, 0x2A, 0xC7, 0x57]
  - id: unknown_one
    type: u2
  # Possibly the amount of exception types this crash handler is aware of?
  - id: unknown_two
    type: u2
  - id: section_count
    type: u4
  - id: sections
    type: section
    repeat: expr 
    repeat-expr: section_count

enums:
  # Simply for readability.
  # A lot of these names are guesses - please change as needed!
  section_types:
    # 'fwvr'
    0x66777672: firmware_version
    # 'fwrv', shown as the build ID.
    0x66766572: firmware_revision
    # 'bldt', "SCM".
    0x626c6474: build_type
    # 'bldp'
    0x626c6470: build_checkout
    # 'p4cl', the changelist ID.
    # This is hardcoded to 0x000494a9 in 1.0.2,
    # equal to CL300201 within its longer version string.
    0x7034636c: p4cl
    # 'udfm', hardcoded to 0x25.
    0x7564666d: udfm
    # 'upid', reading at 0x04 and 0x08 from 0x3d100000 (CHIP_ID).
    # See the `package_id` type for more information.
    0x75706964: package_id
    # 'lmsg', the exception message for this crash.
    # This can be an ARM exception, a C++ exception, etc.
    0x6C6d7367: exception_message
    # 'addr', the address involved in the fault/exception/etc.
    # In the case of a data abort, this is the read/written address.
    0x61646472: fault_address
    # 'fapc', the PC of the faulting code.
    0x66617063: faulting_pc
    # 'htsk', "halting task" possibly?
    # This seems to correspond to the ID of the task faulting.
    0x6874736b: htsk
    # 'fasp', the previous stack pointer.
    0x66617370: fault_stack_pointer
    # 'fpsr', the register(?)
    0x66707372: fpsr
    # 'etyp', the exception type.
    0x65747970: exception_type
    # 'freg', the register contents at time of exception.
    0x66726567: fault_registers
    # 'fsr '
    0x66737220: fsr
    # 'far '
    0x66617220: far
    # 'fstk'
    0x6673746b: fstk
    # 'stk2'
    0x73746B32: stk2
    # 'mstk'
    0x6D73746B: mstk
    # 'lock'
    0x6C6F636B: locks
    # 'sema'
    0x73656D61: semaphores
    # 'task'
    0x7461736B: tasks
    # 'heap'
    0x68656170: heap
    # 'evlg'
    0x65766c67: evlg
types:
  ##################
  # Section format #
  ##################
  # Refer to the enum below for further information about all enum types.
  section:
    seq:
      - id: section_magic
        type: u4
        enum: section_types
      # TODO(spotlightishere): Possibly entry count instead of length?
      # All values on 7th generation iPod nanos are 1.
      - id: length_length
        type: u4
      - id: data_length
        type: u4
      - id: contents
        size: data_length
        # Permits readability of section data.
        type:
          switch-on: section_magic
          cases:
            # String types. Note that we default to ASCII within our `meta`.
            'section_types::firmware_version': str
            'section_types::firmware_revision': str
            'section_types::build_type': str
            'section_types::build_checkout': str
            'section_types::exception_message': str
            # Four byte-width integer types.
            'section_types::p4cl': u4
            'section_types::udfm': u4
            'section_types::fault_address': u4
            'section_types::faulting_pc': u4
            'section_types::fault_stack_pointer': u4
            'section_types::exception_type': u4
            # Custom types.
            'section_types::package_id': package_id
            'section_types::tasks': tasks
            'section_types::fault_registers': register_state
            # TODO(spotlightishere): What are these?
            'section_types::htsk': u4
            'section_types::fpsr': u4

  # Specifically at two offsets:
  # - 0x04: information about revision, stepping, etc.
  # - 0x08: the chip's model alongside security fusing.
  # Refer to the `TestChipId` DXE driver within diags.
  # Alternatively: https://theapplewiki.com/wiki/S5L8720/Hardware#CHIPID
  # (This might not be right.)
  package_id:
    seq:
      # 0x3d100004
      # e.g. 0x8740
      - id: unknown_fields
        type: b22
      - id: revision_character
        type: b6
      - id: revision_level
        type: b4
      
      # 0x3d100008
      - id: security_fusing
        type: u2
      - id: chip_id
        type: u2

  tasks:
    seq:
      - id: task_count
        type: u4
      - id: task_entries
        type: task_entry
        repeat: expr
        repeat-expr: task_count

  task_entry:
    seq:
      - id: task_id
        type: u4
        doc: Incremental, though not sequential.
      - id: xd
        type: u4
      # Possibly flags?
      - id: aaa
        type: u4
      - id: adsffadsfds
        type: strz
        size: 20

  register_state:
    seq:
      - id: r0
        type: u4
      - id: r1
        type: u4
      - id: r2
        type: u4
      - id: r3
        type: u4
      - id: r4
        type: u4
      - id: r5
        type: u4
      - id: r6
        type: u4
      - id: r7
        type: u4
      - id: r8
        type: u4
      - id: r9
        type: u4
      - id: r10
        type: u4
      - id: r11
        type: u4
      - id: r12
        type: u4
      - id: r13
        doc: a.k.a. Stack pointer
        type: u4
