meta:
  id: kwi
  file-extension: kwi
  endian: "be"
seq:
  - id: header_length
    type: u4
  - id: unknown
    type: u4
    doc: Checksum, possibly?
  - id: firmware_name
    type: pascal_string
  - id: firmware_package_count
    type: u4
  - id: firmware_packages
    type: firmware_package
    repeat: expr
    repeat-expr: firmware_package_count
  - id: rsa_key_probably
    size: 256
  - id: offsets
    type: offset_thing

types:
  ###############
  # Basic types #
  ###############
  pascal_string:
    seq:
      - id: str_length
        type: u4
      - id: contents
        type: str
        size: str_length
        encoding: ascii
        if: str_length > 1
        doc: Only present if the string's length is greater than 1.
  firmware_payload:
    seq:
      - id: payload_name
        type: pascal_string
      - id: payload_subsystem
        type: pascal_string
      - id: payload_type
        type: pascal_string
      - id: recurring_header_value
        type: u4
        doc: Observed to match the header's "unknown" value, or be zero.
      - id: payload_version
        type: pascal_string
        
  ##################
  # Firmware types #
  ##################
  
  # An overarching component of firmware.
  # Contains multiple packages.
  firmware_package:
    seq:
      - id: header_length
        type: u4
      - id: package_name
        type: pascal_string
      - id: package_type
        type: pascal_string
      - id: package_string
        type: pascal_string
      - id: unknown_two
        type: u4
        doc: value is 1
      - id: some_version_number
        type: u4
        doc: Observed to match for 19TD1NA-EAPA_1790. Other firmware has it as 0.
      # TODO: Continue
      - id: header_unknown_value
        type: u4
        doc: Matches previous `unknown` value.
      - id: data_offset
        type: u4
        doc: Offset to payload start within image.
      - id: release_headline_count
        type: u4
        doc: Possibly - please verify in firmware! Observed to be one.
      - id: release_headline
        type: pascal_string
        repeat: expr
        repeat-expr: release_headline_count
      # TODO: This does not appear within CY13 firmware.
      - id: release_description
        type: pascal_string
      - id: payload_count
        type: u4
      - id: payload_header_offsets
        type: u4
        repeat: expr
        repeat-expr: payload_count
        doc: Direct offset within the file to the per-payload header itself.
      - id: payloads
        type: firmware_payload
        repeat: expr
        repeat-expr: payload_count
  
  offset_thing:
    seq:
      - id: tag
        type: u4
      - id: value_length
        type: u2
      - id: aah
        type: u4

