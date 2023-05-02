meta:
  # https://github.com/apple-oss-distributions/Security/blob/e4ea024c9bbd3bfda30ec6df270bfb4c7438d1a9/OSX/libsecurity_apple_file_dl/doc/FORMAT
  id: keychain_db
  file-extension: db
  endian: be
seq:
  # The header is 4 "Atoms".
  # An atom is a uint32_t.
  - id: header
    type: file_header
  - id: auth
    doc: The auth section is not utilized.
    type: auth_section
  - id: schema
    doc: The schema specifies offsets for all tables.
    type: schema_section
  # Note that we do not use the specifed offset for tables:
  # in practice they are written linearly, so we rely on that.
  # TODO: Can we respect offsets in some way or form?
  - id: meta_tables
    repeat: expr
    repeat-expr: schema.table_count
    type: meta_table

types:
  file_header:
    seq:
      - id: magic
        contents: ['k', 'y', 'c', 'h']
      - id: version
        doc: "There is only one version number: 0x00010000."
        contents: [0x00, 0x01, 0x00, 0x00]
      - id: auth_offset 
        type: u4
      - id: schema_offset
        type: u4
  auth_section:
    doc: This is not used - its length is set to zero, and its data similar.
    seq:
      - id: auth_size
        type: u4
      - id: auth_data
        size: auth_size
  schema_section:
    doc: The schema simply provides offsets to tables.
    seq:
      - id: section_size
        type: u4
      - id: table_count
        type: u4
      - id: raw_table_offsets
        doc: All raw table offsets are relative to the schema section's offset.
        type: u4
        repeat: expr
        repeat-expr: table_count
  meta_table:
    seq:
      - id: table_size
        type: u4
      - id: record_type
        doc: All records underneath this table utilize this type.
        type: u4
        enum: record_types
      - id: records_count
        type: u4
      - id: records_offset
        type: u4
      - id: indexes_offset
        type: u4
      - id: free_list_head
        type: u4
      - id: record_numbers_count
        doc: Rather, the start of where record numbers begin to go unused.
        type: u4
      # Some tables are empty.
      # We'll hardcode a single offset for empty tables.
      - id: record_offsets
        type: u4
        repeat: expr
        repeat-expr: records_count
        if: 'records_count > 0'
      - id: record_offset_padding
        if: 'records_count == 0'
        type: u4
      - id: records
        type: record(record_type)
        repeat: expr
        repeat-expr: records_count
      - id: index_section_size
        type: u4
      # TODO: Is this correct?
      - id: index_padding
        type: u4
      #   if: 'index_section_size <= 0x8'
      #   doc: If the index section size is 8, there is no index.
      # - id: index_section
      #   type: index_section
      #   if: 'index_section_size > 0x8'
  record:
    params:
      - id: record_type
        type: u4
        enum: record_types
    seq:
      - id: record_size
        type: u4
        doc: Aligned to 4 bytes.
      - id: record_index
        type: u4
      - id: creation_file_version
        type: u4
      - id: record_version
        type: u4
      - id: data_size
        type: u4
      - id: semantic_information
        type: u4
      # We can hackily glean the amount of attributes via the record type.
      # We then leverage the custom "arguments_offsets" type to allow
      # easily reading that amount of offsets.
      - id: attribute_offsets
        type:
          switch-on: record_type
          cases:
            ################
            # Schema types #
            ################
            'record_types::cssm_dl_db_schema_info': repeat_attribute_offsets(2)
            'record_types::cssm_dl_db_schema_indexes': repeat_attribute_offsets(5)
            'record_types::cssm_dl_db_schema_attributes': repeat_attribute_offsets(6)
            # This appears to go unused - we do not handle it.
            'record_types::cssm_dl_db_schema_parsing_module': repeat_attribute_offsets(1)
            
            #############
            # MDS types #
            #############
            'record_types::mds_object_recordtype': repeat_attribute_offsets(6)
      - id: record_data
        size: data_size

      # The size of an attribute should really be specified by
      # the record_size, but we will depend on it being correctly sized
      # with padding.
      - id: attributes
        type:
          switch-on: record_type
          cases:
            ################
            # Schema types #
            ################
            'record_types::cssm_dl_db_schema_info': cssm_dl_db_schema_info
            'record_types::cssm_dl_db_schema_indexes': cssm_dl_db_schema_indexes
            'record_types::cssm_dl_db_schema_attributes': cssm_dl_db_schema_attributes
            # cssm_dl_db_schema_parsing_module goes unused, so we do not handle it.
            
            #############
            # MDS types #
            #############
            'record_types::mds_object_recordtype': mds_object_recordtype
      - id: padding
        doc: Every record must be aligned to the 4 byte boundary.
        if: "_io.pos % 4 != 0"
        size: 4 - (_io.pos % 4)
  # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  # !!!!! This is not a real type !!!!!
  # This is a hack to work around the lack of reverse-enums with Kaitai Struct.
  # https://github.com/kaitai-io/kaitai_struct/issues/443#issuecomment-392324749
  # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  repeat_attribute_offsets:
    params:
      - id: offset_count
        type: u4
    seq:
      - id: offsets
        type: u4
        repeat: expr
        repeat-expr: offset_count
  
  #########
  # Index #
  #########
  # index_section:
  #   seq:
  #     # TODO: This is wrong, but I could not find any database
  #     # with indexes to observe what their values should be.
  #     - id: table_of_contents
  #       type: index_toc
  #       repeat: expr
  #       repeat-expr: _parent.records_count
  # index_toc:
  #   seq:
  #     - id: record_type
  #       type: u4
  #     - id: attribute_type
  #       type: u4
  #     - id: index_offset
  #       type: u4
  
  ###################
  # Attribute types #
  ###################
  attribute_string:
    seq:
      - id: string_size
        type: u4
      - id: value
        type: str
        size: string_size
        encoding: ascii
      - id: padding
        doc: Every string must be aligned to the 4 byte boundary.
        if: "_io.pos % 4 != 0"
        size: 4 - (_io.pos % 4)

  formatted_attribute:
    params:
      - id: format_type
        type: u4
        enum: attribute_formats
    seq:
      - id: formatted_string
        type:
          switch-on: format_type
          cases:
            attribute_formats::string: attribute_string
            attribute_formats::sint32: s4
            attribute_formats::uint32: u4

  formatted_name_attribute:
    params:
      - id: format_type
        type: u4
        enum: attribute_name_formats
    seq:
      - id: formatted_string
        type:
          switch-on: format_type
          cases:
            attribute_name_formats::string: attribute_string
            attribute_name_formats::integer: u4

  ################
  # Record types #
  ################
  cssm_dl_db_schema_info:
    doc: https://github.com/apple-oss-distributions/Security/blob/Security-60420.81.3/OSX/libsecurity_mds/lib/MDSSchema.cpp#L612-L616
    seq:
      - id: relation_id
        type: u4
      - id: relation_name
        type: attribute_string
  
  cssm_dl_db_schema_indexes:
    doc: https://github.com/apple-oss-distributions/Security/blob/Security-60420.81.3/OSX/libsecurity_mds/lib/MDSSchema.cpp#L640-L648
    seq:
      - id: relation_id
        type: u4
      - id: index_id
        type: u4
      - id: attribute_id
        type: u4
      - id: index_type
        type: u4
      - id: indexed_data_location
        type: u4
  
  cssm_dl_db_schema_attributes:
    doc: https://github.com/apple-oss-distributions/Security/blob/Security-60420.81.3/OSX/libsecurity_mds/lib/MDSSchema.cpp#L623-L632
    seq:
      - id: relation_id
        type: u4
      - id: attribute_id
        type: u4
      - id: attribute_name_format
        type: u4
        enum: attribute_name_formats
      - id: attribute_name
        type: formatted_name_attribute(attribute_name_format)
      # The "AttributeNameID" attribute, a BLOB, goes unused.
      - id: attribute_format
        type: u4
        enum: attribute_formats
  
  mds_object_recordtype:
    doc: https://github.com/apple-oss-distributions/Security/blob/Security-60420.81.3/OSX/libsecurity_mds/lib/MDSSchema.cpp#L45-L54
    seq:
      - id: module_id
        type: attribute_string
      # The "manifest" attribute, a BLOB, goes unused.
      - id: module_name
        type: attribute_string
      - id: path
        type: attribute_string
      - id: product_version
        type: attribute_string
      - id: built_in
        type: u4
enums:
  # We use lowercase notation to comply with Kaitai Struct convention.
  record_types:
    ###############################
    # Schema-related record types #
    ###############################
    # CSSM_DL_DB_SCHEMA_INFO
    0: cssm_dl_db_schema_info
    # CSSM_DL_DB_SCHEMA_INDEXES
    1: cssm_dl_db_schema_indexes
    # CSSM_DL_DB_SCHEMA_ATTRIBUTES
    2: cssm_dl_db_schema_attributes
    # CSSM_DL_DB_SCHEMA_PARSING_MODULE
    3: cssm_dl_db_schema_parsing_module
    
    ############################
    # MDS-related record types #
    ############################
    # MDS_OBJECT_RECORDTYPE
    0x40000000: mds_object_recordtype
  
  
  # https://github.com/apple-oss-distributions/RubyCocoa/blob/2ab869b1f886ce3b0cf2aa1ceb134339763782c6/RubyCocoa/sample/PassengerPane/Security.bridgesupport#L1190-L1198
  attribute_formats:
    0: string
    1: sint32
    2: uint32
    3: big_num
    4: real
    5: time_date
    6: blob
    7: multi_uint32
    8: complex
  
  # https://github.com/apple-oss-distributions/RubyCocoa/blob/2ab869b1f886ce3b0cf2aa1ceb134339763782c6/RubyCocoa/sample/PassengerPane/Security.bridgesupport#L1201-L1203
  attribute_name_formats:
    0: string
    1: oid
    2: integer
