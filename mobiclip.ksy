meta:
  id: mobiclip
  file-extension: mo
  endian: le
seq:
  - id: magic
    contents: "MOC5"
  - id: header_size
    type: u4
    doc: "Add 8 for the actual header size."
  - id: header_chunks
    type: header_metadata
    size: header_size
  - id: av_chunks
    type: av_chunk
    repeat: expr
    repeat-expr: amount_of_chunks
instances:
  amount_of_chunks:
    value: header_chunks.contents.first.body.as<layout_metadata>.chunk_count
types:
  header_metadata:
    seq:
      - id: contents
        type: metadata
        repeat: eos
  metadata:
    seq:
      - id: marker
        type: str
        encoding: ascii
        size: 2
      - id: u32_length
        type: u2
        doc: Multiply this value by 4 to get the correct amount of bytes.
      - id: body
        if: u32_length != 0
        type:
          switch-on: marker
          cases:
            "'TL'": layout_metadata
            "'V2'": video_metadata
            "'pc'": rsa_data
            "'A2'": audio_chunk_standard
            "'A3'": audio_chunk_standard
            "'A9'": audio_chunk_standard
            "'AM'": audio_chunk_multitrack
            "'AP'": audio_chunk_standard
            "'AV'": audio_chunk_vorbis
            "'KI'": keyframe_index
            "'PÆ'": audio_chunk_standard
            "'cc'": cc_unknown
            "'HE'": header_end
        doc: |
          A0 -> None
          A2 -> FastAudio
          A3 -> FastAudio Stereo
          A8 -> ADPCM
          A9 -> ADPCM Stereo
          AM -> Multitrack
          AP -> PCM
          AV -> Vorbis
          KI -> Keyframe Index
          PÆ -> ???
          cc -> Seemingly goes unused.
  layout_metadata:
    seq:
      - id: fps
        type: u4
      - id: chunk_count
        type: u4
      - id: unknown_5
        type: u4
  video_metadata:
    seq:
      - id: width
        type: u4
      - id: height
        type: u4
  rsa_data:
    seq:
      - id: rsa_signature
        size: 160
        doc: "RSA-1280 with Barrett reduction."
  av_chunk:
    seq:
      - id: chunk_size
        type: u4
      - id: video_chunk_size
        type: u4
      - id: video_chunk
        size: video_chunk_size
      - id: audio_chunk
        if: chunk_size - video_chunk_size - 8 > 0
        size: chunk_size - video_chunk_size - 8
      - id: unknown
        if: chunk_size - video_chunk_size - 8 > 0
        size: (_io.pos + 4 - (_io.pos % 4)) - _io.pos
  audio_chunk_standard:
    seq:
      - id: frequency
        type: u4
      - id: channel_number
        type: u4
  audio_chunk_multitrack:
    seq:
      - id: audio_stream_count
        type: u4
      - id: audio_stream_features
        type: audio_chunk_standard
        repeat: expr
        repeat-expr: audio_stream_count
  audio_chunk_vorbis:
    seq:
      - id: header
        size: (_parent.u32_length * 4)
  keyframe_index:
    seq:
      - id: keyframes
        type: keyframe
        repeat: expr
        repeat-expr: (_parent.u32_length * 4) / 8
  keyframe:
    seq:
      - id: chunk_offset
        type: u4
      - id: frame_index
        type: u4
  cc_unknown:
    seq:
      - id: unknown
        size: 64
  header_end: {}