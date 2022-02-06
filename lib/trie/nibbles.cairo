# from starkware.cairo.common.math import assert_le, unsigned_div_rem
# 
# NIBBLE_TERMINATOR = 16
# 
# func bytes_to_nibbles(bytes: felt*):
#     # TODO 
# end
# 
# func extract_nibble{ range_check_ptr }(array: IntArray, position: felt) -> (res: felt):
#     alloc_locals
#     elements = array.elements 
#     byte_length = array.byte_length
#     let (word_idx, nibble_idx) = unsigned_div_rem(position, 16)
#     let (word) = array.elements[word_idx]
#     return extract_nibble_word(word, nibble_idx)
# end
# 
# func extract_nibble_word{ range_check_ptr }(word: felt, position: felt) -> (res: felt):
#     alloc_locals
#     assert_le(position, 15)
#     let (shifted) = bitshift_right(word, 60 - position * 4)
#     let (_, nibble) = unsigned_div_rem(shifted, 0x10)
#     return (nibble)
# end
# 
# func encode_nibbles():
#     # TODO
# end
# 
# func decode_nibbles():
#     # TODO
# end
# 
# func is_nibbles_terminated(nibbles):
#     assert nibbles[nibbles.length] == NIBBLE_TERMINATOR
# end
