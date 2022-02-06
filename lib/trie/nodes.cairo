# const BLANK_NODE = 0 
# 
# const NODE_TYPE_BLANK = 1
# const NODE_TYPE_LEAF = 2
# const NODE_TYPE_EXTENSION = 3
# const NODE_TYPE_BRANCH = 4
# 
# struct Node:
#     member elements: felt*
#     member length: felt
# end
# 
# func decode_node(encoded_node_or_hash):
#     if encoded_node_or_hash == BLANK_NODE:
#         return BLANK_NODE
#     end
#     if encoded_node_or_hash_length > 0:
#         return encoded_node_or_hash
#     end
#     return rlp_decode(encoded_node_or_hash)
# end
# 
# func get_node_type(node : Node*) -> felt:
#     alloc_locals
#     if node.length == 0:
#         return NODE_TYPE_BLANK
#     end
#     if node.length == 2:
#         let (local key) = node.elements[0]
#         let (local nibbles) = decode_nibbles(key)
#         if is_nibbles_terminated(nibbles):
#             return NODE_TYPE_LEAF
#         else:
#             return NODE_TYPE_EXTENSION
#         end
#     end
#     if node.length == 17
#         return NODE_TYPE_BRANCH
#     end 
# end
# 
# func extract_key(node):
#     let prefixed_key = node.elements[0]
#     let key_ = decode_nibbles(prefixed_key)
#     let key = remove_nibbles_terminator(key_)
#     return (key)
# end
# 
# func get_common_prefix_length(left_key, right_key):
#     _get_common_prefix_length()
# end
# 
# func _get_common_prefix_length(
#     left_key : felt*,
#     right_key : felt*,
#     left_key_len: felt,
#     right_key_len: felt,
#     current_idx: felt):
# 
#     if i == left_key_len:
#         return (i)
#     end
#     if i == right_key_len:
#         return (i)
#     end
#     left_nibble = extract_nibble(left_key, i)
#     right_nibble = extract_nibble(right_key, i)
#     if left_nibble == right_nibble:
#         _get_common_prefix_length(
#             left_key,
#             right_key,
#             left_key_len,
#             right_key_len,
#             current_idx + 1)  
#     end
# end
# 
# func consume_common_prefix(left_key, right_key):
#     common_prefix_length = get_common_prefix_length(left_key, right_key)
#     common_prefix = slice(left_key, 0, common_prefix_length)
#     left_remainder = slice(left_key, common_prefix_length, left_key.length)
#     right_remainder = slice(right_key, common_prefix_length, right_key.length)
#     return (common_prefix, left_remainder, right_remainder)
# end
