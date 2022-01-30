func set_raw_node(raw_node):
end

func get_from_proof(root_hash : felt*, key : felt*, proof : IntArray*):
    alloc_locals
    let (local trie_key) = bytes_to_nibbles(key)
    let (local node, local remaining_key) = traverse(root_hash, trie_key)
    let (local node_type) = get_node_type(node)

    if node_type == NODE_TYPE_LEAF:
        let (local extracted_key) = extract_key(node)
        if remaining_key == extracted_key:
            let (local value) = node.elements[1]
            return value
        end
    end
    assert 1 = 0
end

func traverse(root_hash, trie_key):
    root_node = get_node(root_hash)
    let (node, remaining_key) = _traverse(root_hash, trie_key)
    assert remaining_key.length = 0
    return (node)
end

func _traverse(node, trie_key):
    alloc_locals
    let (local remaining_key) = trie_key
    if remaining_key_length == 0:
        return node

    let (local node_type) = get_node_type(node)
    if node_type == NODE_TYPE_LEAF:
        let (local leaf_key) = extract_key(node)
        if key_starts_with(leaf_key, remaining_key):
            return (node, remaining_key)
        else:
            return BLANK_NODE
        end
    end
    if node_type == NODE_TYPE_EXTENSION:
        let (next_node_pointer, remaining_key) = _traverse_extension(node, trie_key)
    end
    if node_type == NODE_TYPE_BRANCH:
        next_node_pointer = node[remaining_key[0]]
        remaining_key = remaining_key[1:]
    end
    node = self.get_node(next_node_pointer)
    _traverse(node, remaining_key)
end

func _traverse_extension(node, trie_key):
    let (local current_key) = extract_key(node)
    let (local common_prefix, 
         local current_key_remainder,
         local trie_key_remainer) = consume_common_prefix(current_key, trie_key)
    if current_key_remainer.length == 0:
        return node[1], trie_key_remainder
    end
end

func get_node(node_hash):
    if node_hash == BLANK_NODE:
        return BLANK_NODE
    end
    if node_hash == BLANK_NODE_HASH:
        return BLANK_NODE
    end
    if node_hash_length < 32:
        encoded_node = node_hash
    else:
        encoded_node = self.db[node_hash]
    end
    return decode_node(encoded_node)
end
