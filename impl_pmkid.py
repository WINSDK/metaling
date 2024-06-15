import hashlib
import string

def generate_pmkid(pmk, mac_ap, mac_sta):
    msg = b"PMK Name" + mac_ap + mac_sta
    pmkid = hmac_sha1_128(pmk, msg)
    return pmkid

def hmac_sha1_128(key, msg):
    block_size = 64
    ipad = bytes((x ^ 0x36) for x in range(64))
    opad = bytes((x ^ 0x5C) for x in range(64))

    if len(key) > block_size:
        key = hashlib.sha1(key).digest()
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')

    inner_pad = bytes(a ^ b for a, b in zip(ipad, key))
    outer_pad = bytes(a ^ b for a, b in zip(opad, key))

    inner_hash = hashlib.sha1(inner_pad + msg).digest()
    print(f"inner_hash: {inner_hash.hex()}")
    outer_hash = hashlib.sha1(outer_pad + inner_hash).digest()

    return outer_hash

def mac_to_bytes(mac):
    return bytes.fromhex(mac.replace(':', ''))

def generate_permutations(chars, len, prefix=b""):
    if len == 0:
        yield prefix
    else:
        for char in chars:
            new_prefix = prefix + bytes([char])
            yield from generate_permutations(chars, len - 1, new_prefix)

def generate_rand_pmks(max_len):
    perms = string.ascii_letters + string.digits + string.punctuation
    perms = perms.encode("ascii")
    len = 1

    while len <= max_len:
        yield from generate_permutations(perms, len)
        len += 1

if __name__ == "__main__":
    mac_ap = mac_to_bytes('00:11:22:33:44:55')
    mac_sta = mac_to_bytes('66:77:88:99:AA:BB')

    target = generate_pmkid(b"lol", mac_ap, mac_sta)
    print(f"outer_hash: {target.hex()}")
    exit(0)

    for pmk in generate_rand_pmks(4):
        pmkid = generate_pmkid(pmk, mac_ap, mac_sta)

        if pmkid == target:
            print(f"passphrase is: {pmk.decode('ascii')} ({pmkid.hex()})")
            break
