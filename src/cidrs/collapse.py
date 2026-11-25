"""sec-cidr-collapse 的唯一实现文件。

网段统一表示为字典：

    {"network": "10.0.0.0", "prefix": 24, "version": 4}

network 是规范化地址字符串，prefix 是网络位数，version 是 4 或 6。
所有比较与归并都基于整数地址和位掩码，不使用字符串前缀，也不跨地址族
合并。
"""

from __future__ import annotations

import ipaddress

__all__ = [
    "parse_cidr",
    "normalize",
    "covers",
    "adjacent",
    "collapse",
    "sort_nets",
    "validate_list",
    "cidr_batch",
]

_MAX_PREFIX = {4: 32, 6: 128}
_ISSUE_ORDER = ("host_bits", "mixed_family", "prefix_out_of_range")


def _width_for(version: int) -> int:
    """返回地址族的总位数，非法族抛 ValueError。"""
    try:
        return _MAX_PREFIX[version]
    except KeyError as exc:
        raise ValueError("version must be 4 or 6") from exc


def _parse_address(value: object) -> ipaddress._BaseAddress:
    """把地址字符串解析为标准库地址对象。"""
    if not isinstance(value, str):
        raise ValueError("network must be a string")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def _parse_prefix_text(value: str) -> int:
    """严格解析斜杠后的十进制前缀，拒绝符号、空白和非数字。"""
    if not value or not all("0" <= char <= "9" for char in value):
        raise ValueError("prefix must be a non-negative integer")
    return int(value)


def _net_parts(net: dict) -> tuple[int, int, int, int]:
    """校验网段字典并返回 (version, 原始整数地址, prefix, 地址总位数)。"""
    if not isinstance(net, dict):
        raise ValueError("network entry must be a dict")

    try:
        network = net["network"]
        prefix = net["prefix"]
        version = net["version"]
    except KeyError as exc:
        raise ValueError(f"missing required key: {exc.args[0]}") from exc

    width = _width_for(version)

    if not isinstance(prefix, int) or isinstance(prefix, bool):
        raise ValueError("prefix must be an integer")
    if not 0 <= prefix <= width:
        raise ValueError("prefix is out of range")

    address = _parse_address(network)
    if address.version != version:
        raise ValueError("network address version does not match version")

    return version, int(address), prefix, width


def _normalized_parts(net: dict) -> tuple[int, int, int, int]:
    """返回主机位清零后的 (version, network_int, prefix, width)。"""
    version, raw_address, prefix, width = _net_parts(net)
    shift = width - prefix
    network_int = (raw_address >> shift) << shift
    return version, network_int, prefix, width


def _net_dict(version: int, network_int: int, prefix: int) -> dict:
    """由整数地址构造固定三键的规范网段字典。"""
    if version == 4:
        address = ipaddress.IPv4Address(network_int)
    else:
        address = ipaddress.IPv6Address(network_int)
    return {
        "network": str(address),
        "prefix": prefix,
        "version": version,
    }


def _covers_parts(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> bool:
    """对已规范化的内部四元组执行位级包含判断。"""
    left_version, left_addr, left_prefix, left_width = left
    right_version, right_addr, right_prefix, _ = right

    if left_version != right_version or left_prefix > right_prefix:
        return False

    # 比较 left_prefix 个最高位；前缀为 0 时同地址族必然包含。
    shift = left_width - left_prefix
    return (left_addr >> shift) == (right_addr >> shift)


def _adjacent_tuples(
    left: tuple[int, int, int],
    right: tuple[int, int, int],
) -> bool:
    """判断两个三元组网段是否为可合并的相邻兄弟网段。"""
    left_version, left_addr, left_prefix = left
    right_version, right_addr, right_prefix = right

    if (
        left_version != right_version
        or left_prefix != right_prefix
        or left_prefix == 0
    ):
        return False

    width = _width_for(left_version)
    block_size = 1 << (width - left_prefix)
    return (left_addr ^ right_addr) == block_size


def parse_cidr(text: str) -> dict:
    """解析 CIDR 文本或裸地址。

    - 接受 10.0.0.0/24、2001:db8::/32 以及不带斜杠的单个地址。
    - 不带斜杠时按满前缀处理：IPv4 为 32，IPv6 为 128。
    - 前缀按网络位数解释，必须在 0 到 32 或 0 到 128 的闭区间内。
    - 显式前缀时主机位必须为零；10.0.0.1/24 这类输入抛 ValueError，
      不得静默规范化。
    - 无法解析的地址、多个斜杠、空前缀、非数字前缀均抛 ValueError。

    返回字典的键固定为 network、prefix、version；network 使用标准库
    ipaddress 的规范字符串形式。
    """
    if not isinstance(text, str):
        raise ValueError("CIDR text must be a string")

    slash_count = text.count("/")
    if slash_count == 0:
        address = _parse_address(text)
        prefix = _MAX_PREFIX[address.version]
        return _net_dict(address.version, int(address), prefix)

    if slash_count != 1:
        raise ValueError("CIDR text must contain at most one slash")

    address_text, prefix_text = text.split("/", 1)
    prefix = _parse_prefix_text(prefix_text)
    address = _parse_address(address_text)
    version = address.version
    width = _MAX_PREFIX[version]

    if not 0 <= prefix <= width:
        raise ValueError("prefix is out of range")

    host_mask = (1 << (width - prefix)) - 1
    if int(address) & host_mask:
        raise ValueError("explicit prefix CIDR has non-zero host bits")

    return _net_dict(version, int(address), prefix)


def normalize(net: dict) -> dict:
    """返回主机位清零后的新网段字典。

    - 输入必须含 network、prefix、version 三个键，prefix 合法。
    - 仅清除主机位并规范化地址字符串，前缀长度与地址族保持不变。
    - 不原地修改输入。
    - 10.0.0.1/24 归一为 10.0.0.0/24，2001:db8::1/64 归一为
      2001:db8::/64。
    - 地址无法解析、地址族与 version 不一致或前缀越界时抛 ValueError。
    """
    version, network_int, prefix, _ = _normalized_parts(net)
    return _net_dict(version, network_int, prefix)


def covers(a: dict, b: dict) -> bool:
    """判断网段 a 是否完整包含网段 b，包含同网段。

    - 按网络地址的整数位比较，禁止字符串前缀比较。
    - 同族且 a 的前缀不长于 b、两者的公共前缀一致时返回 True。
    - 网络地址和广播地址都属于网段，因此边界地址必须判为包含。
    - 同网段返回 True。
    - 跨地址族返回 False，不抛异常。
    - 输入可带主机位，比较前按 normalize 的规则处理。
    """
    left = _normalized_parts(a)
    right = _normalized_parts(b)
    return _covers_parts(left, right)


def adjacent(a: dict, b: dict) -> bool:
    """判断两个同前缀网段是否可合并成前缀短一位的网段。

    - 地址族相同、前缀长度相同。
    - 两个网络地址只在共同前缀之后的最后一位不同，即异或结果恰好
      等于该前缀对应的块大小；其他高位必须完全一致。
    - 前缀 0 无法继续合并，返回 False。
    - 满前缀的两个单地址如果只差最后一位，可合并，例如 10.0.0.0/32
      与 10.0.0.1/32 合并为 10.0.0.0/31。
    - 跨族或前缀长度不同返回 False。
    """
    left_version, left_addr, left_prefix, _ = _normalized_parts(a)
    right_version, right_addr, right_prefix, _ = _normalized_parts(b)

    return _adjacent_tuples(
        (left_version, left_addr, left_prefix),
        (right_version, right_addr, right_prefix),
    )


def _remove_contained(nets: set[tuple[int, int, int]]) -> set[tuple[int, int, int]]:
    """删除被另一个不同网段包含的所有网段。"""
    items = list(nets)
    kept: set[tuple[int, int, int]] = set()

    for index, candidate in enumerate(items):
        candidate_parts = (
            candidate[0],
            candidate[1],
            candidate[2],
            _width_for(candidate[0]),
        )
        is_contained = False

        for other_index, other in enumerate(items):
            if index == other_index:
                continue
            other_parts = (
                other[0],
                other[1],
                other[2],
                _width_for(other[0]),
            )
            if _covers_parts(other_parts, candidate_parts):
                is_contained = True
                break

        if not is_contained:
            kept.add(candidate)

    return kept


def _merge_one_round(
    nets: set[tuple[int, int, int]],
) -> tuple[set[tuple[int, int, int]], bool]:
    """在每个相同前缀组内执行一轮相邻兄弟合并。"""
    groups: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
    for net in nets:
        version, _, prefix = net
        groups.setdefault((version, prefix), []).append(net)

    result: set[tuple[int, int, int]] = set()
    changed = False

    for (version, prefix), group in groups.items():
        group.sort(key=lambda item: item[1])
        index = 0

        while index < len(group):
            current = group[index]
            next_net = group[index + 1] if index + 1 < len(group) else None

            if next_net is not None and _adjacent_tuples(current, next_net):
                # 相邻兄弟只有边界位不同；按位与得到父网段地址。
                parent_addr = current[1] & next_net[1]
                result.add((version, parent_addr, prefix - 1))
                changed = True
                index += 2
            else:
                result.add(current)
                index += 1

    return result, changed


def collapse(nets: list) -> list:
    """把网段列表归并为最简列表。

    - 先规范化，再去除重复项与被包含项，然后合并相邻项。
    - 合并产生的更短前缀网段必须继续参与后续轮次，直到没有可合并项。
    - 输入中的重复项只保留一个；被包含项无论位置如何都删除。
    - 输出按网络地址数值升序、同址前缀升序排列。
    - 空列表返回空列表。
    - 混用 IPv4 与 IPv6 时抛 ValueError，不得跨族合并。
    - 返回新列表，不原地修改输入。
    """
    normalized = [_normalized_parts(net) for net in nets]
    families = {parts[0] for parts in normalized}
    if len(families) > 1:
        raise ValueError("IPv4 and IPv6 networks cannot be collapsed together")

    current = {(version, address, prefix) for version, address, prefix, _ in normalized}

    while True:
        current = _remove_contained(current)
        next_current, changed = _merge_one_round(current)
        if not changed:
            current = next_current
            break
        current = next_current

    ordered = sorted(current, key=lambda item: (item[0], item[1], item[2]))
    return [_net_dict(version, address, prefix) for version, address, prefix in ordered]


def _sort_key(net: dict) -> tuple[int, int, int]:
    """按地址族、整数网络地址和前缀长度生成排序键。"""
    version, network_int, prefix, _ = _normalized_parts(net)
    return version, network_int, prefix


def sort_nets(nets: list) -> list:
    """按网络地址数值升序返回新列表，同一地址按前缀升序。

    - 不得按字符串排序：10.0.2.0 必须排在 10.0.10.0 前面。
    - 同一网络地址的 /16 排在 /24 前面。
    - 混族时 IPv4 在前、IPv6 在后，族内仍按地址数值与前缀升序。
    - 不删除、不合并、不原地修改输入。
    """
    ordered = sorted(nets, key=_sort_key)
    return [dict(net) for net in ordered]


def _detect_family(net: object) -> int | None:
    """尽量识别条目地址族，供 validate_list 判断 mixed_family。"""
    if isinstance(net, dict):
        network = net.get("network")
        try:
            return _parse_address(network).version
        except ValueError:
            version = net.get("version")
            if version in _MAX_PREFIX:
                return version
    return None


def validate_list(nets: list) -> list[str]:
    """返回输入网段的问题码列表，没有问题时返回空列表。

    问题码固定为：

    - host_bits：存在前缀合法但主机位非零的网段；
    - mixed_family：同时存在 IPv4 与 IPv6 网段；
    - prefix_out_of_range：前缀不是合法整数或越界，地址无法解析。

    每个问题码最多出现一次，顺序固定为 host_bits、mixed_family、
    prefix_out_of_range。该函数只报告问题，不修改输入，也不负责归并。
    """
    issues: set[str] = set()
    families: set[int] = set()

    for net in nets:
        family = _detect_family(net)
        if family is not None:
            families.add(family)

        try:
            version, raw_address, prefix, width = _net_parts(net)
        except ValueError:
            issues.add("prefix_out_of_range")
            continue

        families.add(version)
        host_mask = (1 << (width - prefix)) - 1
        if raw_address & host_mask:
            issues.add("host_bits")

    if 4 in families and 6 in families:
        issues.add("mixed_family")

    return [code for code in _ISSUE_ORDER if code in issues]


def cidr_batch(lists: list, policy: str) -> dict:
    """批量归并多个网段列表，各列表完全独立。

    - 返回 {"policy": policy, "results": [...]}，policy 原样回显。
    - results 的第 i 项等于对 lists 的第 i 项单独调用 collapse 的结果。
    - 不得把前一个列表的网段、去重集合或中间结果带入后一个列表。
    - 空输入返回 results 为空列表；空子列表返回空列表。
    """
    # 每次列表推导都为每个子列表建立全新的局部集合，不存在共享累积状态。
    results = [collapse(net_list) for net_list in lists]
    return {"policy": policy, "results": results}
