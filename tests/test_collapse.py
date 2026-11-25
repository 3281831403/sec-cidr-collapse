"""sec-cidr-collapse 的验收测试。

测试离线、确定性：不联网、不使用随机数、不依赖系统时钟。
只使用标准库与 pytest。当前 8 个实现函数均为桩，预期恰好 15 failed，
且每条失败都应是 NotImplementedError。
"""

import pytest

from cidrs.collapse import (
    adjacent,
    cidr_batch,
    collapse,
    covers,
    normalize,
    parse_cidr,
    sort_nets,
    validate_list,
)


def net(address: str, prefix: int, version: int = 4) -> dict:
    """构造测试用网段字典。"""
    return {"network": address, "prefix": prefix, "version": version}


def test_parse_rejects_nonzero_host_bits():
    # Defect 1: parse_cidr 必须校验前缀合法性，且显式前缀的主机位为零。
    assert parse_cidr("10.0.0.0/24") == net("10.0.0.0", 24)
    assert validate_list([net("10.0.0.1", 24)]) == ["host_bits"]
    for bad in ("10.0.0.1/24", "2001:db8::1/64", "10.0.0.0/33"):
        with pytest.raises(ValueError):
            parse_cidr(bad)


def test_normalize_clears_host_bits():
    # Defect 2: 同一网段不能有带主机位和不带主机位两种写法。
    assert normalize(net("10.0.0.1", 24)) == net("10.0.0.0", 24)
    assert normalize(net("2001:db8::1", 64, 6)) == net("2001:db8::", 64, 6)


def test_covers_compares_network_bits_not_string_prefix():
    # Defect 3: 包含判定不能拿地址字符串做前缀比较。
    assert covers(net("10.0.0.0", 24), net("10.0.0.0", 24)) is True
    assert covers(net("10.0.0.0", 23), net("10.0.1.0", 24)) is True
    assert covers(net("10.0.0.0", 25), net("10.0.0.0", 24)) is False
    assert covers(net("10.0.0.0", 8), net("10.1.0.0", 16)) is True
    assert covers(net("10.0.0.0", 24), net("10.0.0.255", 32)) is True


def test_adjacent_requires_same_prefix_and_last_bit_only():
    # Defect 4: 只看前缀长度会把不相邻的同前缀网段误判为相邻。
    assert adjacent(net("10.0.0.0", 24), net("10.0.1.0", 24)) is True
    assert adjacent(net("10.0.0.0", 25), net("10.0.0.128", 25)) is True
    assert adjacent(net("10.0.0.0", 24), net("10.0.2.0", 24)) is False
    assert adjacent(net("10.0.0.0", 24), net("10.0.1.0", 25)) is False


def test_collapse_repeats_until_stable():
    # Defect 5: 只做一轮会停在两个 /23，四次相邻合并才能得到 /22。
    result = collapse(
        [
            net("10.0.2.0", 24),
            net("10.0.0.0", 24),
            net("10.0.3.0", 24),
            net("10.0.1.0", 24),
        ]
    )
    assert result == [net("10.0.0.0", 22)]


def test_collapse_removes_contained_before_merging():
    # Defect 6: 先去重再合并而忘了剔除被包含项，/25 会残留。
    result = collapse(
        [
            net("10.0.0.0", 24),
            net("10.0.0.128", 25),
            net("10.0.1.0", 24),
            net("10.0.0.0", 24),
        ]
    )
    assert result == [net("10.0.0.0", 23)]


def test_sort_nets_uses_numeric_address_order():
    # Defect 7: 字符串排序会把 10.0.10.0 放到 10.0.2.0 前面。
    result = sort_nets(
        [
            net("10.0.10.0", 24),
            net("10.0.2.0", 24),
            net("10.0.0.0", 24),
            net("10.0.0.0", 16),
        ]
    )
    assert result == [
        net("10.0.0.0", 16),
        net("10.0.0.0", 24),
        net("10.0.2.0", 24),
        net("10.0.10.0", 24),
    ]


def test_mixed_family_is_rejected():
    # Defect 8: 四版与六版不得混在一起归并。
    mixed = [net("10.0.0.0", 24), net("2001:db8::", 32, 6)]
    assert validate_list([net("10.0.0.0", 33)]) == ["prefix_out_of_range"]
    assert validate_list(mixed) == ["mixed_family"]
    with pytest.raises(ValueError):
        collapse(mixed)


def test_single_address_uses_full_prefix():
    # Defect 9: 裸地址必须补成满前缀，不能丢掉前缀。
    assert parse_cidr("10.0.0.7") == net("10.0.0.7", 32)
    assert parse_cidr("2001:db8::7") == net("2001:db8::7", 128, 6)


def test_cidr_batch_does_not_reuse_previous_results():
    # Defect 10: 第二个列表不能沿用第一个列表的网段。
    result = cidr_batch(
        [
            [net("10.0.0.0", 24)],
            [net("192.168.0.0", 24)],
        ],
        "strict",
    )
    assert result == {
        "policy": "strict",
        "results": [
            [net("10.0.0.0", 24)],
            [net("192.168.0.0", 24)],
        ],
    }


def test_single_net_unchanged():
    # 单个网段归并后保持不变；空集合归并仍为空集合。
    assert collapse([]) == []
    assert collapse([net("172.16.5.0", 24)]) == [net("172.16.5.0", 24)]


def test_adjacent_pair_collapses_to_shorter_prefix():
    # 两个相邻 /25 合并成一个 /24。
    assert collapse(
        [net("192.168.1.128", 25), net("192.168.1.0", 25)]
    ) == [net("192.168.1.0", 24)]


def test_contained_net_is_removed():
    # 被包含的 /16 不再单独输出。
    result = collapse([net("10.1.0.0", 16), net("10.0.0.0", 8)])
    assert result == [net("10.0.0.0", 8)]


def test_sort_nets_numeric_ascending():
    # IPv6 同样按数值排序；同一地址按前缀长度升序。
    result = sort_nets(
        [
            net("2001:db8::10", 128, 6),
            net("2001:db8::2", 128, 6),
            net("2001:db8::", 128, 6),
            net("2001:db8::", 64, 6),
        ]
    )
    assert result == [
        net("2001:db8::", 64, 6),
        net("2001:db8::", 128, 6),
        net("2001:db8::2", 128, 6),
        net("2001:db8::10", 128, 6),
    ]


def test_batches_match_individual_collapse():
    # 两批独立归并的结果必须分别等于单独调用 collapse。
    first = [net("10.0.0.0", 24), net("10.0.1.0", 24)]
    second = [net("192.168.0.0", 24), net("192.168.0.128", 25)]
    batch = cidr_batch([first, second], "strict")
    assert batch == {
        "policy": "strict",
        "results": [collapse(first), collapse(second)],
    }