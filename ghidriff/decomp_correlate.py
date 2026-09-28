import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import ghidra
    from ghidra_builtins import *


def decomp_correlate(self, matches, p1_missing, p2_missing, p1_matches, p2_matches):
    """
    Match unique normalized decompilations among the remaining unmatched functions.
    """

    # only attempt if there is something to match
    if len(p1_missing) == 0 or len(p2_missing) == 0:
        return

    self.logger.info(f'Attempting to Decomp Correlate unmatched functions p1:{len(p1_missing)} p2:{len(p2_missing)}')

    def group_decompilations(functions, accepted):
        groups = {}
        for func in functions:
            if accepted.contains(func.getEntryPoint()):
                continue
            esym = self.enhance_sym(func.getSymbol(), get_decomp_info=True)
            if not esym['decomp_completed']:
                continue
            normalized = tuple(self.remove_code_sig(esym['code']))
            digest = hashlib.sha256(''.join(normalized).encode('utf-8')).digest()
            groups.setdefault(digest, []).append((func, normalized))
        return groups

    p1_groups = group_decompilations(p1_missing, p1_matches)
    p2_groups = group_decompilations(p2_missing, p2_matches)

    for digest, p1_group in p1_groups.items():
        p2_group = p2_groups.get(digest, [])
        if len(p1_group) != 1 or len(p2_group) != 1:
            continue
        p1_func, decomp1 = p1_group[0]
        p2_func, decomp2 = p2_group[0]
        if decomp1 != decomp2:
            continue

        name = 'Decomp Match'
        p1_addr = p1_func.getEntryPoint()
        p2_addr = p2_func.getEntryPoint()
        matches.setdefault((p1_addr, p2_addr), {}).setdefault(name, 0)
        matches[(p1_addr, p2_addr)][name] += 1
        p1_matches.add(p1_addr)
        p2_matches.add(p2_addr)
