from math import factorial

class Fenwick:
    def __init__(self, n):
        self.n = n
        self.bit = [0] * (n + 1)

    def add(self, i, delta):
        while i <= self.n:
            self.bit[i] += delta
            i += i & -i

    def sum(self, i):
        s = 0
        while i > 0:
            s += self.bit[i]
            i -= i & -i
        return s


def rank_permutation(perm):
    """
    Returns the Lehmer rank of `perm` among permutations
    of its values. Rank ∈ [0, n! - 1].
    Time: O(n log n)
    """
    n = len(perm)
    vals = sorted(perm)
    index = {v: i for i, v in enumerate(vals)}
    p = [index[v] for v in perm]

    fw = Fenwick(n)
    for i in range(1, n + 1):
        fw.add(i, 1)

    rank = 0
    for i in range(n):
        x = p[i] + 1
        smaller_unused = fw.sum(x - 1)
        rank += smaller_unused * factorial(n - 1 - i)
        fw.add(x, -1)

    return rank


def unrank_permutation(rank, values):
    """
    Given a rank and the fixed sorted set `values`,
    reconstructs the corresponding permutation.
    Time: O(n log n)
    """
    n = len(values)
    values = sorted(values)

    fw = Fenwick(n)
    for i in range(1, n + 1):
        fw.add(i, 1)

    result = []
    r = rank

    for i in range(n):
        f = factorial(n - 1 - i)
        digit = r // f
        r %= f

        # Binary search over Fenwick to find (digit+1)-th unused element
        left, right = 1, n
        while left < right:
            mid = (left + right) // 2
            if fw.sum(mid) > digit:
                right = mid
            else:
                left = mid + 1

        fw.add(left, -1)
        result.append(values[left - 1])

    return result
