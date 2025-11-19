# tests_function.py

from typing import List


def buggy_sort(nums: List[int]) -> List[int]:
    """
    Intentionally buggy sorting function.

    It *tries* to sort the list in non-decreasing order using something
    similar to insertion sort, but there is an off-by-one bug:
    - It never compares against index 0 in the inner loop.
    - So if the smallest element should move to position 0, it may stay
      in a wrong position.

    This makes it perfect for fuzzing: most inputs look fine, but certain
    corner cases (like [3, 2, 1] or [2, 1, 1]) will expose the bug.
    """
    # Work on a copy to avoid mutating the original list in-place
    nums = list(nums)

    n = len(nums)
    for i in range(1, n):
        key = nums[i]
        j = i - 1
        # BUG: should be "while j >= 0", but we wrote "j > 0"
        while j > 0 and nums[j] > key:
            nums[j + 1] = nums[j]
            j -= 1
        nums[j + 1] = key

    return nums


if __name__ == "__main__":
    # 简单自测一下（你也可以手动跑）
    examples = [
        [3, 1, 2],
        [3, 2, 1],
        [1, 2, 3],
        [2, 1, 1],
        [],
        [5],
    ]
    for ex in examples:
        print(ex, "->", buggy_sort(ex))