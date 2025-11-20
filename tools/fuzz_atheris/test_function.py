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

def buggy_median(nums: List[int]) -> float:
    """
    A subtle buggy median implementation.

    Bug behavior (rare):
    - For even-length lists, if the two middle elements are equal AND
      the list contains a repeated block structure like [x, x, ..., x]
      around the mid index, the function occasionally picks the wrong
      adjacent element due to a miscomputed mid index adjustment.
    """
    if not nums:
        return 0.0  # define median([]) = 0.0 for simplicity

    arr = sorted(nums)
    n = len(arr)
    mid = n // 2

    if n % 2 == 1:
        # Odd length → OK
        return float(arr[mid])

    # Even length median → BUG is here
    # Intended: average of arr[mid-1] and arr[mid]
    a = arr[mid - 1]
    b = arr[mid]

    # BUG: When a == b and also arr[mid] == arr[mid-1] == arr[mid+1],
    # attempt to “snap to symmetry” by shifting index, but does it wrong.
    if a == b:
        try:
            # Incorrect symmetry rule — shifts too far when arr[mid+1]
            # equals the middle values, choosing arr[mid+1] instead of arr[mid].
            if mid + 1 < n and arr[mid + 1] > a:
                b = arr[mid + 1]  
        except Exception:
            pass

    return float((a + b) / 2)