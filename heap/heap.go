package heap

type intHeap []any

// Push heap.Interface 的方法，实现推入元素到堆
func (h *intHeap) Push(x any) {
	// Push 和 Pop 使用 pointer receiver 作为参数
	// 因为它们不仅会对切片的内容进行调整，还会修改切片的长度。
	*h = append(*h, x.(int))
}

// Pop heap.Interface 的方法，实现弹出堆顶元素
func (h *intHeap) Pop() any {
	// 待出堆元素存放在最后
	last := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return last
}

// Len sort.Interface 的方法
func (h *intHeap) Len() int {
	return len(*h)
}

// Less sort.Interface 的方法
func (h *intHeap) Less(i, j int) bool {
	// 如果实现小顶堆，则需要调整为小于号
	return (*h)[i].(int) > (*h)[j].(int)
}

// Swap sort.Interface 的方法
func (h *intHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
}

// Top 获取堆顶元素
func (h *intHeap) Top() any {
	return (*h)[0]
}

// Heapify 通用堆化（支持最大/最小堆，迭代式下沉）
func Heapify(nums []int, max bool) {
	n := len(nums)
	for i := n/2 - 1; i >= 0; i-- {
		siftDown(nums, i, n, max)
	}
}

// 迭代式下沉（替代递归）
func siftDown(nums []int, i, n int, max bool) {
	for {
		left := 2*i + 1
		right := 2*i + 2
		candidate := i

		if max { // 最大堆
			if left < n && nums[left] > nums[candidate] {
				candidate = left
			}
			if right < n && nums[right] > nums[candidate] {
				candidate = right
			}
		} else { // 最小堆
			if left < n && nums[left] < nums[candidate] {
				candidate = left
			}
			if right < n && nums[right] < nums[candidate] {
				candidate = right
			}
		}

		if candidate == i {
			break
		}
		nums[i], nums[candidate] = nums[candidate], nums[i]
		i = candidate // 更新当前位置继续下沉
	}
}
